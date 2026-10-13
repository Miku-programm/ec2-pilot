"""Old-EIP release queue: intent before allocation, owner leases, reuse detection."""
import time
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

import app.main as main
from test_auto_rotation import Cloud, INSTANCE, PASSWORD, add_account, add_monitor, run_scheduled


OLD = "eipalloc-0123456789abcdef0"
OLD_ASSOC = "eipassoc-0123456789abcdef0"
PREVIOUS = {"allocation_id": OLD, "association_id": OLD_ASSOC, "public_ip": "8.8.8.8", "network_border_group": "ap-southeast-2"}


class AwsLikeError(Exception):
    def __init__(self, code, message="denied"):
        super().__init__(code)
        self.code, self.message = code, message


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("PANEL_ALLOWED_HOSTS", "localhost")
    cloud = Cloud()
    cloud.previous = dict(PREVIOUS)
    monkeypatch.setattr(main, "tcp_probe", cloud.probe)
    return cloud


@contextmanager
def panel(path, cloud):
    app = main.create_app(path, start_scheduler=False, aws_factory=cloud.factory, scheduler_tick=0.01,
                          rotation_verify_delay=0, release_wait_seconds=0, release_poll_interval=0)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5555)) as client:
        assert client.post("/api/setup", json={"password": PASSWORD}).status_code == 200
        yield client


@pytest.fixture
def client(tmp_path, cloud):
    with panel(tmp_path, cloud) as client:
        yield client


def rotate(client, account, release=True):
    return client.post(f"/api/accounts/{account}/instances/{INSTANCE}/rotate-ip", json={"release_previous": release})


def queue(client):
    return client.get("/api/state").json()["eip_cleanup"]


def make_due(client):
    with client.app.state.store.connect() as db:
        db.execute("UPDATE eip_cleanup SET next_try=? WHERE state='queued'", (time.time() - 1,))


def test_release_after_confirmed_rotation(client, cloud):
    response = rotate(client, add_account(client))
    assert response.status_code == 200, response.text
    assert "已释放" in response.json()["message"]
    assert cloud.release_calls == [(OLD, "ap-southeast-2")]
    assert queue(client) == []


def test_unchecked_release_keeps_old_eip_and_writes_no_intent(client, cloud):
    response = rotate(client, add_account(client), release=False)
    assert "已保留" in response.json()["message"]
    assert cloud.release_calls == [] and queue(client) == []


def test_intent_is_durable_before_allocation(client, cloud):
    seen = []
    cloud.rotation_hook = lambda: seen.append(queue(client))  # runs after before_allocate, before "allocation"
    rotate(client, add_account(client))
    assert seen[0][0]["allocation_id"] == OLD and seen[0][0]["state"] == "blocked"


def test_failed_or_interrupted_rotation_leaves_blocked_intent_until_admin_approves(client, cloud):
    account = add_account(client)
    cloud.rotate_error = AwsLikeError("AwsTransportError", "uncertain")
    assert rotate(client, account).status_code == 502
    [entry] = queue(client)
    assert entry["state"] == "blocked"
    # The sweeper never touches blocked intents, even when due.
    with client.app.state.store.connect() as db:
        db.execute("UPDATE eip_cleanup SET next_try=0")
    assert client.app.state.run_eip_cleanup() == 0
    assert cloud.release_calls == []
    # After the admin verifies AWS, the row becomes eligible and is still re-checked.
    assert client.post(f"/api/eip-cleanup/{OLD}/approve").status_code == 200
    assert client.app.state.run_eip_cleanup() == 1
    assert cloud.release_calls == [(OLD, "ap-southeast-2")]


def test_stale_view_is_retried_by_sweeper_then_released(client, cloud):
    cloud.release_check_default = "stale"
    response = rotate(client, add_account(client))
    assert "待清理队列" in response.json()["message"]
    [entry] = queue(client)
    assert entry["state"] == "queued" and entry["attempts"] == 1 and cloud.release_calls == []
    assert client.app.state.run_eip_cleanup() == 0  # backoff: not due yet
    cloud.release_check_default = "detached"
    make_due(client)
    assert client.app.state.run_eip_cleanup() == 1
    assert cloud.release_calls == [(OLD, "ap-southeast-2")] and queue(client) == []


@pytest.mark.parametrize("check", ["reused", "unclear"])
def test_reused_or_unclear_address_stops_automatic_cleanup(client, cloud, check):
    cloud.release_check_default = check
    rotate(client, add_account(client))
    [entry] = queue(client)
    assert entry["state"] == "review" and entry["next_try_at"] is None
    with client.app.state.store.connect() as db:
        db.execute("UPDATE eip_cleanup SET next_try=0")
    cloud.release_check_default = "detached"
    assert client.app.state.run_eip_cleanup() == 0
    assert cloud.release_calls == []
    # Review rows cannot be re-queued, only kept.
    assert client.post(f"/api/eip-cleanup/{OLD}/approve").status_code == 409


def test_release_in_use_error_moves_to_review(client, cloud):
    cloud.release_error = AwsLikeError("InvalidIPAddress.InUse")
    rotate(client, add_account(client))
    assert queue(client)[0]["state"] == "review"


def test_release_not_found_counts_as_done(client, cloud):
    cloud.release_error = AwsLikeError("InvalidAllocationID.NotFound")
    rotate(client, add_account(client))
    assert queue(client) == []


def test_transient_errors_back_off_then_fail_after_ten_attempts(client, cloud):
    cloud.release_check_default = AwsLikeError("RequestLimitExceeded")
    rotate(client, add_account(client))
    for _ in range(9):
        make_due(client)
        client.app.state.run_eip_cleanup()
    [entry] = queue(client)
    assert entry["state"] == "failed" and entry["attempts"] == 10 and cloud.release_calls == []
    assert any(a["action"] == "ec2.eip-cleanup.failed" for a in client.get("/api/state").json()["activity"])
    # Admin retry resets attempts and re-queues.
    cloud.release_check_default = "detached"
    assert client.post(f"/api/eip-cleanup/{OLD}/approve").status_code == 200
    assert client.app.state.run_eip_cleanup() == 1 and queue(client) == []


def test_owner_lease_blocks_dismiss_approve_and_second_worker(client, cloud):
    cloud.release_check_default = "stale"
    rotate(client, add_account(client))
    store = client.app.state.store
    make_due(client)
    claimed = store.claim_cleanup(OLD, time.time())
    assert claimed is not None
    assert store.claim_cleanup(OLD, time.time(), due_only=False) is None
    assert client.delete(f"/api/eip-cleanup/{OLD}").status_code == 409
    assert client.app.state.run_eip_cleanup() == 0
    token, data = claimed
    assert store.finish_cleanup(OLD, token, data=data)
    assert client.delete(f"/api/eip-cleanup/{OLD}").status_code == 200
    assert queue(client) == []


def test_lost_lease_never_releases(client, cloud):
    cloud.release_check_default = "stale"
    rotate(client, add_account(client))
    store = client.app.state.store

    def taken_over_then_detached():
        # Another owner takes the row between the read and the release.
        with store.connect() as db:
            db.execute("UPDATE eip_cleanup SET lease_token='someone-else'")
        return "detached"

    cloud.release_check_default = taken_over_then_detached
    make_due(client)
    client.app.state.run_eip_cleanup()
    assert cloud.release_calls == []


def test_intent_conflict_aborts_rotation_before_allocation(client, cloud):
    account = add_account(client)
    cloud.release_check_default = "stale"
    rotate(client, account)
    make_due(client)
    assert client.app.state.store.claim_cleanup(OLD, time.time()) is not None
    rotations = len(cloud.rotations)
    response = rotate(client, account)
    assert response.status_code == 409
    assert len(cloud.rotations) == rotations + 1 and cloud.ip == "1.1.1.1"  # hook aborted; IP unchanged


def test_account_with_pending_cleanup_cannot_be_deleted(client, cloud):
    cloud.release_check_default = "stale"
    account = add_account(client)
    rotate(client, account)
    assert client.delete(f"/api/accounts/{account}").status_code == 409


def test_scheduled_rotation_releases_through_queue(client, cloud):
    monitor = add_monitor(client, failure_threshold=1, release_previous=True)
    [result] = run_scheduled(client, monitor)
    assert result["rotation"]["status"] == "rotated"
    assert "已释放" in result["rotation"]["message"]
    assert cloud.release_calls == [(OLD, "ap-southeast-2")]


def test_scheduled_rotation_cleanup_problem_does_not_pause_rotation(client, cloud):
    monitor = add_monitor(client, failure_threshold=1, release_previous=True)
    cloud.release_check_default = "stale"
    [result] = run_scheduled(client, monitor)
    assert result["rotation"]["status"] == "rotated"
    assert queue(client)[0]["state"] == "queued"
    state = client.get("/api/state").json()
    assert next(m for m in state["monitors"] if m["id"] == monitor)["rotation_status"] == "rotated"


def test_scheduled_rotation_failure_keeps_intent_blocked(client, cloud):
    monitor = add_monitor(client, failure_threshold=1, release_previous=True)
    cloud.rotate_error = AwsLikeError("AwsTransportError", "uncertain")
    [result] = run_scheduled(client, monitor)
    assert result["rotation"]["status"] == "awaiting_review"
    assert queue(client)[0]["state"] == "blocked"
    assert cloud.release_calls == []


def test_builtin_scheduler_runs_cleanup(tmp_path, cloud):
    cloud.release_check_default = "stale"
    app = main.create_app(tmp_path, start_scheduler=True, aws_factory=cloud.factory, scheduler_tick=0.01,
                          rotation_verify_delay=0, release_wait_seconds=0, release_poll_interval=0, cleanup_interval=0)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5555)) as client:
        assert client.post("/api/setup", json={"password": PASSWORD}).status_code == 200
        rotate(client, add_account(client))
        cloud.release_check_default = "detached"
        make_due(client)
        deadline = time.monotonic() + 5
        while queue(client) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert queue(client) == [] and cloud.release_calls == [(OLD, "ap-southeast-2")]
