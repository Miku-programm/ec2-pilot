"""Scheduled rotation exercises real API/store/scheduler and fake cloud/network IO."""
import asyncio
import json
import threading
import time
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

import app.main as main


INSTANCE = "i-0123456789abcdef0"
PASSWORD = "local-test-rotation-password-2026"


class Cloud:
    """Different local account entries deliberately resolve to one AWS resource."""

    def __init__(self):
        self.ip = "8.8.8.8"
        self.state = "running"
        self.rotations = []
        self.probe_calls = []
        self.responses = {}
        self.probe_hook = None
        self.instances_hook = None
        self.rotate_error = None
        self.rotation_hook = None
        self.instances_calls = 0

    def factory(self, credentials, region):
        cloud = self

        class Aws:
            def validate(self):
                return {"aws_account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test"}

            def instances(self):
                cloud.instances_calls += 1
                if cloud.instances_hook:
                    cloud.instances_hook()
                return [{"id": INSTANCE, "name": "test", "state": cloud.state,
                         "public_ip": cloud.ip, "instance_type": "t3.micro"}]

            def rotate_ip(self, instance_id, release_previous=False):
                assert instance_id == INSTANCE
                cloud.rotations.append({"old_ip": cloud.ip, "release_previous": release_previous})
                if cloud.rotation_hook:
                    cloud.rotation_hook()
                if cloud.rotate_error:
                    raise cloud.rotate_error
                cloud.ip = f"1.1.1.{len(cloud.rotations)}"
                return {"public_ip": cloud.ip, "allocation_id": "eipalloc-0123456789abcdef0", "message": "changed"}

        return Aws()

    def probe(self, **args):
        self.probe_calls.append(args.copy())
        if self.probe_hook:
            override = self.probe_hook(args)
            if override is not None:
                return override
        outcome = self.responses.get(args["target_ip"], False)
        if isinstance(outcome, Exception):
            raise outcome
        return measurement(bool(outcome), args["samples"])


def measurement(healthy, samples=1):
    return {"success_count": samples if healthy else 0, "samples": samples,
            "latency_ms": 1.0 if healthy else None, "loss_percent": 0 if healthy else 100,
            "attempts": [{"ok": healthy, "latency_ms": 1.0,
                          **({} if healthy else {"error": "timeout"})} for _ in range(samples)]}


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("PANEL_ALLOWED_HOSTS", "localhost")
    cloud = Cloud()
    monkeypatch.setattr(main, "tcp_probe", cloud.probe)
    return cloud


@contextmanager
def panel(path, cloud, *, scheduler=True):
    app = main.create_app(path, start_scheduler=scheduler, aws_factory=cloud.factory, scheduler_tick=0.01, rotation_verify_delay=0)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5555)) as client:
        route = "/api/setup" if client.get("/api/health").json()["setup_required"] else "/api/login"
        response = client.post(route, json={"password": PASSWORD})
        assert response.status_code == 200, response.text
        yield client


@pytest.fixture
def client(tmp_path, cloud):
    with panel(tmp_path, cloud, scheduler=False) as client:
        yield client


def add_account(client, name="test"):
    response = client.post("/api/accounts", json={
        "name": name, "access_key_id": "AKIA" + "X" * 16,
        "secret_access_key": "fake-rotation-secret-" * 3, "region": "ap-southeast-2",
    })
    assert response.status_code == 200, response.text
    return response.json()["id"]


def add_monitor(client, account=None, **overrides):
    response = client.post("/api/monitors", json={
        "name": "SSH automatic repair", "account_id": account or add_account(client),
        "instance_id": INSTANCE, "port": 22, "samples": 1,
        "schedule_type": "cron", "cron_expression": "*/5 * * * *", "timezone": "Asia/Shanghai",
        "auto_rotate": True, "rotation_trigger": "tcp_failure", "failure_threshold": 3,
        **overrides,
    })
    assert response.status_code == 200, response.text
    return response.json()["id"]


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "scheduled action did not finish before test deadline"


def run_scheduled(client, monitor_id, *, background=False):
    """Force the existing durable schedule due; do not call the manual endpoint."""
    store = client.app.state.store
    before = {row["id"] for row in store.list("results")}
    with store.connect() as db:
        db.execute("UPDATE monitors SET next_due=? WHERE id=?", (time.time() - 1, monitor_id))
    if not background:
        client.app.state.run_check(monitor_id, scheduled=True)

    def completed():
        fresh = [row for row in store.list("results") if row["id"] not in before and row["monitor_id"] == monitor_id]
        with store.connect() as db:
            row = db.execute("SELECT lease_until FROM monitors WHERE id=?", (monitor_id,)).fetchone()
        return bool(fresh) and (row is None or row["lease_until"] == 0)

    wait_until(completed)
    return [row for row in store.list("results") if row["id"] not in before and row["monitor_id"] == monitor_id]


def test_three_complete_failed_rounds_rotate_and_probe_new_ip(client, cloud):
    monitor = add_monitor(client)
    cloud.responses["1.1.1.1"] = True
    for _ in range(2):
        run_scheduled(client, monitor)
        assert cloud.rotations == []
    run_scheduled(client, monitor)
    assert cloud.rotations == [{"old_ip": "8.8.8.8", "release_previous": False}]
    assert any(call["target_ip"] == "1.1.1.1" for call in cloud.probe_calls), "new IP must receive a follow-up check"
    assert cloud.probe_calls[-1]["target_ip"] == "1.1.1.1"


def test_manual_run_only_checks_even_when_automatic_repair_enabled(client, cloud):
    monitor = add_monitor(client)
    for _ in range(4):
        response = client.post(f"/api/monitors/{monitor}/run")
        assert response.status_code == 200, response.text
    assert cloud.rotations == []
    run_scheduled(client, monitor)
    assert cloud.rotations == [], "manual checks must not accumulate scheduled failure rounds"


@pytest.mark.parametrize("interrupt", ["healthy", "probe_error", "no_public_ip", "stopped", "changed_ip"])
def test_failure_rounds_reset_after_missing_or_changed_evidence(client, cloud, interrupt):
    monitor = add_monitor(client)
    run_scheduled(client, monitor)
    run_scheduled(client, monitor)
    if interrupt == "healthy":
        cloud.responses[cloud.ip] = True
    elif interrupt == "probe_error":
        cloud.responses[cloud.ip] = OSError("local probe unavailable")
    elif interrupt == "no_public_ip":
        cloud.ip = None
    elif interrupt == "stopped":
        cloud.state = "stopped"
    else:
        cloud.ip = "9.9.9.9"
    run_scheduled(client, monitor)
    assert cloud.rotations == []
    cloud.responses.clear()
    cloud.state = "running"
    cloud.ip = cloud.ip or "8.8.8.8"
    run_scheduled(client, monitor)
    assert cloud.rotations == []


def test_gfw_rule_requires_real_dual_location_evidence(client, cloud):
    monitor = add_monitor(client, rotation_trigger="suspected_filtering")
    for _ in range(4):
        results = run_scheduled(client, monitor)
        assert results[0]["gfw_status"] == "insufficient_evidence"
    assert cloud.rotations == []


def test_fresh_healthy_confirmation_suppresses_rotation(client, cloud):
    monitor = add_monitor(client)
    for _ in range(2):
        run_scheduled(client, monitor)
    third_round_probe = len(cloud.probe_calls) + 1

    def recovered(args):
        if len(cloud.probe_calls) > third_round_probe:
            return measurement(True, args["samples"])

    cloud.probe_hook = recovered
    run_scheduled(client, monitor)
    assert len(cloud.probe_calls) > third_round_probe, "threshold crossing must recheck before replacing an IP"
    assert cloud.rotations == []


def test_duplicate_account_alias_has_no_hidden_wait_after_previous_rotation(client, cloud):
    original = add_monitor(client, add_account(client, "original"), failure_threshold=1)
    duplicate = add_monitor(client, add_account(client, "duplicate"), failure_threshold=1)
    run_scheduled(client, original)
    assert len(cloud.rotations) == 1
    run_scheduled(client, duplicate)
    assert len(cloud.rotations) == 2, "each eligible scheduled round can rotate without a resource cooldown"
    assert cloud.rotations[-1]["old_ip"] == "1.1.1.1"


def test_ambiguous_aws_failure_blocks_repeat_even_after_restart(tmp_path, cloud):
    cloud.rotate_error = TimeoutError("response lost after allocation")
    with panel(tmp_path, cloud, scheduler=False) as client:
        monitor = add_monitor(client)
        for _ in range(3):
            run_scheduled(client, monitor)
        assert len(cloud.rotations) == 1
    with panel(tmp_path, cloud, scheduler=False) as client:
        for _ in range(4):
            run_scheduled(client, monitor)
        assert len(cloud.rotations) == 1, "restart must not turn an uncertain AWS outcome into a fresh allocation"


@pytest.mark.parametrize("change", ["delete", "disable", "auto_off", "port"])
def test_changes_during_threshold_probe_prevent_stale_rotation(client, cloud, change):
    monitor = add_monitor(client)
    for _ in range(2):
        run_scheduled(client, monitor)
    changed = False

    def edit_while_probe_runs(args):
        nonlocal changed
        if changed:
            return
        changed = True
        if change == "delete":
            response = client.delete(f"/api/monitors/{monitor}")
        else:
            fields = {"disable": {"enabled": False}, "auto_off": {"auto_rotate": False}, "port": {"port": 443}}
            response = client.put(f"/api/monitors/{monitor}", json=fields[change])
        assert response.status_code == 200, response.text

    cloud.probe_hook = edit_while_probe_runs
    run_scheduled(client, monitor)
    assert cloud.rotations == []
    saved = client.app.state.store.get("monitors", monitor)
    if change == "delete":
        assert saved is None
    elif change == "disable":
        assert saved["enabled"] is False
        assert saved["next_run_at"] is None


def test_real_scheduler_executes_cron_repair_without_open_browser(tmp_path, cloud):
    with panel(tmp_path, cloud) as client:
        monitor = add_monitor(client, failure_threshold=1)
        run_scheduled(client, monitor, background=True)
        assert len(cloud.rotations) == 1
        record = client.app.state.store.get("monitors", monitor)
        assert record["schedule_type"] == "cron"
        assert record["next_run_at"]


def test_fresh_cloud_ip_change_invalidates_failure_evidence(client, cloud):
    monitor = add_monitor(client, failure_threshold=1)
    changed = False

    def replace_during_probe(args):
        nonlocal changed
        if not changed:
            changed = True
            cloud.ip = "9.9.9.9"

    cloud.probe_hook = replace_during_probe
    run_scheduled(client, monitor)
    assert cloud.rotations == [], "old-IP failures cannot authorize changing a newly assigned address"


def add_dual_probes(client):
    for region in ("mainland", "overseas"):
        client.app.state.store.put("probes", {
            "id": region, "name": region, "region_type": region,
            "url": f"https://{region}.example.test/probe", "enabled": True,
        }, {"token": "fake-test-probe-token-2026"})


def test_gfw_automatic_repair_requires_and_accepts_failed_mainland_successful_overseas(client, cloud, monkeypatch):
    add_dual_probes(client)
    monitor = add_monitor(client, failure_threshold=1, rotation_trigger="suspected_filtering")
    monkeypatch.setattr(main, "remote_probe", lambda url, token, args: measurement("overseas" in url, args["samples"]))
    run_scheduled(client, monitor)
    assert len(cloud.rotations) == 1


def test_gfw_control_plane_failure_cannot_trigger_repair(client, cloud, monkeypatch):
    add_dual_probes(client)
    monitor = add_monitor(client, failure_threshold=1, rotation_trigger="suspected_filtering")

    def remote(url, token, args):
        if "mainland" in url:
            raise TimeoutError("probe API is down")
        return measurement(True, args["samples"])

    monkeypatch.setattr(main, "remote_probe", remote)
    for _ in range(3):
        run_scheduled(client, monitor)
    assert cloud.rotations == []


def test_no_recursive_rotation_when_new_address_is_also_unreachable(client, cloud):
    monitor = add_monitor(client, failure_threshold=1)
    run_scheduled(client, monitor)
    assert len(cloud.rotations) == 1
    assert any(probe["target_ip"] == "1.1.1.1" for probe in cloud.probe_calls)


def test_explicit_release_previous_option_is_passed_only_when_enabled(client, cloud):
    monitor = add_monitor(client, failure_threshold=1, release_previous=True)
    run_scheduled(client, monitor)
    assert cloud.rotations == [{"old_ip": "8.8.8.8", "release_previous": True}]


RESOURCE = f"123456789012:ap-southeast-2:{INSTANCE}"


def test_attempt_and_uncertainty_marker_are_durable_before_aws_is_called(client, cloud):
    monitor = add_monitor(client, failure_threshold=1)
    inspected = []

    def inspect_reservation():
        # A separate sqlite connection sees only committed data.
        with client.app.state.store.connect() as db:
            guards = db.execute("SELECT data FROM rotation_guards WHERE resource_key=?", (RESOURCE,)).fetchall()
            attempts = db.execute("SELECT data FROM rotation_attempts WHERE resource_key=?", (RESOURCE,)).fetchall()
        assert len(guards) == len(attempts) == 1
        assert json.loads(guards[0][0])["state"] == "in_progress"
        assert json.loads(attempts[0][0])["status"] == "in_progress"
        inspected.append(True)

    cloud.rotation_hook = inspect_reservation
    run_scheduled(client, monitor)
    assert inspected == [True]


def test_more_than_three_changes_within_one_day_are_allowed_without_aging_history(client, cloud):
    original = add_monitor(client, add_account(client, "A"), failure_threshold=1)
    duplicate = add_monitor(client, add_account(client, "B"), failure_threshold=1)
    started = time.time()
    for expected, monitor in enumerate((original, duplicate, original, duplicate, original), start=1):
        run_scheduled(client, monitor)
        assert len(cloud.rotations) == expected, "an eligible cron round must not encounter a cooldown or daily quota"
    with client.app.state.store.connect() as db:
        attempts = db.execute("SELECT created_at,data FROM rotation_attempts WHERE resource_key=?", (RESOURCE,)).fetchall()
    assert len(attempts) == 5, "removing the limit must preserve rotation history"
    assert all(row["created_at"] >= started and json.loads(row["data"])["status"] == "rotated" for row in attempts)


@pytest.mark.parametrize("old_status", ["cooldown", "daily_limit"])
def test_saved_legacy_limits_migrate_without_restricting_next_cron_round(tmp_path, cloud, old_status):
    with panel(tmp_path, cloud, scheduler=False) as client:
        monitor = add_monitor(client, failure_threshold=1)
        for _ in range(4):
            run_scheduled(client, monitor)
        store = client.app.state.store
        record = store.get("monitors", monitor)
        revision = record["config_revision"]
        record.update(cooldown_seconds=86400, max_rotations_per_day=1,
                      rotation_status=old_status, rotation_message="legacy limit is active")
        with store.connect() as db:
            db.execute("UPDATE monitors SET data=? WHERE id=?", (json.dumps(record), monitor))
            old_due = db.execute("SELECT next_due FROM monitors WHERE id=?", (monitor,)).fetchone()[0]
        previous_guard = store.rotation_guard(RESOURCE)

    with panel(tmp_path, cloud, scheduler=False) as client:
        store = client.app.state.store
        saved = store.get("monitors", monitor)
        assert "cooldown_seconds" not in saved and "max_rotations_per_day" not in saved
        assert saved["config_revision"] != revision
        assert saved["rotation_status"] == "skipped"
        for key in ("enabled", "auto_rotate", "cron_expression", "timezone", "next_run_at", "failure_streak"):
            assert saved[key] == record[key], f"migration must preserve {key}"
        assert store.rotation_guard(RESOURCE) == previous_guard
        with store.connect() as db:
            assert db.execute("SELECT next_due FROM monitors WHERE id=?", (monitor,)).fetchone()[0] == old_due
            assert db.execute("SELECT COUNT(*) FROM rotation_attempts WHERE resource_key=?", (RESOURCE,)).fetchone()[0] == 4
        run_scheduled(client, monitor)
        assert len(cloud.rotations) == 5, "saved old limits must not delay the next eligible cron run"


@pytest.mark.parametrize("field,value", [("cooldown_seconds", 1800), ("max_rotations_per_day", 3)])
def test_retired_limit_options_cannot_be_reintroduced_by_api(client, field, value):
    monitor = add_monitor(client)
    response = client.put(f"/api/monitors/{monitor}", json={field: value})
    assert response.status_code == 422, response.text
    saved = client.app.state.store.get("monitors", monitor)
    assert field not in saved


def test_review_reset_allows_next_eligible_round_without_delay_or_quota(client, cloud):
    cloud.rotate_error = TimeoutError("outcome uncertain")
    monitor = add_monitor(client, failure_threshold=1)
    run_scheduled(client, monitor)
    assert len(cloud.rotations) == 1
    response = client.post(f"/api/monitors/{monitor}/reset-rotation")
    assert response.status_code == 200, response.text
    cloud.rotate_error = None
    run_scheduled(client, monitor)
    assert len(cloud.rotations) == 2, "manual review must allow the next eligible scheduled round immediately"
    with client.app.state.store.connect() as db:
        attempts = db.execute("SELECT data FROM rotation_attempts WHERE resource_key=? ORDER BY created_at", (RESOURCE,)).fetchall()
    assert [json.loads(row["data"])["status"] for row in attempts] == ["awaiting_review", "rotated"]


def test_pending_reservation_survives_process_restart_and_needs_review(tmp_path, cloud):
    with panel(tmp_path, cloud, scheduler=False) as client:
        monitor = add_monitor(client, failure_threshold=1)
        record = client.app.state.store.get("monitors", monitor)
        # Emulate an abrupt exit after committing the allocation reservation.
        timestamp = time.time() - 1000
        store = client.app.state.store
        monitor_token = store.acquire_monitor(monitor, timestamp)
        resource_token = store.acquire_resource(RESOURCE, timestamp)
        result = store.reserve_rotation(RESOURCE, monitor, record.get("config_revision", "legacy"), timestamp,
                                        monitor_token=monitor_token, resource_token=resource_token)
        assert result["status"] == "reserved"
    with panel(tmp_path, cloud, scheduler=False) as client:
        run_scheduled(client, monitor)
        assert cloud.rotations == [], "a crashed reservation must never be retried blindly"
        response = client.post(f"/api/monitors/{monitor}/reset-rotation")
        assert response.status_code == 200, response.text
        run_scheduled(client, monitor)
        assert len(cloud.rotations) == 1


def test_recent_in_progress_reservation_cannot_be_reset(client, cloud):
    monitor = add_monitor(client, failure_threshold=1)
    record = client.app.state.store.get("monitors", monitor)
    timestamp = time.time()
    store = client.app.state.store
    monitor_token = store.acquire_monitor(monitor, timestamp)
    resource_token = store.acquire_resource(RESOURCE, timestamp)
    result = store.reserve_rotation(RESOURCE, monitor, record.get("config_revision", "legacy"), timestamp,
                                    monitor_token=monitor_token, resource_token=resource_token)
    assert result["status"] == "reserved"
    # Emulate worker cleanup without a confirmed AWS outcome. The durable guard,
    # rather than a currently held operation lease, must reject the reset.
    store.release_monitor(monitor, monitor_token)
    store.release_resource(RESOURCE, resource_token)
    response = client.post(f"/api/monitors/{monitor}/reset-rotation")
    assert response.status_code == 409, response.text
    assert client.app.state.store.rotation_guard(RESOURCE)["state"] == "in_progress"
    assert cloud.rotations == []


def test_new_ip_starts_a_fresh_failure_streak_after_successful_replacement(client, cloud):
    monitor = add_monitor(client)
    for _ in range(3):
        run_scheduled(client, monitor)
    assert len(cloud.rotations) == 1
    for _ in range(2):
        run_scheduled(client, monitor)
        assert len(cloud.rotations) == 1
    run_scheduled(client, monitor)
    assert len(cloud.rotations) == 2


@pytest.mark.parametrize("failure", ["permission_denied", "network_unreachable", "incomplete_samples"])
def test_local_probe_or_network_errors_cannot_trigger_replacement(client, cloud, failure):
    monitor = add_monitor(client, failure_threshold=1)

    def invalid_probe(args):
        result = measurement(False, args["samples"])
        if failure == "incomplete_samples":
            result["attempts"] = []
        else:
            for attempt in result["attempts"]:
                attempt["error"] = failure
        return result

    cloud.probe_hook = invalid_probe
    run_scheduled(client, monitor)
    assert cloud.rotations == []


def test_gfw_never_rotates_when_any_mainland_probe_has_a_successful_sample(client, cloud, monkeypatch):
    add_dual_probes(client)
    client.app.state.store.put("probes", {
        "id": "mainland-mixed", "name": "mainland mixed", "region_type": "mainland",
        "url": "https://mainland-mixed.example.test/probe", "enabled": True,
    }, {"token": "fake-test-probe-token-2026"})
    monitor = add_monitor(client, failure_threshold=1, samples=2, rotation_trigger="suspected_filtering")

    def remote(url, token, args):
        if "mainland-mixed" in url:
            return {"success_count": 1, "samples": 2, "latency_ms": 1.0, "loss_percent": 50,
                    "attempts": [{"ok": True, "latency_ms": 1.0},
                                 {"ok": False, "latency_ms": 1.0, "error": "permission_denied"}]}
        return measurement("overseas" in url, args["samples"])

    monkeypatch.setattr(main, "remote_probe", remote)
    results = run_scheduled(client, monitor)
    assert results[0]["gfw_status"] == "reachable_from_both"
    assert cloud.rotations == [], "a genuine mainland TCP success contradicts blocking evidence"


def test_rotation_probes_returned_new_ip_while_instance_read_is_stale(client, cloud):
    monitor = add_monitor(client, failure_threshold=1)
    cloud.responses["1.1.1.1"] = True

    def stale_read():
        if cloud.rotations:
            cloud.ip = "8.8.8.8"

    cloud.instances_hook = stale_read
    results = run_scheduled(client, monitor)
    assert len(cloud.rotations) == 1
    assert cloud.probe_calls[-1]["target_ip"] == "1.1.1.1"
    assert results[0]["rotation"]["verification"]["status"] == "reachable"


def test_shutdown_drains_started_worker_before_lifespan_finishes(tmp_path, cloud):
    started = threading.Event()
    release = threading.Event()
    blocked_once = False

    def blocked(args):
        nonlocal blocked_once
        if not blocked_once:
            blocked_once = True
            started.set()
            assert release.wait(10), "test must release the active network worker"

    cloud.probe_hook = blocked
    with panel(tmp_path, cloud, scheduler=False) as client:
        monitor = add_monitor(client, failure_threshold=1)
        with client.app.state.store.connect() as db:
            db.execute("UPDATE monitors SET next_due=? WHERE id=?", (time.time() - 1, monitor))

    async def scenario():
        app = main.create_app(tmp_path, aws_factory=cloud.factory, scheduler_tick=0.01, rotation_verify_delay=0)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        shutdown = None
        try:
            assert await asyncio.to_thread(started.wait, 5), "scheduler must start its network worker"
            shutdown = asyncio.create_task(lifespan.__aexit__(None, None, None))
            # Give cancellation a chance to propagate while the actual worker is
            # deterministically blocked on our event.
            await asyncio.sleep(0.05)
            assert not shutdown.done(), "shutdown must drain the worker, not abandon its to_thread task"
        finally:
            release.set()
            if shutdown is None:
                await lifespan.__aexit__(None, None, None)
            else:
                await shutdown
        assert app.state.store.rotation_guard(RESOURCE)["state"] == "ready"
        with app.state.store.connect() as db:
            assert db.execute("SELECT lease_until FROM monitors WHERE id=?", (monitor,)).fetchone()[0] == 0

    asyncio.run(scenario())
