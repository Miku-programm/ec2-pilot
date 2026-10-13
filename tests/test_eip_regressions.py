"""Release-queue regressions: real routes, SQLite and scheduling; fake AWS IO."""
import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import app.main as main
from test_eip_cleanup import (
    OLD, PREVIOUS, AwsLikeError, add_account, add_monitor, client, cloud,
    make_due, queue, rotate, run_scheduled,
)


RESOURCE = "123456789012:ap-southeast-2:i-0123456789abcdef0"


def test_cleanup_conflict_skips_rotation_and_next_schedule_can_retry(client, cloud):
    account = add_account(client)
    monitor = add_monitor(client, account=account, failure_threshold=1, release_previous=True)
    store = client.app.state.store
    timestamp = time.time()
    assert store.record_cleanup_intent(account, {**PREVIOUS, "attempt_id": "older"}, timestamp)
    assert store.unblock_cleanup(OLD, "older", timestamp)
    token, entry = store.claim_cleanup(OLD, timestamp)
    passed_before_allocate = []
    cloud.rotation_hook = lambda: passed_before_allocate.append(True)

    [result] = run_scheduled(client, monitor)
    assert result["rotation"]["status"] == "skipped"
    assert store.rotation_guard(RESOURCE)["state"] == "ready"
    assert cloud.ip == "8.8.8.8"
    assert passed_before_allocate == [] and cloud.release_calls == []
    assert not any(row["action"] == "ec2.auto-rotate.failed" for row in store.list("activity"))

    # The conflict occurred before AWS allocation. Releasing the other owner's
    # lease must allow the following cron run without a manual reset.
    assert store.finish_cleanup(OLD, token, data=entry)
    [result] = run_scheduled(client, monitor)
    assert result["rotation"]["status"] == "rotated"
    assert passed_before_allocate == [True]
    assert cloud.ip != "8.8.8.8"
    assert cloud.release_calls == [(OLD, "ap-southeast-2")]


@pytest.mark.parametrize("scheduled", [False, True])
def test_active_rotation_intent_cannot_be_approved_or_released(client, cloud, scheduled):
    account = add_account(client)
    monitor = add_monitor(client, account=account, failure_threshold=1, release_previous=True) if scheduled else None
    approvals, dismissals = [], []

    def during_allocation():
        # The durable intent exists, but AllocateAddress/AssociateAddress has
        # not returned yet. Approval must not race the active mutation.
        approvals.append(client.post(f"/api/eip-cleanup/{OLD}/approve").status_code)
        dismissals.append(client.delete(f"/api/eip-cleanup/{OLD}").status_code)
        assert client.app.state.run_eip_cleanup() == 0

    cloud.rotation_hook = during_allocation
    cloud.rotate_error = AwsLikeError("AwsTransportError", "association not confirmed")
    if scheduled:
        [result] = run_scheduled(client, monitor)
        assert result["rotation"]["status"] == "awaiting_review"
        assert client.app.state.store.rotation_guard(RESOURCE)["state"] == "awaiting_review"
    else:
        assert rotate(client, account).status_code == 502
    assert approvals == [409] and dismissals == [409]
    assert cloud.release_calls == []
    assert queue(client)[0]["state"] == "blocked"
    assert client.app.state.run_eip_cleanup() == 0


def test_pending_intent_prevents_account_delete_during_rotation(client, cloud):
    account = add_account(client)
    intent_written = threading.Event()
    allow_rotation = threading.Event()

    def during_allocation():
        intent_written.set()
        assert allow_rotation.wait(5)

    cloud.rotation_hook = during_allocation
    with ThreadPoolExecutor(max_workers=1) as pool:
        rotating = pool.submit(rotate, client, account)
        try:
            assert intent_written.wait(5)
            response = client.delete(f"/api/accounts/{account}")
            assert response.status_code == 409, response.text
            assert client.app.state.store.get("accounts", account) is not None
        finally:
            allow_rotation.set()
        assert rotating.result(timeout=5).status_code == 200
    assert queue(client) == []


@pytest.mark.parametrize("check", ["detached", "gone", "reused", "stale"])
def test_lost_completion_does_not_publish_false_cleanup_success(client, cloud, monkeypatch, check):
    cloud.release_check_default = check
    store = client.app.state.store
    monkeypatch.setattr(store, "finish_cleanup", lambda *args, **kwargs: False)
    response = rotate(client, add_account(client))
    assert response.status_code == 200, response.text
    [entry] = queue(client)
    assert entry["state"] == "queued" and entry["attempts"] == 0
    completion_actions = {
        "ec2.eip-cleanup.released", "ec2.eip-cleanup.gone",
        "ec2.eip-cleanup.review", "ec2.eip-cleanup.queued", "ec2.eip-cleanup.failed",
    }
    assert not any(row["action"] in completion_actions for row in store.list("activity"))
    assert "已释放" not in response.json()["message"]


def test_shutdown_waits_for_running_cleanup(tmp_path, cloud, monkeypatch):
    monkeypatch.setenv("PANEL_SCHEDULER", "internal")
    entered = threading.Event()
    allow_return = threading.Event()
    finished = threading.Event()

    def blocking_check():
        entered.set()
        try:
            assert allow_return.wait(5)
            return "stale"
        finally:
            finished.set()

    cloud.release_check_default = blocking_check
    app = main.create_app(tmp_path, start_scheduler=True, aws_factory=cloud.factory,
                          scheduler_tick=0.01, release_wait_seconds=0, cleanup_interval=0)

    async def wait_for_entry():
        while not entered.is_set():
            await asyncio.sleep(0.005)

    async def scenario():
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        store = app.state.store
        store.put("accounts", {"id": "a", "region": "ap-southeast-2", "aws_account_id": "123456789012"}, secret={})
        timestamp = time.time()
        assert store.record_cleanup_intent("a", {**PREVIOUS, "attempt_id": "first"}, timestamp)
        assert store.unblock_cleanup(OLD, "first", timestamp)
        closing = None
        try:
            await asyncio.wait_for(wait_for_entry(), timeout=5)
            closing = asyncio.create_task(context.__aexit__(None, None, None))
            await asyncio.sleep(0.05)
            returned_before_worker = closing.done() and not finished.is_set()
        finally:
            allow_return.set()
            if closing is None:
                await asyncio.wait_for(context.__aexit__(None, None, None), timeout=5)
            else:
                await asyncio.wait_for(closing, timeout=5)
        assert finished.is_set()
        assert not returned_before_worker, "shutdown returned while its cleanup thread was still calling AWS"

    asyncio.run(scenario())


def test_external_cron_processes_due_cleanup(client, cloud, monkeypatch, capsys):
    from app import cron_worker

    cloud.release_check_default = "stale"
    rotate(client, add_account(client))
    make_due(client)
    cloud.release_check_default = "detached"
    store = client.app.state.store

    def create_worker(*, start_scheduler):
        assert start_scheduler is False
        return main.create_app(store.directory, start_scheduler=False, aws_factory=cloud.factory,
                               rotation_verify_delay=0, release_wait_seconds=0)

    monkeypatch.setattr(cron_worker, "create_app", create_worker)
    asyncio.run(cron_worker.run())
    summary = json.loads(capsys.readouterr().out)
    assert summary["checked"] == 0 and summary["eip_cleanup_processed"] == 1
    assert queue(client) == []
    assert cloud.release_calls == [(OLD, "ap-southeast-2")]
