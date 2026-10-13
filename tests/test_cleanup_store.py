"""Durable cleanup ownership and account deletion must share transaction rules."""
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

import pytest

from app.store import Store


ACCOUNT = "account-a"
AWS_ACCOUNT = "123456789012"
REGION = "us-east-1"
INSTANCE = "i-0123456789abcdef0"
RESOURCE = f"{AWS_ACCOUNT}:{REGION}:{INSTANCE}"
ALLOCATION = "eipalloc-0123456789abcdef0"


def add_account(store, account_id=ACCOUNT):
    store.put("accounts", {"id": account_id, "aws_account_id": AWS_ACCOUNT, "region": REGION}, secret={})


def intent(attempt="rotation-one", **changes):
    return {"allocation_id": ALLOCATION, "association_id": "eipassoc-0123456789abcdef0",
            "instance_id": INSTANCE, "attempt_id": attempt, **changes}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    result = Store(tmp_path)
    add_account(result)
    return result


def queue(store, timestamp=100):
    assert store.record_cleanup_intent(ACCOUNT, intent(), timestamp)
    assert store.unblock_cleanup(ALLOCATION, "rotation-one", timestamp)


def test_replacement_revokes_expired_owner_and_preserves_new_intent(store):
    queue(store)
    stale_token, stale_data = store.claim_cleanup(ALLOCATION, 101)
    assert store.record_cleanup_intent(ACCOUNT, intent("rotation-two"), 500)

    assert not store.finish_cleanup(ALLOCATION, stale_token, remove=True, timestamp=500)
    assert not store.finish_cleanup(ALLOCATION, stale_token, state="failed", data=stale_data, timestamp=500)
    assert not store.renew_cleanup(ALLOCATION, stale_token, 500)
    assert not store.unblock_cleanup(ALLOCATION, "rotation-one", 500)
    [entry] = store.list_cleanup()
    assert entry["state"] == "blocked" and entry["attempt_id"] == "rotation-two"

    assert store.unblock_cleanup(ALLOCATION, "rotation-two", 501)
    new_token, _ = store.claim_cleanup(ALLOCATION, 502)
    assert stale_token != new_token
    assert not store.finish_cleanup(ALLOCATION, stale_token, remove=True, timestamp=503)
    assert store.finish_cleanup(ALLOCATION, new_token, remove=True, timestamp=503)
    assert store.list_cleanup() == []


@pytest.mark.parametrize("remove", [False, True])
def test_expired_owner_cannot_complete_even_before_a_successor_claims(store, remove):
    queue(store)
    token, data = store.claim_cleanup(ALLOCATION, 101)
    assert not store.finish_cleanup(ALLOCATION, token, remove=remove, data=data, timestamp=401)
    assert len(store.list_cleanup()) == 1
    assert store.claim_cleanup(ALLOCATION, 402) is not None


def test_completion_requires_queued_state_in_addition_to_ownership(store):
    queue(store)
    token, _ = store.claim_cleanup(ALLOCATION, 101)
    with store.connect() as db:
        db.execute("UPDATE eip_cleanup SET state='blocked' WHERE allocation_id=?", (ALLOCATION,))
    assert not store.finish_cleanup(ALLOCATION, token, remove=True, timestamp=102)
    assert store.list_cleanup()[0]["state"] == "blocked"


def test_live_owner_prevents_replacement_approval_and_dismissal(store):
    queue(store)
    token, _ = store.claim_cleanup(ALLOCATION, 101)
    assert not store.record_cleanup_intent(ACCOUNT, intent("rotation-two"), 102)
    assert store.approve_cleanup(ALLOCATION, 102) == "busy"
    assert store.dismiss_cleanup(ALLOCATION, 102) == "busy"
    assert store.finish_cleanup(ALLOCATION, token, state="failed", timestamp=102)
    assert store.approve_cleanup(ALLOCATION, 103) == "queued"


def test_approval_revokes_any_token_from_an_expired_failed_attempt(store):
    queue(store)
    old_token, _ = store.claim_cleanup(ALLOCATION, 101)
    with store.connect() as db:
        db.execute("UPDATE eip_cleanup SET state='failed' WHERE allocation_id=?", (ALLOCATION,))
    assert store.approve_cleanup(ALLOCATION, 500) == "queued"
    with store.connect() as db:
        row = db.execute("SELECT lease_token,lease_until FROM eip_cleanup").fetchone()
    assert row["lease_token"] == "" and row["lease_until"] == 0
    assert not store.finish_cleanup(ALLOCATION, old_token, remove=True, timestamp=500)


def test_active_rotation_prevents_approval_and_dismissal_of_blocked_intent(store):
    timestamp = time.time()
    assert store.record_cleanup_intent(ACCOUNT, intent(), timestamp)
    token = store.acquire_resource(RESOURCE, timestamp)
    assert store.list_cleanup()[0]["processing"] is True
    assert store.approve_cleanup(ALLOCATION, timestamp + 1) == "busy"
    assert store.dismiss_cleanup(ALLOCATION, timestamp + 1) == "busy"
    assert store.list_cleanup()[0]["state"] == "blocked"
    store.release_resource(RESOURCE, token)
    assert store.list_cleanup()[0]["processing"] is False
    assert store.approve_cleanup(ALLOCATION, timestamp + 2) == "queued"


def test_list_exposes_live_cleanup_processing_without_lease_token(store):
    timestamp = time.time()
    queue(store, timestamp)
    token, _ = store.claim_cleanup(ALLOCATION, timestamp + 0.001)
    [entry] = store.list_cleanup()
    assert entry["processing"] is True and "lease_token" not in entry
    assert store.finish_cleanup(ALLOCATION, token, state="review", timestamp=timestamp + 1)
    assert store.list_cleanup()[0]["processing"] is False


def test_intent_uses_saved_cloud_identity_and_requires_existing_account(store):
    assert store.record_cleanup_intent(ACCOUNT, intent(region="wrong-region", aws_account_id="wrong-account"), 100)
    [entry] = store.list_cleanup()
    assert entry["aws_account_id"] == AWS_ACCOUNT and entry["region"] == REGION
    assert not store.record_cleanup_intent("missing-account", intent("replacement"), 101)
    assert store.list_cleanup()[0]["attempt_id"] == "rotation-one"


@pytest.mark.parametrize("successor", [False, True])
def test_expired_rotation_owner_cannot_write_or_replace_cleanup_intent(store, successor):
    old_token = store.acquire_resource(RESOURCE, 100, duration=1)
    if successor:
        new_token = store.acquire_resource(RESOURCE, 102)
        assert store.record_cleanup_intent(ACCOUNT, intent("new-rotation"), 102, resource_token=new_token)
    assert not store.record_cleanup_intent(ACCOUNT, intent("late-old-rotation"), 103, resource_token=old_token)
    if successor:
        assert store.list_cleanup()[0]["attempt_id"] == "new-rotation"
    else:
        assert store.list_cleanup() == []


def test_delete_account_rejects_live_resources_shared_by_other_aliases(store):
    add_account(store, "account-alias")
    token = store.acquire_resource(RESOURCE, 100)
    assert store.delete_account_if_unused(ACCOUNT, 101) == "busy"
    assert store.delete_account_if_unused("account-alias", 101) == "busy"
    assert store.get("accounts", ACCOUNT) is not None
    store.release_resource(RESOURCE, token)
    assert store.delete_account_if_unused(ACCOUNT, 102) == "deleted"
    assert store.delete_account_if_unused(ACCOUNT, 103) == "missing"


def test_account_delete_ignores_expired_or_other_region_resource_leases(store):
    assert store.acquire_resource(RESOURCE, 100, duration=1)
    assert store.acquire_resource(f"{AWS_ACCOUNT}:ap-southeast-2:{INSTANCE}", 100)
    assert store.delete_account_if_unused(ACCOUNT, 102) == "deleted"
    assert not store.record_cleanup_intent(ACCOUNT, intent(), 103)


def test_account_delete_preserves_credentials_needed_by_monitors_or_cleanup(store):
    store.put("monitors", {"id": "monitor-a", "account_id": ACCOUNT}, next_due=100)
    assert store.delete_account_if_unused(ACCOUNT, 100) == "monitors"
    store.delete("monitors", "monitor-a")
    assert store.record_cleanup_intent(ACCOUNT, intent(), 101)
    assert store.delete_account_if_unused(ACCOUNT, 102) == "cleanup"
    assert store.get("accounts", ACCOUNT, include_secret=True)["credentials"] == {}


def test_simultaneous_account_delete_and_intent_never_orphan_cleanup(store):
    # Either transaction can win. The forbidden outcome is a committed intent
    # paired with deleted credentials; exercise the actual SQLite contention.
    for number in range(8):
        account_id = f"racing-account-{number}"
        allocation_id = f"eipalloc-{number:017x}"
        add_account(store, account_id)
        ready = threading.Barrier(2)

        def write_intent():
            ready.wait(timeout=5)
            return store.record_cleanup_intent(account_id, intent(allocation_id=allocation_id), 100)

        def delete_account():
            ready.wait(timeout=5)
            return store.delete_account_if_unused(account_id, 100)

        with ThreadPoolExecutor(max_workers=2) as pool:
            write = pool.submit(write_intent)
            delete = pool.submit(delete_account)
            written, outcome = write.result(timeout=15), delete.result(timeout=15)
        assert (written, outcome) in {(True, "cleanup"), (False, "deleted")}
        assert bool(store.list_cleanup(account_id)) == written
        assert (store.get("accounts", account_id) is not None) == written


def test_preallocation_skip_releases_rotation_guard_without_changing_last_success(store):
    monitor = {"id": "monitor-a", "account_id": ACCOUNT, "instance_id": INSTANCE,
               "enabled": True, "auto_rotate": True, "config_revision": "revision-a"}
    store.put("monitors", monitor, next_due=100)
    monitor_token = store.acquire_monitor("monitor-a", 100)
    resource_token = store.acquire_resource(RESOURCE, 100)
    with store.connect() as db:
        db.execute("INSERT INTO rotation_guards VALUES (?,?)", (RESOURCE, json.dumps({"state": "ready", "last_rotation_at": 42})))
    reserved = store.reserve_rotation(RESOURCE, "monitor-a", "revision-a", 101,
                                      monitor_token=monitor_token, resource_token=resource_token)
    store.finish_rotation(RESOURCE, reserved["attempt_id"], {"status": "skipped", "message": "cleanup busy before allocation"}, 102)
    assert store.rotation_guard(RESOURCE)["state"] == "ready"
    assert store.rotation_guard(RESOURCE)["last_rotation_at"] == 42
    assert store.reserve_rotation(RESOURCE, "monitor-a", "revision-a", 103,
                                  monitor_token=monitor_token, resource_token=resource_token)["status"] == "reserved"
