import threading
from app.store import Store
from app.leases import keep_lease


def test_expired_monitor_owner_cannot_release_or_renew_successor(tmp_path):
    store = Store(tmp_path)
    store.put("monitors", {"id": "job", "enabled": True}, next_due=1)
    first = store.acquire_monitor("job", 100, lease_seconds=10)
    assert first
    assert store.acquire_monitor("job", 105) is None
    second = store.acquire_monitor("job", 111)
    assert second and first != second
    store.release_monitor("job", first)
    assert store.renew_monitor("job", first, 120) is False
    assert store.acquire_monitor("job", 121) is None
    store.release_monitor("job", second)
    assert store.acquire_monitor("job", 122)


def test_resource_owner_renewal_prevents_expiry_and_stale_release(tmp_path):
    store = Store(tmp_path)
    first = store.acquire_resource("actual-account:region:instance", 100, duration=10)
    assert store.renew_resource("actual-account:region:instance", first, 105)
    assert store.acquire_resource("actual-account:region:instance", 111) is None
    second = store.acquire_resource("actual-account:region:instance", 1006)
    assert second
    store.release_resource("actual-account:region:instance", first)
    assert store.renew_resource("actual-account:region:instance", first, 1007) is False
    assert store.acquire_resource("actual-account:region:instance", 1008) is None


def test_heartbeat_renews_and_marks_ownership_loss():
    renewed = threading.Event()
    def renew():
        renewed.set()
        return False
    with keep_lease(renew, interval=0.005) as owned:
        assert renewed.wait(2)
        for _ in range(100):
            if not owned.is_set():
                break
            threading.Event().wait(0.001)
        assert not owned.is_set()


def test_stale_worker_cannot_reserve_rotation_or_reschedule_successor(tmp_path):
    store = Store(tmp_path)
    store.put("monitors", {"id": "job", "enabled": True, "auto_rotate": True, "interval_seconds": 60, "config_revision": "v1"}, next_due=1)
    old_monitor = store.acquire_monitor("job", 100, lease_seconds=10)
    old_resource = store.acquire_resource("resource", 100, duration=10)
    new_monitor = store.acquire_monitor("job", 111)
    new_resource = store.acquire_resource("resource", 111)
    rejected = store.reserve_rotation("resource", "job", "v1", 112, monitor_token=old_monitor, resource_token=old_resource)
    assert rejected["status"] == "skipped"
    store.complete_monitor("job", "reachable", "old-check", 112, old_monitor)
    assert store.get("monitors", "job").get("last_checked_at") is None
    assert store.update_monitor("job", {"failure_streak": 9}, expected_lease=old_monitor) is None
    valid = store.reserve_rotation("resource", "job", "v1", 2000, monitor_token=new_monitor, resource_token=new_resource)
    assert valid["status"] == "skipped", "even correct tokens cannot authorize after expiry"
