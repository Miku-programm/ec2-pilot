"""Concurrent HTTP mutations must lock the AWS resource, not its local alias."""
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import threading

from fastapi.testclient import TestClient

import app.main as main


def test_duplicate_account_entries_serialize_rotation_of_same_aws_instance(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("PANEL_ALLOWED_HOSTS", "localhost")
    first_entered = threading.Event()
    release_first = threading.Event()
    second_lock_attempted = threading.Event()
    observer_guard = threading.Lock()
    lock_attempts = []
    calls = []
    instance_id = "i-0123456789abcdef0"

    class ObservedLock:
        """Real mutex with an observable contention point; no timing guesses."""
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            acquired = self.lock.acquire(blocking=False)
            with observer_guard:
                lock_attempts.append({"lock": self, "contended": not acquired})
                if len(lock_attempts) == 2:
                    second_lock_attempted.set()
            if not acquired:
                self.lock.acquire()
            return self

        def __exit__(self, *_):
            self.lock.release()

    def observed_defaultdict(factory, *args, **kwargs):
        # Only instrument the app's mutation mutexes; all mutex semantics remain
        # real and the test does not assume the format of the account/resource key.
        return defaultdict(ObservedLock if factory is threading.Lock else factory, *args, **kwargs)

    monkeypatch.setattr(main, "defaultdict", observed_defaultdict)

    class FakeAws:
        def __init__(self, credentials, region):
            self.region = region

        def validate(self):
            return {"aws_account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test"}

        def rotate_ip(self, target_id, release_previous=False):
            assert target_id == instance_id
            with observer_guard:
                calls.append(target_id)
                ordinal = len(calls)
            if ordinal == 1:
                first_entered.set()
                assert release_first.wait(10), "test must release the first AWS operation"
            return {"public_ip": "203.0.113.10", "allocation_id": "eipalloc-0123456789abcdef0", "message": "changed"}

    app = main.create_app(tmp_path, start_scheduler=False, aws_factory=FakeAws)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5555)) as client:
        setup = client.post("/api/setup", json={"password": "test-concurrency-password-2026"})
        assert setup.status_code == 200, setup.text
        entries = []
        for name in ("Sydney account alias A", "Sydney account alias B"):
            response = client.post("/api/accounts", json={
                "name": name, "access_key_id": "AKIA" + "X" * 16,
                "secret_access_key": "fake-secret-testing-" * 3, "region": "ap-southeast-2",
            })
            assert response.status_code == 200, response.text
            entries.append(response.json())
        assert entries[0]["id"] != entries[1]["id"]
        assert entries[0]["aws_account_id"] == entries[1]["aws_account_id"]

        def rotate(entry):
            return client.post(f"/api/accounts/{entry['id']}/instances/{instance_id}/rotate-ip", json={"release_previous": False})

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(rotate, entries[0])
            second = None
            try:
                assert first_entered.wait(5), "first mutation must reach the fake AWS service"
                second = executor.submit(rotate, entries[1])
                assert second_lock_attempted.wait(5), "second request must reach its mutation lock"
                # The first fake AWS call is still held by release_first. Thus the
                # second attempt must contend on that very mutex, deterministically.
                assert lock_attempts[1]["contended"], "duplicate local entries must share a lock for the same AWS instance"
                assert lock_attempts[0]["lock"] is lock_attempts[1]["lock"]
                assert len(calls) == 1
            finally:
                release_first.set()
                result1 = first.result(timeout=10)
                result2 = second.result(timeout=10) if second is not None else None
            assert result1.status_code == 200, result1.text
            assert result2 is not None and result2.status_code == 200, result2.text if result2 else "missing second response"
            assert calls == [instance_id, instance_id]
