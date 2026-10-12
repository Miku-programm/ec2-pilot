import time
import threading
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
import app.main as main

PASSWORD = "test-password-only-2026"
INSTANCE = "i-0123456789abcdef0"


class FakeAws:
    ip = "8.8.8.8"
    calls = []

    def __init__(self, credentials, region):
        self.credentials = credentials
        self.region = region

    def validate(self):
        return {"aws_account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test"}

    def instances(self):
        return [{"id": INSTANCE, "name": "test", "state": "running", "public_ip": self.ip, "instance_type": "t3.micro"}]

    def rotate_ip(self, instance_id, release_previous=False):
        self.calls.append(("rotate", instance_id, release_previous))
        return {"public_ip": "1.1.1.1", "allocation_id": "eipalloc-0123456789abcdef0", "message": "changed"}

    def launch(self, payload):
        self.calls.append(("launch", payload))
        return {"instance_ids": [INSTANCE], "message": "submitted"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    FakeAws.ip = "8.8.8.8"
    FakeAws.calls = []
    app = create_app(tmp_path, start_scheduler=False, aws_factory=FakeAws)
    with TestClient(app, base_url="http://localhost", client=("127.0.0.1", 5555)) as c:
        yield c


def auth(c):
    assert c.post("/api/setup", json={"password": PASSWORD}).status_code == 200


def add_account(c):
    r = c.post("/api/accounts", json={"name": "test", "access_key_id": "AKIA" + "X" * 16, "secret_access_key": "secret-testing-" * 4, "region": "ap-southeast-2"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def add_monitor(c, account_id, **overrides):
    body = {"name": "SSH", "account_id": account_id, "instance_id": INSTANCE, "port": 22, "interval_seconds": 60, **overrides}
    r = c.post("/api/monitors", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_auth_setup_logout_and_csrf(client):
    assert client.get("/api/state").status_code == 401
    assert client.get("/api/health").json()["setup_required"]
    auth(client)
    assert client.get("/api/state").status_code == 200
    assert client.post("/api/setup", json={"password": PASSWORD}).status_code == 409
    assert client.post("/api/scripts", headers={"Origin": "https://evil.test"}, json={"name": "x", "content": ""}).status_code == 403
    cookie = client.cookies.get("ec2_panel_session")
    assert cookie
    client.post("/api/logout")
    assert client.get("/api/state").status_code == 401
    assert client.post("/api/login", json={"password": PASSWORD}).status_code == 200


def test_secrets_encrypted_and_not_returned(client):
    auth(client)
    account_id = add_account(client)
    text = client.get("/api/state").text
    assert "secret-testing" not in text
    assert "AKIA" + "X" * 16 not in text
    with client.app.state.store.connect() as db:
        raw = db.execute("SELECT secret FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
    assert "secret-testing" not in raw
    record = client.app.state.store.get("accounts", account_id, True)
    assert record["credentials"]["secret_access_key"] == "secret-testing-" * 4


def test_validation_does_not_echo_credentials(client):
    auth(client)
    r = client.post("/api/accounts", json={"name": "n", "access_key_id": "tiny-secret", "secret_access_key": "private-short"})
    assert r.status_code == 422
    assert "tiny-secret" not in r.text
    assert "private-short" not in r.text


def test_launch_idempotency_and_specific_rotate_route(client):
    auth(client)
    a = add_account(client)
    launch = {"name": "new", "image_id": "ami-0123456789abcdef0", "instance_type": "t3.micro"}
    assert client.post(f"/api/accounts/{a}/instances/launch", json=launch).status_code == 422
    token = "12345678-1234-1234-1234-123456789012"
    r = client.post(f"/api/accounts/{a}/instances/launch", json=launch, headers={"Idempotency-Key": token})
    assert r.status_code == 200, r.text
    assert FakeAws.calls[-1][1]["operation_token"] == token
    r = client.post(f"/api/accounts/{a}/instances/{INSTANCE}/rotate-ip", json={"release_previous": False})
    assert r.status_code == 200, r.text
    assert FakeAws.calls[-1] == ("rotate", INSTANCE, False)


def test_monitor_resolves_latest_ip_and_does_not_claim_gfw(client, monkeypatch):
    auth(client)
    a = add_account(client)
    m = add_monitor(client, a)
    seen = []

    def probe(**kwargs):
        seen.append(kwargs["target_ip"])
        return {"success_count": 0, "samples": 3, "latency_ms": None, "loss_percent": 100, "attempts": []}

    monkeypatch.setattr(main, "tcp_probe", probe)
    FakeAws.ip = "1.1.1.1"
    r = client.post(f"/api/monitors/{m}/run").json()["result"]
    assert seen == ["1.1.1.1"]
    assert r["status"] == "unreachable"
    assert r["gfw_status"] == "insufficient_evidence"
    assert client.delete(f"/api/accounts/{a}").status_code == 409
    assert client.put(f"/api/monitors/{m}", json={"enabled": False}).status_code == 200
    assert client.app.state.store.due_monitors(time.time() + 100000) == []


def test_no_public_ip_never_probes(client, monkeypatch):
    auth(client)
    a = add_account(client)
    m = add_monitor(client, a)
    FakeAws.ip = None
    monkeypatch.setattr(main, "tcp_probe", lambda **kw: pytest.fail("No IP must not be probed"))
    r = client.post(f"/api/monitors/{m}/run").json()["result"]
    assert r["status"] == "no_public_ip"


def test_scheduler_runs_without_browser_and_persists(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    FakeAws.ip = "8.8.8.8"
    event = threading.Event()
    def probe(**kw):
        event.set()
        return {"success_count": 3, "samples": 3, "latency_ms": 2.5, "loss_percent": 0, "attempts": []}
    monkeypatch.setattr(main, "tcp_probe", probe)
    with TestClient(create_app(tmp_path, start_scheduler=False, aws_factory=FakeAws), base_url="http://localhost", client=("127.0.0.1", 55)) as c:
        auth(c)
        a = add_account(c)
        m = add_monitor(c, a)
        record = c.app.state.store.get("monitors", m)
        c.app.state.store.put("monitors", record, next_due=time.time() - 1)
    with TestClient(create_app(tmp_path, start_scheduler=True, aws_factory=FakeAws, scheduler_tick=0.05), base_url="http://localhost") as c:
        assert event.wait(3), "background scheduler should run a persisted due task"
        deadline = time.time() + 3
        while not c.app.state.store.list("results") and time.time() < deadline:
            time.sleep(0.02)
        assert c.app.state.store.list("results")[0]["status"] == "reachable"


def test_rebound_host_cannot_claim_setup(client):
    response = client.post("/api/setup", headers={"Host": "rebound.attacker.example:8080", "Origin": "http://rebound.attacker.example:8080"}, json={"password": PASSWORD})
    assert response.status_code == 400
    assert client.get("/api/health").json()["setup_required"] is True


@pytest.mark.parametrize("action", ["delete", "disable"])
def test_monitor_completion_respects_changes_during_probe(client, monkeypatch, action):
    auth(client)
    a = add_account(client)
    m = add_monitor(client, a)
    def probe(**kwargs):
        if action == "delete":
            client.app.state.store.delete("monitors", m)
        else:
            record = client.app.state.store.get("monitors", m)
            record["enabled"] = False
            client.app.state.store.put("monitors", record, next_due=1e12)
        return {"success_count": 3, "samples": 3, "latency_ms": 2.5, "loss_percent": 0, "attempts": []}
    monkeypatch.setattr(main, "tcp_probe", probe)
    assert client.post(f"/api/monitors/{m}/run").status_code == 200
    record = client.app.state.store.get("monitors", m)
    if action == "delete":
        assert record is None
    else:
        assert record["enabled"] is False
        assert record["next_run_at"] is None
    assert client.app.state.store.due_monitors(time.time() + 100000) == []


def test_probe_validation_failure_does_not_store_token(client, monkeypatch):
    auth(client)
    def reject(url):
        raise ValueError("Probe URL must use public HTTPS")
    monkeypatch.setattr(main, "validate_remote_url", reject)
    response = client.post("/api/probes", json={"name": "local", "region_type": "mainland", "url": "https://127.0.0.1/probe", "token": "probe-test-secret-" * 2})
    assert response.status_code == 422
    assert client.get("/api/state").json()["probes"] == []
    assert "probe-test-secret" not in response.text


@pytest.mark.parametrize("suffix", ["\n", " ", "令牌"])
def test_probe_rejects_tokens_invalid_for_bearer_headers(client, monkeypatch, suffix):
    auth(client)
    monkeypatch.setattr(main, "validate_remote_url", lambda url: url)
    token = "private-probe-test-token-1234" + suffix
    response = client.post("/api/probes", json={"name": "test", "region_type": "mainland", "url": "https://example.com/probe", "token": token})
    assert response.status_code == 422
    assert "private-probe-test-token" not in response.text
    assert client.get("/api/state").json()["probes"] == []
