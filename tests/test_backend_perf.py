"""Client reuse, per-instance lookups, concurrent probes and a non-blocking scheduler."""
import threading
import time

from botocore.stub import Stubber
from fastapi.testclient import TestClient

import app.main as main
from app.aws_service import AwsService
from app.main import create_app
from tests.test_main import FakeAws, INSTANCE, add_account, add_monitor, auth, client  # noqa: F401


def measurement(samples=3):
    return {"success_count": samples, "samples": samples, "latency_ms": 1.0, "loss_percent": 0,
            "attempts": [{"ok": True, "latency_ms": 1.0} for _ in range(samples)]}


def test_aws_service_is_reused_until_account_is_deleted(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    built = []

    class CountingAws(FakeAws):
        def __init__(self, credentials, region):
            super().__init__(credentials, region)
            built.append(region)

    with TestClient(create_app(tmp_path, start_scheduler=False, aws_factory=CountingAws), base_url="http://localhost", client=("127.0.0.1", 5555)) as c:
        auth(c)
        account = add_account(c)
        validation_builds = len(built)
        for _ in range(3):
            assert c.get(f"/api/accounts/{account}/instances").status_code == 200
        assert len(built) == validation_builds + 1
        assert c.delete(f"/api/accounts/{account}").status_code == 200
        assert c.get(f"/api/accounts/{account}/instances").status_code == 404
        assert len(built) == validation_builds + 1


def test_instance_lookup_queries_one_id_and_reports_missing():
    service = AwsService({"access_key_id": "AKIATESTKEYEXAMPLE001", "secret_access_key": "test-secret-value-do-not-log"}, "ap-southeast-2")
    with Stubber(service.ec2) as stub:
        stub.add_response("describe_instances", {"Reservations": [{"Instances": [{
            "InstanceId": INSTANCE, "State": {"Name": "running"}, "PublicIpAddress": "203.0.113.5",
            "Tags": [{"Key": "Name", "Value": "web"}],
        }]}]}, {"InstanceIds": [INSTANCE]})
        stub.add_client_error("describe_instances", "InvalidInstanceID.NotFound", expected_params={"InstanceIds": [INSTANCE]})
        found = service.instance(INSTANCE)
        assert found["id"] == INSTANCE and found["name"] == "web" and found["public_ip"] == "203.0.113.5"
        assert service.instance(INSTANCE) is None
        stub.assert_no_pending_responses()
    assert service.instance("i-123") is None  # malformed ID: no request, not found


def test_local_and_remote_probes_run_concurrently_in_stable_order(client, monkeypatch):
    def slow_local(**args):
        time.sleep(0.5)
        return measurement(args["samples"])

    def slow_remote(url, token, args):
        time.sleep(0.5)
        return measurement(args["samples"])

    monkeypatch.setattr(main, "tcp_probe", slow_local)
    monkeypatch.setattr(main, "remote_probe", slow_remote)
    auth(client)
    monitor = add_monitor(client, add_account(client))
    store = client.app.state.store
    for index, region in enumerate(["mainland", "overseas"]):
        store.put("probes", {"id": f"probe{index}", "name": f"P{index}", "region_type": region,
                             "url": f"https://{region}.example/probe", "enabled": True}, {"token": "t" * 32})
    started = time.monotonic()
    result = client.post(f"/api/monitors/{monitor}/run").json()["result"]
    elapsed = time.monotonic() - started
    assert elapsed < 1.2, f"three 0.5 s probes should overlap, took {elapsed:.2f}s"
    assert [o["name"] for o in result["observations"]] == ["面板后端", *(p["name"] for p in store.list("probes"))]
    assert result["gfw_status"] == "reachable_from_both"


def test_slow_monitor_does_not_delay_a_monitor_that_becomes_due_later(tmp_path, monkeypatch):
    monkeypatch.delenv("PANEL_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("PANEL_ENCRYPTION_KEY", raising=False)
    slow_started, release_slow, fast_done = threading.Event(), threading.Event(), threading.Event()

    def probe(**args):
        if args["port"] == 22:
            slow_started.set()
            assert release_slow.wait(10)
        else:
            fast_done.set()
        return measurement(args["samples"])

    monkeypatch.setattr(main, "tcp_probe", probe)
    with TestClient(create_app(tmp_path, start_scheduler=False, aws_factory=FakeAws), base_url="http://localhost", client=("127.0.0.1", 5555)) as c:
        auth(c)
        account = add_account(c)
        slow, fast = add_monitor(c, account, port=22), add_monitor(c, account, name="HTTPS", port=443)
        store = c.app.state.store
        store.put("monitors", store.get("monitors", slow), next_due=time.time() - 1)
        store.put("monitors", store.get("monitors", fast), next_due=time.time() + 0.5)
    try:
        with TestClient(create_app(tmp_path, start_scheduler=True, aws_factory=FakeAws, scheduler_tick=0.02), base_url="http://localhost"):
            assert slow_started.wait(5)
            assert fast_done.wait(5), "a monitor due later must run while an earlier one is still busy"
            release_slow.set()
    finally:
        release_slow.set()
    results = {r["port"]: r["status"] for r in store.list("results")}
    assert results == {22: "reachable", 443: "reachable"}, "shutdown should let the slow check finish"


def test_static_files_are_compressed_and_revalidated(client):
    script = client.get("/app.js", headers={"Accept-Encoding": "gzip"})
    assert script.status_code == 200
    assert script.headers["content-encoding"] == "gzip"
    assert script.headers["cache-control"] == "no-cache"
    assert "refreshData" in script.text
    page = client.get("/", headers={"Accept-Encoding": "gzip"})
    assert page.headers["cache-control"] == "no-cache"
    cached = client.get("/app.js", headers={"If-None-Match": script.headers["etag"]})
    assert cached.status_code == 304
    assert client.get("/api/health").headers["cache-control"] == "no-store"
