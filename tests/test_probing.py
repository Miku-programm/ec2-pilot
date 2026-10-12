import errno
import json
import socket
import threading

import pytest

from app import probing


def result(ok=True):
    return {"success_count": int(ok), "samples": 1, "latency_ms": 5.0 if ok else None,
            "loss_percent": 0.0 if ok else 100.0,
            "attempts": [{"ok": ok, "latency_ms": 5.0, **({} if ok else {"error": "timeout"})}]}


class FakeSocket:
    def __init__(self, failure=None):
        self.failure = failure
        self.connected = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected = address
        if self.failure:
            raise self.failure

    def close(self):
        self.closed = True


def test_tcp_measures_partial_success_and_closes_sockets(monkeypatch):
    sockets = [FakeSocket(), FakeSocket(TimeoutError()), FakeSocket(OSError(errno.ECONNREFUSED, "refused"))]
    queue = iter(sockets)
    monkeypatch.setattr(probing.socket, "socket", lambda *a: next(queue))
    ticks = iter([0.0, 0.010, 1.0, 1.020, 2.0, 2.030])
    monkeypatch.setattr(probing.time, "perf_counter", lambda: next(ticks))
    data = probing.tcp_probe("8.8.8.8", 443, samples=3)
    assert data["success_count"] == 1
    assert data["latency_ms"] == 10.0
    assert data["loss_percent"] == 66.67
    assert [a.get("error") for a in data["attempts"]] == [None, "timeout", "connection_refused"]
    assert all(s.closed and s.connected == ("8.8.8.8", 443) for s in sockets)


def test_local_socket_failure_is_not_reported_as_tcp_unreachable(monkeypatch):
    def socket_failure(*args):
        raise OSError(errno.EMFILE, "too many open files")
    monkeypatch.setattr(probing.socket, "socket", socket_failure)
    with pytest.raises(OSError):
        probing.tcp_probe("8.8.8.8", 443)


@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.0.1",
                                      "100.64.0.1", "224.0.0.1", "0.0.0.0", "192.0.2.5",
                                      "::1", "2606:4700:4700::1111", "example.com", 134744072])
def test_tcp_rejects_non_public_literal_ipv4_before_socket(target, monkeypatch):
    monkeypatch.setattr(probing.socket, "socket", lambda *a: pytest.fail("must not connect"))
    with pytest.raises(ValueError):
        probing.tcp_probe(target, 443)


@pytest.mark.parametrize("overrides", [{"port": 0}, {"port": 65536}, {"port": True}, {"port": 22.0},
                                       {"samples": 0}, {"samples": 6}, {"samples": True},
                                       {"timeout_seconds": 0.9}, {"timeout_seconds": 11},
                                       {"timeout_seconds": float("nan")}, {"timeout_seconds": True}])
def test_limits_rejected(overrides):
    values = {"target_ip": "8.8.8.8", "port": 443}
    with pytest.raises(ValueError):
        probing.validate_probe_request(**(values | overrides))


def observation(region, reachable, **extra):
    return {"region_type": region, **result(reachable), **extra}


@pytest.mark.parametrize("observations,expected", [
    ([], "insufficient_evidence"),
    ([observation("local", False), observation("overseas", True)], "insufficient_evidence"),
    ([observation("mainland", False), observation("overseas", True)], "suspected_filtering"),
    ([observation("mainland", True), observation("overseas", True)], "reachable_from_both"),
    ([observation("mainland", False), observation("overseas", False)], "unreachable_from_both"),
    ([observation("mainland", True), observation("overseas", False)], "insufficient_evidence"),
    ([observation("mainland", False, error="HTTP 401"), observation("overseas", True)], "insufficient_evidence"),
    ([observation("mainland", False, status="error"), observation("overseas", True)], "insufficient_evidence"),
    ([observation("mainland", False), observation("mainland", True), observation("overseas", True)], "reachable_from_both"),
])
def test_conservative_classification(observations, expected):
    assert probing.classify_gfw(observations) == expected


def public_dns(host, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]


@pytest.mark.parametrize("url", ["http://probe.example/probe", "https://localhost/probe",
                                 "https://probe.example:0/probe",
                                 "https://user:password@probe.example/probe", "https://probe.example/#secret",
                                 "https://probe.example/probe?token=secret", "https://probe.example/\r\nx"])
def test_remote_rejects_unsafe_url(url, monkeypatch):
    monkeypatch.setattr(probing.socket, "getaddrinfo", public_dns)
    with pytest.raises(ValueError):
        probing._resolve_probe_url(url)


def test_remote_rejects_any_private_dns_record(monkeypatch):
    monkeypatch.setattr(probing.socket, "getaddrinfo", lambda *a, **k: public_dns(*a, **k) + [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443))])
    with pytest.raises(ValueError):
        probing._resolve_probe_url("https://probe.example/probe")


def test_public_url_validator_preserves_exact_configured_url(monkeypatch):
    monkeypatch.setattr(probing.socket, "getaddrinfo", public_dns)
    url = "https://probe.example:8443/probe"
    assert probing.validate_remote_url(url) == url


def test_dns_resolution_has_a_bounded_wait(monkeypatch):
    release = threading.Event()
    finished = threading.Event()
    def slow_dns(*args, **kwargs):
        try:
            release.wait(2)
            return public_dns(*args, **kwargs)
        finally:
            finished.set()
    monkeypatch.setattr(probing.socket, "getaddrinfo", slow_dns)
    monkeypatch.setattr(probing, "DNS_TIMEOUT_SECONDS", 0.01)
    try:
        with pytest.raises(ValueError, match="DNS"):
            probing._resolve_probe_url("https://probe.example/probe")
    finally:
        release.set()
        assert finished.wait(1)


def test_pinned_connection_uses_validated_ip_and_original_tls_hostname(monkeypatch):
    fake = FakeSocket()
    monkeypatch.setattr(probing.socket, "socket", lambda *a: fake)
    monkeypatch.setattr(probing.socket, "getaddrinfo", lambda *a, **k: pytest.fail("must not re-resolve"))
    seen = {}
    class Context:
        def wrap_socket(self, raw, server_hostname):
            seen["hostname"] = server_hostname
            return raw
    monkeypatch.setattr(probing.ssl, "create_default_context", lambda: Context())
    connection = probing._PinnedHTTPSConnection("probe.example", 443, [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("8.8.8.8", 443))], 5)
    connection.connect()
    assert fake.connected == ("8.8.8.8", 443)
    assert seen["hostname"] == "probe.example"
    connection.close()


class FakeResponse:
    def __init__(self, data=None, status=200, content_type="application/json"):
        self.body = json.dumps(result() if data is None else data).encode()
        self.status = status
        self.content_type = content_type

    def getheader(self, name, default=None):
        return self.content_type if name == "Content-Type" else default

    def read(self, size):
        return self.body[:size]


def fake_remote(monkeypatch, response):
    seen = {}
    class Connection:
        def __init__(self, host, port, addresses, timeout):
            seen.update(host=host, addresses=addresses, timeout=timeout)

        def request(self, method, path, body, headers):
            seen.update(method=method, path=path, payload=json.loads(body), headers=headers)

        def getresponse(self):
            return response

        def close(self):
            seen["closed"] = True

        def abort(self):
            seen["aborted"] = True
    monkeypatch.setattr(probing.socket, "getaddrinfo", public_dns)
    monkeypatch.setattr(probing, "_PinnedHTTPSConnection", Connection)
    return seen


def test_remote_validated_result_and_auth(monkeypatch):
    seen = fake_remote(monkeypatch, FakeResponse())
    actual = probing.remote_probe("https://probe.example/probe", "secret-token", {
        "target_ip": "1.1.1.1", "port": 443, "samples": 1})
    assert actual == result()
    assert seen["headers"]["Authorization"] == "Bearer secret-token"
    assert seen["payload"]["samples"] == 1
    assert seen["closed"]


@pytest.mark.parametrize("response", [FakeResponse(status=302), FakeResponse(status=401),
                                      FakeResponse(content_type="text/html"),
                                      FakeResponse(data=result() | {"success_count": 0}),
                                      FakeResponse(data=result() | {"latency_ms": float("nan")}),
                                      FakeResponse(data=result() | {"loss_percent": 50}),
                                      FakeResponse(data=result() | {"samples": 5})])
def test_remote_rejects_redirects_and_untrustworthy_results(monkeypatch, response):
    seen = fake_remote(monkeypatch, response)
    with pytest.raises(ValueError):
        probing.remote_probe("https://probe.example/probe", "secret-token", {
            "target_ip": "1.1.1.1", "port": 443, "samples": 1})
    assert seen["closed"]


def test_probe_agent_requires_token_on_startup(monkeypatch):
    from fastapi.testclient import TestClient
    from app.probe_agent import app
    monkeypatch.delenv("PROBE_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


@pytest.mark.parametrize("token", ["short", "a" * 23, "a" * 513, "a" * 24 + " ", "a" * 24 + "中"])
def test_probe_agent_rejects_weak_or_invalid_startup_token(monkeypatch, token):
    from fastapi.testclient import TestClient
    from app.probe_agent import app
    monkeypatch.setenv("PROBE_TOKEN", token)
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_probe_agent_auth_limits_and_capacity(monkeypatch):
    from fastapi.testclient import TestClient
    from app import probe_agent
    token = "test-token-" + "a" * 24
    monkeypatch.setenv("PROBE_TOKEN", token)
    monkeypatch.setattr(probe_agent, "tcp_probe", lambda **kwargs: result())
    headers = {"Authorization": "Bearer " + token}
    payload = {"target_ip": "8.8.8.8", "port": 443, "samples": 1}
    with TestClient(probe_agent.app) as client:
        assert client.get("/health").json() == {"ok": True}
        assert client.post("/probe", json=payload).status_code == 401
        assert client.post("/probe", json=payload, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/probe", json=payload, headers=headers).json() == result()
        assert client.post("/probe", json=payload | {"target_ip": "127.0.0.1"}, headers=headers).status_code == 422
        assert client.post("/probe", json=payload | {"samples": True}, headers=headers).status_code == 422
        assert client.post("/probe", json=payload | {"samples": 6}, headers=headers).status_code == 422
        assert client.post("/probe", json=payload | {"timeout_seconds": 11}, headers=headers).status_code == 422
        for _ in range(4):
            probe_agent._capacity.acquire()
        try:
            assert client.post("/probe", json=payload, headers=headers).status_code == 429
        finally:
            for _ in range(4):
                probe_agent._capacity.release()
