"""Real TCP measurements and conservative comparisons between probe locations."""

from __future__ import annotations

import errno
import http.client
import ipaddress
import json
import math
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit


MAX_RESPONSE_BYTES = 32_768
DNS_TIMEOUT_SECONDS = 5
_dns_capacity = threading.BoundedSemaphore(4)


def _public_address(value: str, *, ipv4_only: bool = False):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValueError("必须提供有效的公网 IP 地址") from exc
    if (
        (ipv4_only and address.version != 4)
        or not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("只允许探测公网 IPv4 地址" if ipv4_only else "探针地址必须是公网地址")
    return address


def validate_probe_request(target_ip, port, timeout_seconds=3, samples=3):
    """Validate inputs before making any network request; never resolve targets."""
    if not isinstance(target_ip, str):
        raise ValueError("目标必须是公网 IPv4 地址")
    target_ip = str(_public_address(target_ip, ipv4_only=True))
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("端口必须为 1–65535 的整数")
    if (
        type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or not 1 <= timeout_seconds <= 10
    ):
        raise ValueError("超时必须在 1–10 秒之间")
    if type(samples) is not int or not 1 <= samples <= 5:
        raise ValueError("采样次数必须为 1–5 的整数")
    return {
        "target_ip": target_ip,
        "port": port,
        "timeout_seconds": timeout_seconds,
        "samples": samples,
    }


def _error_name(exc: OSError) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    return {
        errno.ECONNREFUSED: "connection_refused",
        errno.ENETUNREACH: "network_unreachable",
        errno.EHOSTUNREACH: "host_unreachable",
        errno.EACCES: "permission_denied",
        errno.EPERM: "permission_denied",
        errno.ECONNRESET: "connection_reset",
    }.get(exc.errno, "connection_error")


def tcp_probe(target_ip, port, timeout_seconds=3, samples=3) -> dict:
    """Measure TCP connect time, not ICMP latency or application response time."""
    values = validate_probe_request(target_ip, port, timeout_seconds, samples)
    attempts = []
    for _ in range(values["samples"]):
        attempt = {"ok": False, "latency_ms": 0.0}
        # Local socket setup failures are probe errors, not evidence that the
        # destination is unreachable. Time only the connect operation.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(values["timeout_seconds"])
            started = time.perf_counter()
            try:
                connection.connect((values["target_ip"], values["port"]))
                attempt["ok"] = True
            except OSError as exc:
                attempt["error"] = _error_name(exc)
            attempt["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        attempts.append(attempt)
    successful = [attempt["latency_ms"] for attempt in attempts if attempt["ok"]]
    return {
        "success_count": len(successful),
        "samples": values["samples"],
        "latency_ms": round(sum(successful) / len(successful), 3) if successful else None,
        "loss_percent": round(100 * (1 - len(successful) / values["samples"]), 2),
        "attempts": attempts,
    }


def classify_gfw(observations: list) -> str:
    """A failed control-plane call is missing evidence, never a failed TCP probe."""
    if not isinstance(observations, list):
        return "insufficient_evidence"
    locations = {"mainland": [], "overseas": []}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        region = observation.get("region_type")
        if region not in locations or observation.get("error"):
            continue
        if observation.get("status") in ("error", "no_public_ip"):
            continue
        count, samples = observation.get("success_count"), observation.get("samples")
        if type(count) is not int or type(samples) is not int or not 1 <= samples <= 5:
            continue
        if not 0 <= count <= samples:
            continue
        locations[region].append(count > 0)
    mainland, overseas = locations["mainland"], locations["overseas"]
    if not mainland or not overseas:
        return "insufficient_evidence"
    if any(mainland) and any(overseas):
        return "reachable_from_both"
    if not any(mainland) and any(overseas):
        return "suspected_filtering"
    if not any(mainland) and not any(overseas):
        return "unreachable_from_both"
    return "insufficient_evidence"


def _lookup_probe_addresses(hostname, port):
    # OS DNS calls have no portable timeout. Bound callers and the number of
    # outstanding daemon resolver threads, including on resolver failure.
    if not _dns_capacity.acquire(blocking=False):
        raise ValueError("探针 DNS 查询繁忙，请稍后重试")
    complete = threading.Event()
    outcome = {}

    def resolve():
        try:
            outcome["addresses"] = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError:
            outcome["failed"] = True
        finally:
            _dns_capacity.release()
            complete.set()

    worker = threading.Thread(target=resolve, name="probe-dns", daemon=True)
    try:
        worker.start()
    except RuntimeError as exc:
        _dns_capacity.release()
        raise ValueError("无法启动探针 DNS 查询") from exc
    if not complete.wait(DNS_TIMEOUT_SECONDS):
        raise ValueError("探针 DNS 查询超时")
    if outcome.get("failed") or "addresses" not in outcome:
        raise ValueError("无法解析探针主机名")
    return outcome["addresses"]


def _resolve_probe_url(url: str):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError("探针 URL 无效")
    try:
        parsed = urlsplit(url)
        port = 443 if parsed.port is None else parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError("探针 URL 无效") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or not 1 <= port <= 65535
    ):
        raise ValueError("探针 URL 必须是无用户名、查询参数或片段的 HTTPS 地址")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("探针主机名无效") from exc
    if hostname == "localhost" or hostname.endswith(".localhost") or "%" in hostname:
        raise ValueError("探针地址必须是公网地址")
    addresses = _lookup_probe_addresses(hostname, port)
    if not addresses:
        raise ValueError("探针主机名没有可用地址")
    resolved = []
    for family, kind, protocol, _, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("探针地址类型不受支持")
        _public_address(sockaddr[0])
        entry = (family, kind, protocol, sockaddr)
        if entry not in resolved:
            resolved.append(entry)
    return hostname, port, parsed.path or "/probe", resolved


def validate_remote_url(url: str) -> str:
    """Validate configured URLs with the same bounded DNS policy used at runtime."""
    _resolve_probe_url(url)
    return url


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Use validated numeric addresses while preserving TLS SNI/cert validation."""

    def __init__(self, hostname, port, addresses, timeout):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self.addresses = addresses
        self.connected_socket = None

    def connect(self):
        deadline = time.monotonic() + self.timeout
        last_error = None
        for family, kind, protocol, sockaddr in self.addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("探针连接超时")
            raw = socket.socket(family, kind, protocol)
            self.connected_socket = raw
            try:
                raw.settimeout(remaining)
                raw.connect(sockaddr)  # Literal sockaddr: no second DNS resolution.
                raw.settimeout(max(0.1, deadline - time.monotonic()))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                self.connected_socket = self.sock
                return
            except OSError as exc:
                raw.close()
                last_error = exc
        raise last_error or OSError("无法连接探针")

    def abort(self):
        connection = self.connected_socket or self.sock
        if connection is not None:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.close()


def _finite_latency(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 120_000


def _validate_result(data, expected_samples: int) -> dict:
    if not isinstance(data, dict):
        raise ValueError("探针响应不是有效对象")
    count, samples = data.get("success_count"), data.get("samples")
    attempts = data.get("attempts")
    if (
        type(count) is not int
        or type(samples) is not int
        or samples != expected_samples
        or not 0 <= count <= samples
        or not isinstance(attempts, list)
        or len(attempts) != samples
    ):
        raise ValueError("探针响应采样数据无效")
    cleaned = []
    for attempt in attempts:
        if not isinstance(attempt, dict) or type(attempt.get("ok")) is not bool:
            raise ValueError("探针响应采样格式无效")
        if not _finite_latency(attempt.get("latency_ms")):
            raise ValueError("探针响应延迟无效")
        item = {"ok": attempt["ok"], "latency_ms": attempt["latency_ms"]}
        if "error" in attempt:
            error = attempt["error"]
            if not isinstance(error, str) or len(error) > 200 or attempt["ok"]:
                raise ValueError("探针响应错误字段无效")
            item["error"] = error
        cleaned.append(item)
    if sum(item["ok"] for item in cleaned) != count:
        raise ValueError("探针响应成功次数不一致")
    latency, loss = data.get("latency_ms"), data.get("loss_percent")
    if (count and not _finite_latency(latency)) or (not count and latency is not None):
        raise ValueError("探针响应平均延迟无效")
    expected_loss = round(100 * (1 - count / samples), 2)
    if type(loss) not in (int, float) or not math.isfinite(loss) or abs(loss - expected_loss) > 0.02:
        raise ValueError("探针响应丢包率不一致")
    if count:
        expected_latency = sum(a["latency_ms"] for a in cleaned if a["ok"]) / count
        if abs(latency - expected_latency) > 0.02:
            raise ValueError("探针响应平均延迟不一致")
    return {"success_count": count, "samples": samples, "latency_ms": latency,
            "loss_percent": loss, "attempts": cleaned}


def remote_probe(url: str, token: str, payload: dict) -> dict:
    """Call a configured HTTPS probe without redirects or DNS rebinding."""
    if not isinstance(payload, dict):
        raise ValueError("探测参数无效")
    values = validate_probe_request(
        payload.get("target_ip"), payload.get("port"),
        payload.get("timeout_seconds", 3), payload.get("samples", 3),
    )
    if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("探针令牌无效")
    hostname, port, path, addresses = _resolve_probe_url(url)
    timeout = min(60, values["timeout_seconds"] * values["samples"] + 5)
    connection = _PinnedHTTPSConnection(hostname, port, addresses, timeout)
    # Interrupt slow/dribbling responses as well as normal socket inactivity.
    expired = threading.Event()
    def expire():
        expired.set()
        connection.abort()
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        connection.request("POST", path, body=json.dumps(values).encode("utf-8"), headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        })
        response = connection.getresponse()
        if 300 <= response.status <= 399:
            raise ValueError("探针不允许 HTTP 重定向")
        if response.status != 200:
            raise ValueError(f"探针返回 HTTP {response.status}")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("探针必须返回 JSON")
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("探针响应过大")
        if expired.is_set():
            raise TimeoutError("探针请求超时")
        try:
            data = json.loads(content)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("探针响应 JSON 无效") from exc
        return _validate_result(data, values["samples"])
    except (OSError, http.client.HTTPException) as exc:
        # Never reflect authorization headers, response bodies, or token values.
        if expired.is_set() or isinstance(exc, TimeoutError):
            raise ValueError("探针请求超时") from exc
        raise ValueError("无法完成探针 HTTPS 请求") from exc
    finally:
        timer.cancel()
        connection.close()
