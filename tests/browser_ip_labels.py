"""Exercise IP provenance display against mocked APIs only; never contact AWS."""
import asyncio
import json
import os
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

BASE = Path(__file__).resolve().parents[1]

ACCOUNT = {"id": "acct1", "name": "QA account", "region": "us-east-1"}
STATE = {"accounts": [ACCOUNT], "scripts": [], "probes": [], "activity": [], "meta": {}, "monitors": [], "results": []}
INSTANCES = [
    {"id": "i-00000000000000001", "name": "Missing allocation", "public_ip": "203.0.113.1"},
    {"id": "i-00000000000000002", "name": "Null allocation", "public_ip": "203.0.113.2", "elastic_allocation_id": None},
    {"id": "i-00000000000000003", "name": "Known elastic IP", "public_ip": "203.0.113.3", "elastic_allocation_id": "eipalloc-00000000000000003"},
    {"id": "i-00000000000000004", "name": "No public address", "public_ip": None, "elastic_allocation_id": None},
]
STATE["monitors"] = [{
    "id": "monitor1", "name": "Preflight probe unavailable", "account_id": "acct1",
    "instance_id": INSTANCES[0]["id"], "port": 443, "enabled": True,
    "schedule_type": "cron", "cron_expression": "*/5 * * * *", "timezone": "Asia/Shanghai",
    "auto_rotate": True, "rotation_trigger": "suspected_filtering", "failure_threshold": 3,
    "rotation_status": "recovered", "rotation_message": "复检探针出错，证据不足，未更换 IP。",
    "last_status": "error",
}]
STATE["results"] = [{
    "id": "result1", "instance_id": INSTANCES[0]["id"], "monitor_name": "Preflight probe unavailable",
    "target_ip": INSTANCES[0]["public_ip"], "port": 443, "status": "error",
    "checked_at": "2026-01-01T00:00:00Z", "latency_ms": None, "loss_percent": None,
    "gfw_status": "insufficient_evidence", "rotation": {
        "status": "recovered", "message": "复检探针出错，证据不足，未更换 IP。",
    },
}]
for instance in INSTANCES:
    instance.update(state="running", instance_type="t4g.micro", private_ip="10.0.0.10", availability_zone="us-east-1a")
REQUESTS = []
ERRORS = []
UNEXPECTED = []
CHECKS = []


async def route_all(route):
    request = route.request
    url = urlparse(request.url)
    if url.hostname != "127.0.0.1":
        UNEXPECTED.append(request.url)
        await route.abort()
        return
    if not url.path.startswith("/api/"):
        await route.continue_()
        return
    path = url.path.removeprefix("/api")
    payload = request.post_data_json if request.post_data else None
    REQUESTS.append((request.method, path, payload))
    if request.method == "GET" and path == "/health":
        data = {"setup_required": False}
    elif request.method == "GET" and path == "/state":
        data = STATE
    elif request.method == "GET" and path == "/accounts/acct1/instances":
        data = {"instances": INSTANCES}
    elif request.method == "POST" and path in [f"/accounts/acct1/instances/{instance['id']}/rotate-ip" for instance in INSTANCES]:
        data = {"message": "QA mock rotation completed", "public_ip": "203.0.113.10"}
    else:
        UNEXPECTED.append((request.method, path, payload))
        await route.fulfill(status=500, json={"detail": "Unexpected QA API"})
        return
    await route.fulfill(json=data)


class StaticHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE / "static"), **kwargs)

    def log_message(self, *args):
        pass


async def main(server):
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 1000})
        # Keep periodic UI polling out of exact request counts; explicit refreshes
        # after a mutation still run and are asserted below.
        await page.add_init_script("window.setInterval = () => 0;")
        page.on("pageerror", lambda error: ERRORS.append(str(error)))
        await page.route("**/*", route_all)
        await page.goto(f"http://127.0.0.1:{server.server_port}/")
        await page.get_by_role("heading", name="运行概览", exact=True).wait_for()
        await page.locator('[data-action="navigate"][data-page="instances"]').first.click()
        await page.get_by_role("heading", name="EC2 实例", exact=True).wait_for()
        rows = page.locator("#main-content tbody tr")
        assert await rows.count() == 4
        expected_labels = ["公网 IPv4（类型未识别）", "公网 IPv4（类型未识别）", "弹性 IP", "无公网 IPv4"]
        for index, label in enumerate(expected_labels):
            assert await rows.nth(index).locator("td").nth(2).locator(".cell-sub").inner_text() == label
        assert "自动分配 IP" not in await page.locator("#main-content").inner_text()
        CHECKS.append("missing/null/known Allocation ID and no public IPv4 labels")
        initial_requests = list(REQUESTS)
        assert initial_requests == [("GET", "/health", None), ("GET", "/state", None), ("GET", "/accounts/acct1/instances", None)]

        async def close():
            await page.locator('#modal [data-action="close-modal"]').first.click()

        async def open_rotate(index):
            instance = INSTANCES[index]
            await page.locator(f'[data-action="instance-menu"][data-id="{instance["id"]}"]').click()
            await page.get_by_role("heading", name=instance["name"], exact=True).wait_for()
            assert instance["id"] in await page.locator("#modal").inner_text()
            await page.locator('#modal [data-action="rotate-ip"]').click()
            await page.get_by_role("heading", name="更换公网 IPv4", exact=True).wait_for()

        for index in range(4):
            await open_rotate(index)
            allocation_value = await page.locator('#modal .details-grid > div').filter(has=page.locator("small", has_text="旧弹性 IP Allocation ID")).locator("span").inner_text()
            assert allocation_value == (INSTANCES[index].get("elastic_allocation_id") or "未查询（执行时由后端核实）")
            assert "无 / 未检测到" not in await page.locator("#modal").inner_text()
            assert not await page.locator('#modal [name="release_previous"]').is_checked()
            await close()
        assert REQUESTS == initial_requests, REQUESTS
        CHECKS.extend(["instance detail/menu and rotate dialog distinguish unknown from known allocation", "opening list and dialogs makes no extra API calls", "old EIP release is unchecked for every fixture"])

        # Missing/stale list knowledge must not make a release decision or supply an Allocation ID.
        for index, release in [(0, False), (1, True), (2, False), (2, True)]:
            before = len(REQUESTS)
            await open_rotate(index)
            if release:
                await page.locator('#modal [name="release_previous"]').check()
            await page.locator('#modal [name="cost_ack"]').check()
            await page.locator('#modal button[type="submit"]').click()
            await page.wait_for_function('!document.querySelector("#modal").open')
            for _ in range(500):
                if len(REQUESTS) >= before + 3:
                    break
                await asyncio.sleep(0.01)
            await page.wait_for_function('!document.querySelector("#refresh-icon").classList.contains("rotating")')
            expected = [("POST", f"/accounts/acct1/instances/{INSTANCES[index]['id']}/rotate-ip", {"release_previous": release}), ("GET", "/state", None), ("GET", "/accounts/acct1/instances", None)]
            assert REQUESTS[before:] == expected, REQUESTS[before:]
        CHECKS.append("rotation sends only user-selected release_previous boolean; backend resolves allocation independently")

        await page.set_viewport_size({"width": 390, "height": 844})
        await open_rotate(0)
        assert "未查询（执行时由后端核实）" in await page.locator("#modal").inner_text()
        assert await page.locator("#modal").evaluate("element => element.scrollWidth <= element.clientWidth")
        if os.environ.get("QA_SCREENSHOT_DIR"):
            screenshot_dir = Path(os.environ["QA_SCREENSHOT_DIR"])
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            await page.locator("#modal").screenshot(path=str(screenshot_dir / "ip-display-mobile.png"))
        await close()
        CHECKS.append("mobile list menu and unknown allocation dialog without horizontal overflow")

        await page.set_viewport_size({"width": 1440, "height": 1000})
        await page.locator('[data-action="navigate"][data-page="monitors"]').click()
        await page.get_by_role("heading", name="网络监测", exact=True).wait_for()
        assert "复检未触发换 IP" in await page.locator("#main-content").inner_text()
        assert "连接已恢复" not in await page.locator("#main-content").inner_text()
        assert "复检探针出错，证据不足，未更换 IP。" in await page.locator("#main-content").inner_text()
        await page.locator('[data-action="monitor-tab"][data-tab="history"]').click()
        assert "复检未触发换 IP" in await page.locator("#main-content").inner_text()
        assert "连接已恢复" not in await page.locator("#main-content").inner_text()
        await page.locator('[data-action="result-details"]').click()
        assert "复检未触发换 IP" in await page.locator("#modal").inner_text()
        assert "连接已恢复" not in await page.locator("#modal").inner_text()
        await close()
        CHECKS.append("preflight error is not presented as confirmed recovery in task, history or details")

        # The built-in demo follows the same display rules without issuing any API request.
        before_demo = len(REQUESTS)
        await page.goto(f"http://127.0.0.1:{server.server_port}/?demo=1#instances")
        await page.get_by_role("heading", name="EC2 实例", exact=True).wait_for()
        demo_labels = await page.locator("#main-content tbody tr td:nth-child(3) .cell-sub").all_text_contents()
        assert demo_labels == ["弹性 IP", "公网 IPv4（类型未识别）", "公网 IPv4（类型未识别）", "无公网 IPv4"], demo_labels
        assert len(REQUESTS) == before_demo
        CHECKS.append("demo matches provenance labels and remains API-free")
        assert not ERRORS, ERRORS
        assert not UNEXPECTED, UNEXPECTED
        await browser.close()
    print(json.dumps({"passed": True, "checks": CHECKS, "mock_only": True, "api_requests": len(REQUESTS)}, ensure_ascii=False))


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 0), StaticHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        asyncio.run(main(server))
    finally:
        server.shutdown()
