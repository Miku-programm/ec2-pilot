"""Exercise old-EIP queue UX using mocked APIs only; never contact AWS."""
import asyncio
import copy
import json
import os
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

BASE = Path(__file__).resolve().parents[1]
ACCOUNT = {
    "id": "acct1", "name": '<img src=x onerror="window.injected=true">',
    "region": "us-east-1", "aws_account_id": "123456789012",
}
INSTANCE = {
    "id": "i-00000000000000001", "name": "Mock instance", "state": "running",
    "instance_type": "t4g.micro", "public_ip": "203.0.113.1",
    "private_ip": "10.0.0.1", "availability_zone": "us-east-1a",
}


def entry(number, state, **overrides):
    return {
        "allocation_id": f"eipalloc-{number:017x}", "association_id": f"eipassoc-{number:017x}",
        "public_ip": f"203.0.113.{number}", "account_id": "acct1",
        "aws_account_id": "123456789012", "region": "us-east-1", "instance_id": INSTANCE["id"],
        "attempt_id": f"attempt-{number}", "state": state, "processing": False,
        "attempts": 2, "next_try_at": "2026-10-15T10:00:00Z", "last_error": None,
        **overrides,
    }


ROWS = [
    entry(1, "blocked"), entry(2, "queued"), entry(3, "review"),
    entry(4, "failed", attempts=10), entry(5, "blocked", processing=True),
    entry(6, "queued", processing=True),
    entry(7, "queued", region="ap-southeast-2", last_error='<script>window.injected=true</script>'),
]
STATE = {
    "accounts": [ACCOUNT], "scripts": [], "probes": [], "activity": [], "meta": {},
    "monitors": [], "results": [], "eip_cleanup": copy.deepcopy(ROWS),
}
REQUESTS, ERRORS, UNEXPECTED, CHECKS = [], [], [], []
ACTION_GATE = None
CONFLICT_ID = None


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
        data = {"instances": [INSTANCE]}
    elif path.startswith("/eip-cleanup/"):
        allocation_id = path.split("/")[2]
        row = next((item for item in STATE["eip_cleanup"] if item["allocation_id"] == allocation_id), None)
        if ACTION_GATE:
            await ACTION_GATE.wait()
        if row and allocation_id == CONFLICT_ID:
            row["processing"] = True
            await route.fulfill(status=409, json={"detail": "后台或换 IP 操作正在处理这个 EIP，请稍后再试"})
            return
        if row and request.method == "DELETE" and path == f"/eip-cleanup/{allocation_id}":
            STATE["eip_cleanup"].remove(row)
            data = {"ok": True}
        elif row and request.method == "POST" and path == f"/eip-cleanup/{allocation_id}/approve":
            row.update(state="queued", attempts=0, last_error=None)
            data = {"ok": True}
        else:
            UNEXPECTED.append((request.method, path, payload))
            await route.fulfill(status=500, json={"detail": "Unexpected mock cleanup action"})
            return
    else:
        UNEXPECTED.append((request.method, path, payload))
        await route.fulfill(status=500, json={"detail": "Unexpected mock API"})
        return
    await route.fulfill(json=data)


class StaticHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE / "static"), **kwargs)

    def log_message(self, *args):
        pass


async def main(server):
    global ACTION_GATE, CONFLICT_ID
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 1100})
        await page.add_init_script("window.setInterval = () => 0;")
        page.on("pageerror", lambda error: ERRORS.append(str(error)))
        await page.route("**/*", route_all)
        await page.goto(f"http://127.0.0.1:{server.server_port}/#monitors")
        await page.get_by_role("heading", name="网络监测", exact=True).wait_for()
        notice = page.locator("#eip-cleanup-notice")
        assert await notice.locator("[data-cleanup-id]").count() == 7

        def row(number):
            return page.locator(f'[data-cleanup-id="eipalloc-{number:017x}"]')

        for number, expected in [(1, "换 IP 结果待核对"), (2, "等待释放"),
                                 (3, "自动释放已停止"), (4, "多次释放未成功"),
                                 (5, "换 IP 正在执行"), (6, "后台正在核查并处理释放")]:
            assert expected in await row(number).inner_text()
            assert ACCOUNT["name"] in await row(number).inner_text()
            assert ACCOUNT["aws_account_id"] in await row(number).inner_text()
            assert INSTANCE["id"] in await row(number).inner_text()
        assert "ap-southeast-2" in await row(7).inner_text()
        assert "us-east-1" not in await row(7).inner_text()
        assert "重试计数 2 / 10" in await row(2).inner_text()
        assert "下次检查" in await row(2).inner_text()
        CHECKS.append("queued, blocked, review, failed and live processing states include exact account/region/instance")

        for number in (1, 4):
            assert await row(number).locator('[data-action="approve-eip-cleanup"]').count() == 1
        for number in (2, 3, 5, 6):
            assert await row(number).locator('[data-action="approve-eip-cleanup"]').count() == 0
        for number in (5, 6):
            assert await row(number).locator('[data-action="keep-eip"]').is_disabled()
            assert "结果待核对" not in await row(number).inner_text()
        assert await notice.locator("img,script").count() == 0
        assert await page.evaluate("window.injected === undefined")
        assert '<script>window.injected=true</script>' in await row(7).inner_text()
        CHECKS.extend(["active work cannot be approved or dismissed; review has no automatic retry action", "untrusted account names and backend errors are escaped"])

        # New automatic monitors continue to require explicit old-address release opt-in.
        await page.locator('[data-action="add-monitor"]').first.click()
        await page.locator('#modal [name="auto_rotate"]').check()
        assert not await page.locator('#modal [name="release_previous"]').is_checked()
        await page.locator('#modal [data-action="close-modal"]').first.click()
        CHECKS.append("new automatic monitor preserves release_previous=false")

        # Hold the response to test duplicate-click protection across re-rendering.
        ACTION_GATE = asyncio.Event()
        before = len(REQUESTS)
        await row(1).locator('[data-action="approve-eip-cleanup"]').click()
        await page.wait_for_function('document.querySelector("[data-cleanup-id=\\"eipalloc-00000000000000001\\"] [data-action=approve-eip-cleanup]").disabled')
        await row(1).locator('[data-action="approve-eip-cleanup"]').dispatch_event("click")
        ACTION_GATE.set()
        await row(1).get_by_text("等待释放", exact=False).wait_for()
        await row(1).locator('[data-action="keep-eip"]').wait_for(state="visible")
        for _ in range(100):
            if not await row(1).locator('[data-action="keep-eip"]').is_disabled():
                break
            await asyncio.sleep(0.01)
        ACTION_GATE = None
        mutations = [item for item in REQUESTS[before:] if item[0] != "GET"]
        assert mutations == [("POST", "/eip-cleanup/eipalloc-00000000000000001/approve", {})], mutations
        assert "已重新排队" in await page.locator("#toast-stack").inner_text()
        CHECKS.append("approve queues the exact address once and refreshes without loading EC2 again")
        assert all(path != "/accounts/acct1/instances" for _, path, _ in REQUESTS[before:])

        await row(3).locator('[data-action="keep-eip"]').click()
        await row(3).wait_for(state="detached")
        assert ("DELETE", "/eip-cleanup/eipalloc-00000000000000003", None) in REQUESTS
        assert "面板将保留此 EIP" in await page.locator("#toast-stack").inner_text()
        CHECKS.append("keep removes queue entry and explicitly preserves the AWS address")

        # A stale browser row can lose a race to a worker: retain it and show 409.
        CONFLICT_ID = "eipalloc-00000000000000002"
        await row(2).locator('[data-action="keep-eip"]').click()
        await row(2).get_by_text("后台正在核查并处理释放", exact=False).wait_for()
        assert await row(2).locator('[data-action="keep-eip"]').is_disabled()
        assert "请稍后再试" in await page.locator("#toast-stack").inner_text()
        assert await row(2).count() == 1
        CONFLICT_ID = None
        CHECKS.append("409 is visible and refreshes the active row without claiming a successful cancellation")

        # Failed cleanup can be requeued, unlike review rows that may belong elsewhere.
        await row(4).locator('[data-action="approve-eip-cleanup"]').click()
        await row(4).get_by_text("重试计数 0 / 10", exact=False).wait_for()
        assert ("POST", "/eip-cleanup/eipalloc-00000000000000004/approve", {}) in REQUESTS
        CHECKS.append("verified failed cleanup can restart its cleanup retry counter")

        await page.set_viewport_size({"width": 390, "height": 844})
        assert await notice.evaluate("node => node.scrollWidth <= node.clientWidth"), await notice.bounding_box()
        box = await notice.bounding_box()
        assert box["x"] >= 0 and box["x"] + box["width"] <= 391, box
        assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        if os.environ.get("QA_SCREENSHOT_DIR"):
            directory = Path(os.environ["QA_SCREENSHOT_DIR"])
            directory.mkdir(parents=True, exist_ok=True)
            await notice.screenshot(path=str(directory / "eip-cleanup-mobile.png"))
        CHECKS.append("390px mobile queue has no horizontal overflow")

        STATE["eip_cleanup"] = []
        await page.locator('[data-action="refresh"]').first.click()
        await notice.wait_for(state="detached")
        CHECKS.append("completed empty queue no longer shows a pending-address warning")
        before_demo = len(REQUESTS)
        await page.goto(f"http://127.0.0.1:{server.server_port}/?demo=1#monitors")
        await page.get_by_role("heading", name="网络监测", exact=True).wait_for()
        assert len(REQUESTS) == before_demo
        assert await page.locator("#eip-cleanup-notice").count() == 0
        CHECKS.append("read-only demo has no cleanup mutations or backend requests")
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
