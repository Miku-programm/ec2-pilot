"""Refresh queueing, IME-safe search and non-disruptive polling, using mocked APIs only."""
import asyncio
import copy
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright

BASE = Path(__file__).resolve().parents[1]
ACCOUNT = {"id": "acct1", "name": "Mock account", "region": "us-east-1", "aws_account_id": "123456789012"}
INSTANCES = [
    {"id": "i-00000000000000001", "name": "测试 web", "state": "running", "instance_type": "t4g.micro",
     "public_ip": "203.0.113.1", "private_ip": "10.0.0.1", "availability_zone": "us-east-1a"},
    {"id": "i-00000000000000002", "name": "database", "state": "stopped", "instance_type": "t3.micro",
     "public_ip": None, "private_ip": "10.0.0.2", "availability_zone": "us-east-1a"},
]
STATE = {"accounts": [ACCOUNT], "scripts": [{"id": "s1", "name": "Script one", "content": "", "created_at": "2026-10-20T00:00:00Z"}],
         "probes": [], "activity": [], "meta": {}, "monitors": [], "results": [], "eip_cleanup": []}
STATE_GATE = None
REQUESTS, ERRORS, UNEXPECTED, CHECKS = [], [], [], []


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
    REQUESTS.append((request.method, path))
    if path == "/health":
        data = {"setup_required": False}
    elif path == "/state":
        data = copy.deepcopy(STATE)  # snapshot when the request was made
        if STATE_GATE:
            await STATE_GATE.wait()
    elif path == "/accounts/acct1/instances":
        data = {"instances": INSTANCES}
    else:
        UNEXPECTED.append((request.method, path))
        await route.fulfill(status=500, json={"detail": "Unexpected mock API"})
        return
    await route.fulfill(json=data)


class StaticHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE / "static"), **kwargs)

    def log_message(self, *args):
        pass


def state_requests():
    return sum(1 for item in REQUESTS if item == ("GET", "/state"))


async def wait_for(page, predicate, timeout=5):
    deadline = asyncio.get_running_loop().time() + timeout
    while not await predicate():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached"
        await page.wait_for_timeout(50)


async def main(server):
    global STATE_GATE
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 1000})
        # Capture the 30 s poll callback so the test can fire it on demand.
        await page.add_init_script("window.setInterval = fn => { window.__poll = fn; return 1; };")
        page.on("pageerror", lambda error: ERRORS.append(str(error)))
        await page.route("**/*", route_all)
        await page.goto(f"http://127.0.0.1:{server.server_port}/#scripts")
        await page.get_by_text("Script one").wait_for()

        # 1. A refresh requested while the poll is in flight is queued, not dropped,
        #    and the poll's older response does not overwrite it.
        STATE_GATE = asyncio.Event()
        before = state_requests()
        await page.evaluate("window.__poll()")
        await wait_for(page, lambda: asyncio.sleep(0, state_requests() == before + 1))
        STATE["scripts"].append({"id": "s2", "name": "Script two", "content": "", "created_at": "2026-10-21T00:00:00Z"})
        await page.locator("#refresh-icon").click(force=True)
        await page.wait_for_timeout(200)
        assert state_requests() == before + 1, "second refresh must wait for the in-flight one"
        STATE_GATE.set()
        await page.get_by_text("Script two").wait_for(timeout=5000)
        assert state_requests() == before + 2
        STATE_GATE = None
        CHECKS.append("refresh during an in-flight poll is queued and renders the newer data")

        # 2. Search updates only the result list and survives IME composition.
        await page.goto(f"http://127.0.0.1:{server.server_port}/#instances")
        await page.get_by_text("database").wait_for()
        search = page.locator("#instance-search")
        await search.click()
        await page.evaluate("window.__search = document.querySelector('#instance-search')")
        await page.evaluate("""() => {
            const input = document.querySelector('#instance-search');
            input.dispatchEvent(new CompositionEvent('compositionstart', {bubbles: true}));
            input.value = 'ce';
            input.dispatchEvent(new InputEvent('input', {bubbles: true, isComposing: true, data: 'ce'}));
        }""")
        await page.wait_for_timeout(300)
        assert await page.evaluate("document.querySelector('#instance-search') === window.__search")
        assert await page.get_by_text("database").count() == 1, "no filtering while composing"
        await page.evaluate("""() => {
            const input = document.querySelector('#instance-search');
            input.value = '测试';
            input.dispatchEvent(new CompositionEvent('compositionend', {bubbles: true, data: '测试'}));
        }""")
        await wait_for(page, lambda: _count_is(page, "database", 0))
        assert await page.get_by_text("测试 web").count() == 1
        assert await page.evaluate("document.activeElement === window.__search")
        CHECKS.append("IME composition is not interrupted and the committed text filters results")

        await search.fill("")
        await search.press_sequentially("data", delay=20)
        await wait_for(page, lambda: _count_is(page, "测试 web", 0))
        assert await page.evaluate("document.activeElement === window.__search && window.__search.value === 'data'")
        await search.fill("null")
        await wait_for(page, lambda: _count_is(page, "database", 0))
        assert "0 台实例" in await page.locator("#instance-count").inner_text(), "missing IP must not match 'null'"
        await search.fill("")
        await page.locator("#account-filter").select_option("acct1")
        await page.get_by_text("database").wait_for()
        CHECKS.append("typing and account filter keep the search box; missing IP does not match 'null'")

        # 3. Polls skip unchanged data and wait while the user selects text.
        await page.evaluate("document.querySelector('#instance-results').dataset.marker = 'kept'")
        await page.evaluate("window.__poll()")
        await page.wait_for_timeout(400)
        assert await page.evaluate("document.querySelector('#instance-results')?.dataset.marker === 'kept'"), "unchanged poll must not re-render"
        await page.evaluate("""() => {
            const cell = [...document.querySelectorAll('#instance-results td')].find(td => td.textContent.includes('database'));
            getSelection().selectAllChildren(cell);
        }""")
        STATE["scripts"].append({"id": "s3", "name": "Script three", "content": "", "created_at": "2026-10-22T00:00:00Z"})
        before = state_requests()
        await page.evaluate("window.__poll()")
        await wait_for(page, lambda: asyncio.sleep(0, state_requests() == before + 1))
        await page.wait_for_timeout(1500)
        assert await page.evaluate("document.querySelector('#instance-results')?.dataset.marker === 'kept'"), "selection must defer the render"
        assert not await page.evaluate("getSelection().isCollapsed")
        await page.evaluate("getSelection().removeAllRanges()")
        await wait_for(page, lambda: page.evaluate("document.querySelector('#instance-results')?.dataset.marker !== 'kept'"))
        CHECKS.append("unchanged polls do not re-render; changed polls wait for the text selection to end")

        assert not ERRORS, ERRORS
        assert not UNEXPECTED, UNEXPECTED
        await browser.close()


async def _count_is(page, text, expected):
    return await page.get_by_text(text).count() == expected


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 0), StaticHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        asyncio.run(main(server))
    finally:
        server.shutdown()
    print(json.dumps({"passed": True, "checks": CHECKS, "mock_only": True, "api_requests": len(REQUESTS)}, ensure_ascii=False))
