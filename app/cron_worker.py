"""One due-task batch for Linux crontab. Shares durable leases with the web app."""
import argparse
import asyncio
import json
from .main import create_app


async def run():
    app = create_app(start_scheduler=False)
    async with app.router.lifespan_context(app):
        results = await app.state.run_due_monitors()
        cleaned = await asyncio.to_thread(app.state.run_eip_cleanup)
        print(json.dumps({"checked": len(results), "rotated": sum(r.get("rotation", {}).get("status") == "rotated" for r in results), "needs_review": sum(r.get("rotation", {}).get("status") == "awaiting_review" for r in results), "eip_cleanup_processed": cleaned}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="执行到期的 cron 检测任务，然后退出。复用面板数据目录及加密密钥。")
    parser.add_argument("--once", action="store_true", help="单次执行（默认行为）")
    parser.parse_args()
    asyncio.run(run())
