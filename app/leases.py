"""Renew durable ownership while a worker waits on probes or AWS."""
from contextlib import contextmanager
import threading


@contextmanager
def keep_lease(renew, interval=30):
    stopped, alive = threading.Event(), threading.Event()
    alive.set()

    def heartbeat():
        while not stopped.wait(interval):
            try:
                owned = renew()
            except Exception:
                owned = False
            if not owned:
                alive.clear()
                return

    worker = threading.Thread(target=heartbeat, name="panel-lease-renewal", daemon=True)
    worker.start()
    try:
        yield alive
    finally:
        stopped.set()
        worker.join(timeout=12)
