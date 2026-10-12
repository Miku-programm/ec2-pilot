"""Small SQLite store. Credentials are encrypted at rest; keys never enter JSON responses."""
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet
from .scheduling import next_run


def now():
    return datetime.now(timezone.utc).isoformat()


def uid():
    return uuid.uuid4().hex


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "panel.sqlite3"
        key_path = self.directory / "vault.key"
        key = os.environ.get("PANEL_ENCRYPTION_KEY")
        if key:
            self.cipher = Fernet(key.encode())
        else:
            if not key_path.exists():
                fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as out:
                    out.write(Fernet.generate_key())
            self.cipher = Fernet(key_path.read_bytes())
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, data TEXT NOT NULL, secret TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS scripts (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS probes (id TEXT PRIMARY KEY, data TEXT NOT NULL, secret TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS monitors (id TEXT PRIMARY KEY, data TEXT NOT NULL, next_due REAL NOT NULL, lease_until REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS results (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS result_time ON results(created_at);
                CREATE TABLE IF NOT EXISTS rotation_guards (resource_key TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS rotation_attempts (id TEXT PRIMARY KEY, resource_key TEXT NOT NULL, monitor_id TEXT NOT NULL, created_at REAL NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS rotation_resource_time ON rotation_attempts(resource_key,created_at);
                CREATE TABLE IF NOT EXISTS resource_leases (resource_key TEXT PRIMARY KEY, token TEXT NOT NULL, expires REAL NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            if "lease_token" not in {row[1] for row in db.execute("PRAGMA table_info(monitors)")}:
                db.execute("ALTER TABLE monitors ADD COLUMN lease_token TEXT NOT NULL DEFAULT ''")
            # Remove retired limits from saved policies, including tasks that
            # were previously waiting on a limit. Preserve schedules and history.
            for row in db.execute("SELECT id,data FROM monitors").fetchall():
                monitor = json.loads(row["data"])
                retired = any(key in monitor for key in ("cooldown_seconds", "max_rotations_per_day"))
                monitor.pop("cooldown_seconds", None)
                monitor.pop("max_rotations_per_day", None)
                if monitor.get("rotation_status") in {"cooldown", "daily_limit"}:
                    monitor.update(rotation_status="skipped", rotation_message="规则已更新，等待下一次定时检测")
                    retired = True
                if retired:
                    monitor["config_revision"] = uid()
                    db.execute("UPDATE monitors SET data=? WHERE id=?", (json.dumps(monitor, ensure_ascii=False), row["id"]))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
            with db:
                yield db
        finally:
            db.close()

    def encrypt(self, value):
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def decrypt(self, value):
        return json.loads(self.cipher.decrypt(value.encode()))

    def get_setting(self, key):
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))

    def list(self, table, limit=None):
        assert table in {"accounts", "scripts", "probes", "monitors", "results", "activity"}
        order = "created_at DESC" if table in {"results", "activity"} else "rowid DESC"
        query = f"SELECT data FROM {table} ORDER BY {order}"
        with self.connect() as db:
            rows = db.execute(query + (" LIMIT ?" if limit else ""), (limit,) if limit else ()).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, table, item_id, include_secret=False):
        assert table in {"accounts", "scripts", "probes", "monitors"}
        with self.connect() as db:
            row = db.execute(f"SELECT * FROM {table} WHERE id=?", (item_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row["data"])
        if include_secret and "secret" in row.keys():
            data["credentials"] = self.decrypt(row["secret"])
        return data

    def put(self, table, data, secret=None, next_due=None):
        assert table in {"accounts", "scripts", "probes", "monitors", "results", "activity"}
        with self.connect() as db:
            packed = json.dumps(data, ensure_ascii=False)
            if table in {"accounts", "probes"}:
                if secret is None:
                    db.execute(f"UPDATE {table} SET data=? WHERE id=?", (packed, data["id"]))
                else:
                    db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)", (data["id"], packed, self.encrypt(secret)))
            elif table == "monitors":
                db.execute("INSERT INTO monitors(id,data,next_due) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,next_due=excluded.next_due", (data["id"], packed, next_due or 0))
            elif table in {"results", "activity"}:
                db.execute(f"INSERT INTO {table} VALUES (?,?,?)", (data["id"], packed, data.get("created_at") or data["checked_at"]))
                # Bounded local storage: retain the newest 5,000 checks and 2,000 actions.
                keep = 5000 if table == "results" else 2000
                db.execute(f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (keep,))
            else:
                db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?)", (data["id"], packed))

    def delete(self, table, item_id):
        assert table in {"accounts", "scripts", "probes", "monitors"}
        with self.connect() as db:
            db.execute(f"DELETE FROM {table} WHERE id=?", (item_id,))

    def audit(self, action, message, level="info"):
        self.put("activity", {"id": uid(), "action": action, "message": message, "level": level, "created_at": now()})

    def acquire_monitor(self, item_id, timestamp, lease_seconds=300, due_only=False):
        token = uid()
        with self.connect() as db:
            cursor = db.execute("UPDATE monitors SET lease_until=?,lease_token=? WHERE id=? AND lease_until<?" + (" AND next_due<=?" if due_only else ""), (timestamp + lease_seconds, token, item_id, timestamp, timestamp) if due_only else (timestamp + lease_seconds, token, item_id, timestamp))
            return token if cursor.rowcount == 1 else None

    def release_monitor(self, item_id, token):
        with self.connect() as db:
            db.execute("UPDATE monitors SET lease_until=0,lease_token='' WHERE id=? AND lease_token=?", (item_id, token))

    def renew_monitor(self, item_id, token, timestamp, duration=900):
        with self.connect() as db:
            return db.execute("UPDATE monitors SET lease_until=? WHERE id=? AND lease_token=?", (timestamp + duration, item_id, token)).rowcount == 1

    def complete_monitor(self, item_id, status, checked_at, timestamp, lease_token):
        # Serialize configuration reads with deletes/toggles; never UPSERT a task
        # that a user removed while its network probe was running.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,lease_token,lease_until FROM monitors WHERE id=?", (item_id,)).fetchone()
            if not row or row["lease_token"] != lease_token or row["lease_until"] <= timestamp:
                return
            current = json.loads(row[0])
            due = next_run(current, timestamp)
            current.update(last_status=status, last_checked_at=checked_at,
                           next_run_at=datetime.fromtimestamp(due, timezone.utc).isoformat() if current["enabled"] else None)
            db.execute("UPDATE monitors SET data=?,next_due=? WHERE id=?", (json.dumps(current, ensure_ascii=False), due if current["enabled"] else 1e12, item_id))

    def due_monitors(self, timestamp):
        with self.connect() as db:
            rows = db.execute("SELECT data FROM monitors WHERE next_due<=? AND lease_until<? ORDER BY next_due LIMIT 100", (timestamp, timestamp)).fetchall()
        return [json.loads(row[0]) for row in rows if json.loads(row[0])["enabled"]]

    def update_monitor(self, item_id, updates, expected_revision=None, reschedule=False, expected_lease=None):
        """Merge atomically; a completed check cannot revive deleted/edited policy."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,next_due,lease_token FROM monitors WHERE id=?", (item_id,)).fetchone()
            if not row:
                return None
            if expected_lease is not None and row["lease_token"] != expected_lease:
                return None
            current = json.loads(row["data"])
            if expected_revision is not None and current.get("config_revision", "legacy") != expected_revision:
                return None
            current.update(updates)
            due = row["next_due"]
            if reschedule:
                import time
                due = next_run(current, time.time()) if current["enabled"] else 1e12
                current["next_run_at"] = datetime.fromtimestamp(due, timezone.utc).isoformat() if current["enabled"] else None
            db.execute("UPDATE monitors SET data=?,next_due=? WHERE id=?", (json.dumps(current, ensure_ascii=False), due, item_id))
            return current

    def acquire_resource(self, key, timestamp, duration=900):
        token = uid()
        with self.connect() as db:
            cursor = db.execute("INSERT INTO resource_leases VALUES (?,?,?) ON CONFLICT(resource_key) DO UPDATE SET token=excluded.token,expires=excluded.expires WHERE resource_leases.expires<=?", (key, token, timestamp + duration, timestamp))
            return token if cursor.rowcount == 1 else None

    def release_resource(self, key, token):
        with self.connect() as db:
            db.execute("DELETE FROM resource_leases WHERE resource_key=? AND token=?", (key, token))

    def renew_resource(self, key, token, timestamp, duration=900):
        with self.connect() as db:
            return db.execute("UPDATE resource_leases SET expires=? WHERE resource_key=? AND token=?", (timestamp + duration, key, token)).rowcount == 1

    def rotation_guard(self, key):
        with self.connect() as db:
            row = db.execute("SELECT data FROM rotation_guards WHERE resource_key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else {}

    def reserve_rotation(self, key, monitor_id, revision, timestamp, *, monitor_token, resource_token):
        """Commit an attempt + uncertainty marker BEFORE a non-idempotent AWS call."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,lease_token,lease_until FROM monitors WHERE id=?", (monitor_id,)).fetchone()
            resource = db.execute("SELECT token,expires FROM resource_leases WHERE resource_key=?", (key,)).fetchone()
            if not row or row["lease_token"] != monitor_token or row["lease_until"] <= timestamp or not resource or resource["token"] != resource_token or resource["expires"] <= timestamp:
                return {"status": "skipped", "message": "任务或资源租约已过期，本轮不更换 IP"}
            monitor = json.loads(row[0]) if row else {}
            if not monitor.get("enabled") or not monitor.get("auto_rotate") or monitor.get("config_revision", "legacy") != revision:
                return {"status": "skipped", "message": "任务已暂停、删除或修改，本轮不更换 IP"}
            row = db.execute("SELECT data FROM rotation_guards WHERE resource_key=?", (key,)).fetchone()
            guard = json.loads(row[0]) if row else {}
            if guard.get("state") in {"in_progress", "awaiting_review"}:
                return {"status": "awaiting_review", "message": "上次换 IP 未确认或失败，请先核对 AWS 后解除暂停"}
            attempt_id = uid()
            guard.update(state="in_progress", attempt_id=attempt_id, last_attempt_at=timestamp)
            db.execute("INSERT OR REPLACE INTO rotation_guards VALUES (?,?)", (key, json.dumps(guard)))
            db.execute("INSERT INTO rotation_attempts VALUES (?,?,?,?,?)", (attempt_id, key, monitor_id, timestamp, json.dumps({"status": "in_progress"})))
            db.execute("DELETE FROM rotation_attempts WHERE created_at<?", (timestamp - 30 * 86400,))
            return {"status": "reserved", "attempt_id": attempt_id}

    def finish_rotation(self, key, attempt_id, outcome, timestamp):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM rotation_guards WHERE resource_key=?", (key,)).fetchone()
            guard = json.loads(row[0]) if row else {}
            if guard.get("attempt_id") != attempt_id:
                raise RuntimeError("Rotation reservation changed before completion")
            guard["state"] = "ready" if outcome["status"] == "rotated" else "awaiting_review"
            guard["message"] = outcome.get("message", "")
            if outcome["status"] == "rotated":
                guard["last_rotation_at"] = timestamp
            db.execute("UPDATE rotation_guards SET data=? WHERE resource_key=?", (json.dumps(guard, ensure_ascii=False), key))
            db.execute("UPDATE rotation_attempts SET data=? WHERE id=?", (json.dumps(outcome, ensure_ascii=False), attempt_id))

    def reset_rotation(self, key, timestamp):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM rotation_guards WHERE resource_key=?", (key,)).fetchone()
            guard = json.loads(row[0]) if row else {}
            if guard.get("state") == "in_progress" and timestamp - guard.get("last_attempt_at", 0) < 900:
                return False
            guard.update(state="ready", message="管理员已核对并解除暂停")
            db.execute("INSERT OR REPLACE INTO rotation_guards VALUES (?,?)", (key, json.dumps(guard, ensure_ascii=False)))
            return True
