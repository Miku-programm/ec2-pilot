"""Small SQLite store. Credentials are encrypted at rest; keys never enter JSON responses."""
import json
import os
import sqlite3
import time
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
                CREATE TABLE IF NOT EXISTS eip_cleanup (allocation_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL, next_try REAL NOT NULL, lease_token TEXT NOT NULL DEFAULT '', lease_until REAL NOT NULL DEFAULT 0);
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

    def delete_account_if_unused(self, account_id, timestamp):
        """Check references and remove credentials in one write transaction.

        The same transaction boundary as record_cleanup_intent ensures that a
        rotation cannot leave a newly written intent without its credentials.
        Resource leases use the real AWS identity, including other panel aliases.
        """
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                return "missing"
            account = json.loads(row["data"])
            if any(json.loads(row["data"]).get("account_id") == account_id
                   for row in db.execute("SELECT data FROM monitors")):
                return "monitors"
            if db.execute("SELECT 1 FROM eip_cleanup WHERE account_id=? LIMIT 1", (account_id,)).fetchone():
                return "cleanup"
            prefix = f"{account['aws_account_id']}:{account['region']}:"
            if any(row["resource_key"].startswith(prefix) for row in db.execute(
                    "SELECT resource_key FROM resource_leases WHERE expires>?", (timestamp,))):
                return "busy"
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
            return "deleted"

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
            # A known pre-allocation abort did not send a mutation to AWS and
            # must not pause the monitor as if an AWS outcome were uncertain.
            guard["state"] = "ready" if outcome["status"] in {"rotated", "skipped"} else "awaiting_review"
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

    # ---- Old-EIP release queue ------------------------------------------------
    # Only addresses the user chose to release ever enter this table.
    # States: blocked (rotation not yet confirmed; never processed), queued,
    # review (reused/unclear; automatic cleanup stopped), failed (retries exhausted).
    # Every AWS action happens under an owner lease; dismiss/approve/update
    # refuse to touch a row whose lease is live.

    CLEANUP_LEASE_SECONDS = 300

    def record_cleanup_intent(self, account_id, entry, timestamp, *, resource_token=None):
        """Write a blocked intent BEFORE AllocateAddress. Returns False if a
        worker owns the row or its account was deleted (caller must abort)."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                return False
            account = json.loads(row["data"])
            if resource_token is not None:
                key = f"{account['aws_account_id']}:{account['region']}:{entry.get('instance_id', '')}"
                owned = db.execute("SELECT 1 FROM resource_leases WHERE resource_key=? AND token=? AND expires>?",
                                   (key, resource_token, timestamp)).fetchone()
                if not owned:
                    return False
            data = {**entry, "account_id": account_id, "aws_account_id": account["aws_account_id"],
                    "region": account["region"], "created_at": timestamp, "attempts": 0, "last_error": None}
            packed = json.dumps(data, ensure_ascii=False)
            cursor = db.execute(
                "INSERT INTO eip_cleanup(allocation_id,account_id,state,data,next_try) VALUES (?,?,'blocked',?,1e12) "
                "ON CONFLICT(allocation_id) DO UPDATE SET account_id=excluded.account_id,state='blocked',data=excluded.data,next_try=1e12,lease_token='',lease_until=0 "
                "WHERE eip_cleanup.lease_until<?",
                (entry["allocation_id"], account_id, packed, timestamp))
            return cursor.rowcount == 1

    def unblock_cleanup(self, allocation_id, attempt_id, timestamp):
        """Rotation confirmed: make the intent eligible. Only the matching attempt
        may unblock it, so a stale caller cannot release a newer intent."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,state FROM eip_cleanup WHERE allocation_id=?", (allocation_id,)).fetchone()
            if not row or row["state"] != "blocked" or json.loads(row["data"]).get("attempt_id") != attempt_id:
                return False
            db.execute("UPDATE eip_cleanup SET state='queued',next_try=? WHERE allocation_id=?", (timestamp, allocation_id))
            return True

    def claim_cleanup(self, allocation_id, timestamp, due_only=True):
        """Atomically take ownership of one queued row. Returns (token, data) or None."""
        token = uid()
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE eip_cleanup SET lease_token=?,lease_until=? WHERE allocation_id=? AND state='queued' AND lease_until<?"
                + (" AND next_try<=?" if due_only else ""),
                (token, timestamp + self.CLEANUP_LEASE_SECONDS, allocation_id, timestamp) + ((timestamp,) if due_only else ()))
            if cursor.rowcount != 1:
                return None
            row = db.execute("SELECT data FROM eip_cleanup WHERE allocation_id=?", (allocation_id,)).fetchone()
        return token, json.loads(row[0])

    def renew_cleanup(self, allocation_id, token, timestamp):
        """Re-confirm ownership immediately before an AWS mutation."""
        with self.connect() as db:
            return db.execute(
                "UPDATE eip_cleanup SET lease_until=? WHERE allocation_id=? AND lease_token=? AND lease_until>? AND state='queued'",
                (timestamp + self.CLEANUP_LEASE_SECONDS, allocation_id, token, timestamp)).rowcount == 1

    def finish_cleanup(self, allocation_id, token, *, remove=False, state=None, data=None, next_try=None, timestamp=None):
        """A live queued-row owner may complete; expired owners change nothing."""
        timestamp = time.time() if timestamp is None else timestamp
        with self.connect() as db:
            if remove:
                return db.execute("DELETE FROM eip_cleanup WHERE allocation_id=? AND lease_token=? AND lease_until>? AND state='queued'", (allocation_id, token, timestamp)).rowcount == 1
            return db.execute(
                "UPDATE eip_cleanup SET state=COALESCE(?,state),data=COALESCE(?,data),next_try=COALESCE(?,next_try),lease_token='',lease_until=0 "
                "WHERE allocation_id=? AND lease_token=? AND lease_until>? AND state='queued'",
                (state, json.dumps(data, ensure_ascii=False) if data is not None else None, next_try, allocation_id, token, timestamp)).rowcount == 1

    def due_cleanup(self, timestamp, limit=20):
        with self.connect() as db:
            rows = db.execute("SELECT allocation_id FROM eip_cleanup WHERE state='queued' AND next_try<=? AND lease_until<? ORDER BY next_try LIMIT ?",
                              (timestamp, timestamp, limit)).fetchall()
        return [row[0] for row in rows]

    @staticmethod
    def _cleanup_resource_busy(db, data, timestamp):
        """A blocked intent may still belong to an in-flight rotation."""
        identity = data
        if not data.get("aws_account_id") or not data.get("region"):
            row = db.execute("SELECT data FROM accounts WHERE id=?", (data.get("account_id"),)).fetchone()
            identity = json.loads(row["data"]) if row else {}
        if not identity.get("aws_account_id") or not identity.get("region") or not data.get("instance_id"):
            return False
        key = f"{identity['aws_account_id']}:{identity['region']}:{data['instance_id']}"
        return db.execute("SELECT 1 FROM resource_leases WHERE resource_key=? AND expires>?", (key, timestamp)).fetchone() is not None

    def dismiss_cleanup(self, allocation_id, timestamp):
        """User keeps the address. Refused while cleanup or rotation is active.
        Returns 'removed', 'busy' or 'missing'."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,lease_until FROM eip_cleanup WHERE allocation_id=?", (allocation_id,)).fetchone()
            if not row:
                return "missing"
            if row["lease_until"] >= timestamp or self._cleanup_resource_busy(db, json.loads(row["data"]), timestamp):
                return "busy"
            db.execute("DELETE FROM eip_cleanup WHERE allocation_id=?", (allocation_id,))
            return "removed"

    def approve_cleanup(self, allocation_id, timestamp):
        """Admin verified AWS: blocked/failed rows become queued again.
        Returns 'queued', 'busy', 'invalid' or 'missing'."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data,state,lease_until FROM eip_cleanup WHERE allocation_id=?", (allocation_id,)).fetchone()
            if not row:
                return "missing"
            data = json.loads(row["data"])
            if row["lease_until"] >= timestamp or self._cleanup_resource_busy(db, data, timestamp):
                return "busy"
            if row["state"] not in {"blocked", "failed"}:
                return "invalid"
            data.update(attempts=0, last_error=None)
            db.execute("UPDATE eip_cleanup SET state='queued',next_try=?,data=?,lease_token='',lease_until=0 WHERE allocation_id=?",
                       (timestamp, json.dumps(data, ensure_ascii=False), allocation_id))
            return "queued"

    def list_cleanup(self, account_id=None):
        query = "SELECT data,state,next_try,lease_until FROM eip_cleanup" + (" WHERE account_id=?" if account_id else "") + " ORDER BY rowid"
        timestamp = time.time()
        with self.connect() as db:
            rows = db.execute(query, (account_id,) if account_id else ()).fetchall()
            items = []
            for row in rows:
                data = json.loads(row["data"])
                items.append({**data, "state": row["state"],
                              "processing": row["lease_until"] > timestamp or self._cleanup_resource_busy(db, data, timestamp),
                              "next_try_at": datetime.fromtimestamp(row["next_try"], timezone.utc).isoformat() if row["next_try"] < 1e11 else None})
        return items
