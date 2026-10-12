"""Local, authenticated EC2 control panel. Run one worker for the durable scheduler."""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .aws_service import AwsService
from .models import Password, Account, Script, Launch, Rotate, Monitor, MonitorPatch, Probe, UserData
from .probing import tcp_probe, remote_probe, classify_gfw, validate_remote_url
from .store import Store, now, uid
from .scheduling import next_run
from .rotation_policy import qualifying_failure
from .leases import keep_lease

VERSION = "1.1.1"
BASE = Path(__file__).resolve().parent.parent
COOKIE = "ec2_panel_session"


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return f"{salt}${digest}"


def check_password(password, stored):
    if not stored:
        return False
    return hmac.compare_digest(hash_password(password, stored.split("$", 1)[0]), stored)


def iso_timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def create_app(data_dir=None, *, start_scheduler=True, aws_factory=AwsService, scheduler_tick=5, rotation_verify_delay=2):
    attempts = defaultdict(deque)
    login_lock = threading.Lock()
    mutation_locks = defaultdict(threading.Lock)
    allowed_hosts = {host.strip().lower() for host in os.getenv("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",") if host.strip()}

    @asynccontextmanager
    async def lifespan(app):
        directory = data_dir or os.getenv("PANEL_DATA_DIR", str(BASE / "data"))
        app.state.store = Store(directory)
        app.state.monitor_slots = asyncio.Semaphore(4)
        app.state.manual_tasks = set()
        initial = os.getenv("PANEL_ADMIN_PASSWORD")
        if initial and not app.state.store.get_setting("password"):
            if len(initial) < 12:
                raise RuntimeError("PANEL_ADMIN_PASSWORD must contain at least 12 characters")
            app.state.store.set_setting("password", hash_password(initial))
        if not app.state.store.get_setting("initialized"):
            app.state.store.put("scripts", {"id": uid(), "name": "首次启动 · 安装 Nginx（Amazon Linux 2023）", "content": "#!/bin/bash\nset -euxo pipefail\ndnf install -y nginx\nsystemctl enable --now nginx\n", "created_at": now()})
            app.state.store.put("scripts", {"id": uid(), "name": "每次启动 · systemd 示例（Amazon Linux）", "content": "#!/bin/bash\nset -euxo pipefail\ncat > /usr/local/bin/panel-boot.sh <<'SCRIPT'\n#!/bin/bash\ndate -Is >> /var/log/panel-boot.log\nSCRIPT\nchmod 700 /usr/local/bin/panel-boot.sh\ncat > /etc/systemd/system/panel-boot.service <<'UNIT'\n[Unit]\nDescription=Custom boot task\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/panel-boot.sh\n[Install]\nWantedBy=multi-user.target\nUNIT\nsystemctl daemon-reload\nsystemctl enable --now panel-boot.service\n", "created_at": now()})
            app.state.store.set_setting("initialized", "1")
        task = asyncio.create_task(scheduler(app)) if start_scheduler and os.getenv("PANEL_SCHEDULER", "internal") != "external" else None
        yield
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app = FastAPI(title="EC2 Pilot", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def request_guard(request, call_next):
        # Do not trust arbitrary Host headers, including during first-run setup.
        # This also prevents a public domain rebound to a local IP from setting
        # the administrator password with a matching, attacker-chosen Origin.
        if request.url.hostname not in allowed_hosts:
            return JSONResponse({"detail": "访问地址未列入 PANEL_ALLOWED_HOSTS"}, status_code=400)
        if request.url.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected = str(request.base_url).rstrip("/")
            if origin and origin.rstrip("/") != expected:
                return JSONResponse({"detail": "来源不匹配，请从面板自身地址操作"}, status_code=403)
            length = request.headers.get("content-length")
            if length and (not length.isdigit() or int(length) > 131072):
                return JSONResponse({"detail": "请求过大"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        # Never echo credential values from Pydantic's input field.
        errors = [f"{'.'.join(str(p) for p in e['loc'][1:])}: {e['msg']}" for e in exc.errors()]
        return JSONResponse({"detail": "；".join(errors)}, status_code=422)

    def store():
        return app.state.store

    def authenticated(request: Request):
        token = request.cookies.get(COOKIE, "")
        if not token:
            raise HTTPException(401, "请先登录面板")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with store().connect() as db:
            row = db.execute("SELECT expires FROM sessions WHERE id=?", (token_hash,)).fetchone()
        if not row or row[0] <= time.time():
            raise HTTPException(401, "会话已过期，请重新登录")

    auth = [Depends(authenticated)]

    def session_response():
        token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with store().connect() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES (?,?)", (token_hash, time.time() + 43200))
        result = JSONResponse({"ok": True})
        result.set_cookie(COOKIE, token, max_age=43200, httponly=True, samesite="strict", secure=os.getenv("PANEL_SECURE_COOKIE", "0") == "1")
        return result

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": VERSION, "setup_required": not bool(store().get_setting("password"))}

    @app.post("/api/setup")
    def setup(body: Password, request: Request):
        try:
            local = ipaddress.ip_address(request.client.host).is_loopback
        except ValueError:
            local = False
        if not local:
            raise HTTPException(403, "首次设置只允许本机连接；Docker/远程部署请设置 PANEL_ADMIN_PASSWORD")
        with login_lock:
            if store().get_setting("password"):
                raise HTTPException(409, "管理员已设置，请登录")
            store().set_setting("password", hash_password(body.password))
        store().audit("setup", "完成面板管理员设置")
        return session_response()

    @app.post("/api/login")
    def login(body: Password, request: Request):
        ip = request.client.host
        with login_lock:
            history = attempts[ip]
            while history and history[0] < time.time() - 900:
                history.popleft()
            if len(history) >= 8:
                raise HTTPException(429, "尝试过于频繁，请 15 分钟后重试")
            history.append(time.time())
            if not check_password(body.password, store().get_setting("password")):
                raise HTTPException(401, "密码不正确")
            attempts.pop(ip, None)
        return session_response()

    @app.post("/api/logout")
    def logout(request: Request):
        with store().connect() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest(),))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE)
        return response

    def need(table, item_id, secret=False):
        item = store().get(table, item_id, secret)
        if not item:
            raise HTTPException(404, "记录不存在")
        return item

    def aws(account_id):
        account = need("accounts", account_id, True)
        return aws_factory(account["credentials"], account["region"])

    def resource_key(account_id, resource):
        account = need("accounts", account_id)
        return f"{account['aws_account_id']}:{account['region']}:{resource}"

    @contextmanager
    def mutation_lock(account_id, resource):
        key = resource_key(account_id, resource)
        with mutation_locks[key]:
            lease = store().acquire_resource(key, time.time())
            if not lease:
                raise HTTPException(409, "此 AWS 资源正在由另一个任务操作，请稍后重试")
            try:
                with keep_lease(lambda: store().renew_resource(key, lease, time.time())) as owned:
                    owned.lease_token = lease
                    yield owned
            finally:
                store().release_resource(key, lease)

    def aws_call(callback):
        try:
            return callback()
        except HTTPException:
            raise
        except Exception as exc:
            from botocore.exceptions import ClientError, BotoCoreError
            if isinstance(exc, ClientError):
                error = exc.response.get("Error", {})
                raise HTTPException(502, f"AWS {error.get('Code', 'Error')}: {error.get('Message', '请求失败')}") from None
            if hasattr(exc, "code") and hasattr(exc, "message"):
                raise HTTPException(502, f"AWS {exc.code}: {exc.message}") from None
            if isinstance(exc, (ValueError, BotoCoreError)):
                raise HTTPException(400, str(exc)) from None
            raise HTTPException(502, "AWS 请求失败，请检查网络、区域及服务权限") from None

    @app.get("/api/state", dependencies=auth)
    def state():
        payload = {name: store().list(name, 100 if name in {"activity", "results"} else None) for name in ["accounts", "scripts", "probes", "monitors", "results", "activity"]}
        for monitor in payload["monitors"]:
            if store().get("accounts", monitor["account_id"]):
                guard = store().rotation_guard(resource_key(monitor["account_id"], monitor["instance_id"]))
                if guard.get("state") in {"in_progress", "awaiting_review"}:
                    monitor.update(rotation_status="awaiting_review", rotation_message="换 IP 尚未确认或失败；请核对 AWS 后解除自动更换暂停")
        return {**payload, "meta": {"default_region": "ap-southeast-2", "server_time": now(), "version": VERSION, "scheduler_mode": os.getenv("PANEL_SCHEDULER", "internal")}}

    @app.post("/api/accounts", dependencies=auth)
    def add_account(body: Account):
        credentials = {k: getattr(body, k) for k in ["access_key_id", "secret_access_key", "session_token"]}
        identity = aws_call(lambda: aws_factory(credentials, body.region).validate())
        record = {"id": uid(), "name": body.name.strip(), "region": body.region, "aws_account_id": identity["aws_account_id"], "arn": identity["arn"], "access_key_hint": body.access_key_id[:4] + "…" + body.access_key_id[-4:], "created_at": now()}
        store().put("accounts", record, credentials)
        store().audit("account.add", f"添加账号 {record['name']}（{record['aws_account_id']}）")
        return record

    @app.delete("/api/accounts/{account_id}", dependencies=auth)
    def delete_account(account_id: str):
        account = need("accounts", account_id)
        if any(m["account_id"] == account_id for m in store().list("monitors")):
            raise HTTPException(409, "请先删除这个账号关联的检测任务")
        store().delete("accounts", account_id)
        store().audit("account.delete", f"移除面板账号 {account['name']}，AWS 资源未改变")
        return {"ok": True}

    @app.get("/api/accounts/{account_id}/instances", dependencies=auth)
    def instances(account_id: str):
        return {"instances": aws_call(lambda: aws(account_id).instances())}

    @app.get("/api/accounts/{account_id}/resources", dependencies=auth)
    def resources(account_id: str):
        return aws_call(lambda: aws(account_id).resources())

    def user_data(body):
        if body.script_id and body.user_data:
            raise HTTPException(422, "请选择脚本模板或填写自定义脚本，不要同时提交")
        content = need("scripts", body.script_id)["content"] if body.script_id else body.user_data or ""
        if len(content.encode()) > 16384:
            raise HTTPException(422, "User Data 的 UTF-8 长度不能超过 16 KiB")
        return content

    @app.post("/api/accounts/{account_id}/instances/launch", dependencies=auth)
    def launch(account_id: str, body: Launch, request: Request):
        # A client idempotency key is mandatory for costly creation; repeat requests reuse AWS ClientToken.
        token = request.headers.get("Idempotency-Key", "")
        if not 16 <= len(token) <= 64 or not all(c.isalnum() or c == "-" for c in token):
            raise HTTPException(422, "创建实例需要 Idempotency-Key（16–64 位字母数字或连字符）")
        payload = body.model_dump(exclude_none=True)
        payload["user_data"] = user_data(body)
        payload["operation_token"] = token
        payload.pop("script_id", None)
        with mutation_lock(account_id, "launch"):
            result = aws_call(lambda: aws(account_id).launch(payload))
        store().audit("ec2.launch", f"请求创建 {body.name}，实例 {', '.join(result.get('instance_ids', []))}")
        return result

    @app.post("/api/accounts/{account_id}/instances/{instance_id}/{action}", dependencies=auth)
    def instance_action(account_id: str, instance_id: str, action: str):
        if action not in {"start", "stop", "reboot"}:
            raise HTTPException(404, "未知实例操作")
        with mutation_lock(account_id, instance_id):
            result = aws_call(lambda: getattr(aws(account_id), action)(instance_id))
        store().audit(f"ec2.{action}", f"{action} · {instance_id}")
        return result or {"message": "操作已提交，请刷新状态"}

    @app.put("/api/accounts/{account_id}/instances/{instance_id}/user-data", dependencies=auth)
    def set_script(account_id: str, instance_id: str, body: UserData):
        with mutation_lock(account_id, instance_id):
            result = aws_call(lambda: aws(account_id).set_user_data(instance_id, user_data(body)))
        store().audit("ec2.user-data", f"更新 {instance_id} 的启动脚本")
        return result or {"message": "已保存。现有实例的 cloud-init 通常不会自动重跑，请按脚本设计确认。"}

    # Register this before generic action at runtime (see route ordering below).
    @app.post("/api/accounts/{account_id}/instances/{instance_id}/rotate-ip", dependencies=auth)
    def rotate_ip(account_id: str, instance_id: str, body: Rotate):
        with mutation_lock(account_id, instance_id):
            result = aws_call(lambda: aws(account_id).rotate_ip(instance_id, body.release_previous))
        store().audit("ec2.rotate-ip", f"{instance_id} 换 IP：{result.get('public_ip', '已提交')}")
        return result

    # Specific POST /rotate-ip must precede the generic /{action} route.
    generic_index = next(i for i, r in enumerate(app.router.routes) if getattr(r, "endpoint", None) is instance_action)
    rotate_route = app.router.routes.pop()
    app.router.routes.insert(generic_index, rotate_route)

    @app.post("/api/scripts", dependencies=auth)
    def add_script(body: Script):
        if len(body.content.encode()) > 16384:
            raise HTTPException(422, "脚本不能超过 16 KiB UTF-8")
        record = {"id": uid(), **body.model_dump(), "created_at": now()}
        store().put("scripts", record)
        return record

    @app.put("/api/scripts/{item_id}", dependencies=auth)
    def edit_script(item_id: str, body: Script):
        record = need("scripts", item_id)
        if len(body.content.encode()) > 16384:
            raise HTTPException(422, "脚本不能超过 16 KiB UTF-8")
        record.update(body.model_dump())
        store().put("scripts", record)
        return record

    @app.delete("/api/scripts/{item_id}", dependencies=auth)
    def delete_script(item_id: str):
        need("scripts", item_id)
        store().delete("scripts", item_id)
        return {"ok": True}

    def validate_monitor(body):
        need("accounts", body.account_id)
        records = aws_call(lambda: aws(body.account_id).instances())
        if not any(r["id"] == body.instance_id for r in records):
            raise HTTPException(422, "请选择这个账号、区域内实际存在的 EC2 实例")

    @app.post("/api/monitors", dependencies=auth)
    def add_monitor(body: Monitor):
        if len(store().list("monitors")) >= 100:
            raise HTTPException(409, "简易版最多支持 100 个检测任务")
        validate_monitor(body)
        due = next_run(body.model_dump(), time.time())
        record = {"id": uid(), **body.model_dump(), "config_revision": uid(), "failure_streak": 0, "rotation_status": "skipped", "rotation_message": "等待定时检测", "next_run_at": iso_timestamp(due) if body.enabled else None, "last_status": "pending", "last_checked_at": None}
        store().put("monitors", record, next_due=due if body.enabled else 1e12)
        store().audit("monitor.add", f"添加检测任务 {body.name}")
        return record

    @app.put("/api/monitors/{item_id}", dependencies=auth)
    def edit_monitor(item_id: str, body: MonitorPatch):
        record = need("monitors", item_id)
        updates = body.model_dump(exclude_none=True)
        from pydantic import ValidationError
        candidate = {key: record[key] for key in Monitor.model_fields if key in record}
        candidate.update(updates)
        try:
            validated = Monitor(**candidate)
        except ValidationError as exc:
            raise HTTPException(422, "；".join(e["msg"] for e in exc.errors())) from None
        if "account_id" in updates or "instance_id" in updates:
            validate_monitor(validated)
        updates = {**validated.model_dump(), "config_revision": uid(), "failure_streak": 0, "failure_ip": None}
        updated = store().update_monitor(item_id, updates, expected_revision=record.get("config_revision", "legacy"), reschedule=True)
        if updated is None:
            raise HTTPException(409, "任务同时被修改或删除，请刷新后重试")
        return updated

    @app.delete("/api/monitors/{item_id}", dependencies=auth)
    def delete_monitor(item_id: str):
        need("monitors", item_id)
        store().delete("monitors", item_id)
        return {"ok": True}

    def observe(record, expected_ip=None):
        result = {"target_ip": None, "status": "error", "success_count": 0, "samples": record["samples"], "latency_ms": None, "loss_percent": None, "gfw_status": "insufficient_evidence", "summary": "", "observations": []}
        try:
            items = aws_call(lambda: aws(record["account_id"]).instances())
            instance = next((i for i in items if i["id"] == record["instance_id"]), None)
            if not instance:
                result["summary"] = "实例不存在或不在所选区域"
            elif not (expected_ip or instance.get("public_ip")):
                result.update(status="no_public_ip", summary="实例没有公网 IPv4，本次未发起探测")
            elif instance.get("state") != "running":
                result.update(status="error", summary="实例尚未运行，本次未发起探测")
            else:
                result["target_ip"] = expected_ip or instance["public_ip"]
                args = {"target_ip": result["target_ip"], "port": record["port"], "timeout_seconds": record["timeout_seconds"], "samples": record["samples"]}
                measured = tcp_probe(**args)
                result.update({key: measured[key] for key in ["success_count", "samples", "latency_ms", "loss_percent"]})
                result["status"] = "reachable" if measured["success_count"] else "unreachable"
                result["observations"].append({"name": "面板后端", "region_type": "local", **measured})
                for probe in store().list("probes"):
                    if not probe.get("enabled", True):
                        continue
                    try:
                        token = need("probes", probe["id"], True)["credentials"]["token"]
                        observed = remote_probe(probe["url"], token, args)
                        result["observations"].append({"name": probe["name"], "region_type": probe["region_type"], **observed})
                    except Exception:
                        result["observations"].append({"name": probe["name"], "region_type": probe["region_type"], "error": "远程探针连接或响应失败"})
                result["gfw_status"] = classify_gfw(result["observations"])
                result["summary"] = f"本地 TCP {measured['success_count']}/{record['samples']} 次连接成功。"
                if result["gfw_status"] == "insufficient_evidence":
                    result["summary"] += " 缺少有效的国内/境外对照，无法判断 GFW。"
                elif result["gfw_status"] == "suspected_filtering":
                    result["summary"] += " 国内失败、境外成功，疑似路径过滤；仍需排查安全组、服务和路由。"
        except HTTPException as exc:
            result["summary"] = str(exc.detail)
        except Exception:
            result["summary"] = "检测失败，请检查实例公网地址、探针和服务配置"
        return result

    def automate_rotation(record, result, monitor_owned, monitor_token):
        revision = record.get("config_revision", "legacy")
        item_id = record["id"]
        current = store().get("monitors", item_id)
        if not monitor_owned.is_set() or not current or not current.get("enabled") or not current.get("auto_rotate") or current.get("config_revision", "legacy") != revision:
            return {"status": "skipped", "message": "自动更换未启用，或任务在本轮检测期间已修改"}
        failed = qualifying_failure(current, result)
        same_ip = current.get("failure_ip") == result.get("target_ip")
        streak = (current.get("failure_streak", 0) + 1 if same_ip else 1) if failed else 0
        updated = store().update_monitor(item_id, {"failure_streak": streak, "failure_ip": result.get("target_ip") if failed else None}, expected_revision=revision, expected_lease=monitor_token)
        if updated is None:
            return {"status": "skipped", "message": "任务已修改，本轮不更换 IP"}
        key = resource_key(record["account_id"], record["instance_id"])
        if store().rotation_guard(key).get("state") in {"in_progress", "awaiting_review"}:
            return {"status": "awaiting_review", "message": "上次换 IP 未确认或失败；检测继续，自动更换暂停，请先核对 AWS"}
        if not failed:
            return {"status": "skipped", "message": "未满足有效失败条件，连续失败计数已清零"}
        if streak < current["failure_threshold"]:
            return {"status": "threshold", "message": f"连续失败 {streak}/{current['failure_threshold']} 轮，尚未达到更换条件"}
        with mutation_lock(record["account_id"], record["instance_id"]) as resource_owned:
            latest = store().get("monitors", item_id)
            if not latest or not latest.get("enabled") or not latest.get("auto_rotate") or latest.get("config_revision", "legacy") != revision:
                return {"status": "skipped", "message": "任务已暂停或修改，本轮不更换 IP"}
            # Re-read AWS state/IP and repeat the entire selected trigger check
            # immediately before reserving a costly, non-idempotent action.
            confirmed = observe(latest)
            if confirmed.get("target_ip") != result.get("target_ip") or not qualifying_failure(latest, confirmed):
                store().update_monitor(item_id, {"failure_streak": 0, "failure_ip": None}, expected_revision=revision, expected_lease=monitor_token)
                return {"status": "recovered", "message": "操作前复检已恢复、IP 已变化或证据不足，取消本次更换", "verification": confirmed}
            if not monitor_owned.is_set() or not resource_owned.is_set():
                return {"status": "skipped", "message": "任务租约已失效，本轮不更换 IP"}
            reservation = store().reserve_rotation(key, item_id, revision, time.time(), monitor_token=monitor_token, resource_token=resource_owned.lease_token)
            if reservation["status"] != "reserved":
                return reservation
            attempt_id = reservation["attempt_id"]
            outcome = {"status": "awaiting_review", "old_ip": result["target_ip"], "message": "换 IP 结果未确认，请核对 AWS 后解除暂停"}
            try:
                changed = aws_call(lambda: aws(record["account_id"]).rotate_ip(record["instance_id"], latest.get("release_previous", False)))
                if not changed.get("public_ip"):
                    raise HTTPException(502, "AWS 未返回新公网地址，请先核对")
                outcome.update(status="rotated", new_ip=changed["public_ip"], message=changed.get("message", "新 IP 已绑定"))
                store().finish_rotation(key, attempt_id, outcome, time.time())
                store().update_monitor(item_id, {"failure_streak": 0, "failure_ip": None, "last_rotation_at": now()}, expected_revision=revision, expected_lease=monitor_token)
                store().audit("ec2.auto-rotate", f"{record['instance_id']} 自动换 IP：{outcome['old_ip']} → {outcome['new_ip']}")
            except Exception as exc:
                detail = str(exc.detail) if isinstance(exc, HTTPException) else "换 IP 执行或记录失败，结果无法确认"
                outcome.update(status="awaiting_review", message=detail + "；自动更换已暂停，请核对 AWS 后解除暂停")
                store().finish_rotation(key, attempt_id, outcome, time.time())
                store().audit("ec2.auto-rotate.failed", f"{record['instance_id']}：{outcome['message']}", "error")
                return outcome
            if rotation_verify_delay:
                time.sleep(rotation_verify_delay)
            # Do not recurse or rotate again when the new address fails its check.
            verification = observe(latest, expected_ip=outcome["new_ip"])
            outcome["verification"] = verification
            outcome["message"] += " 换后复测：" + verification["summary"]
            return outcome

    def run_check(item_id, scheduled=False):
        record = need("monitors", item_id)
        if scheduled and not record["enabled"]:
            raise HTTPException(409, "定时任务已暂停")
        lease = store().acquire_monitor(item_id, time.time(), 900, due_only=scheduled)
        if not lease:
            raise HTTPException(409, "这个任务正在检测中或尚未到期")
        result = {"id": uid(), "monitor_id": item_id, "monitor_name": record["name"], "instance_id": record["instance_id"], "port": record["port"], "checked_at": now(), "scheduled": scheduled}
        keeper = keep_lease(lambda: store().renew_monitor(item_id, lease, time.time()))
        monitor_owned = keeper.__enter__()
        try:
            result.update(observe(record))
            if scheduled:
                try:
                    result["rotation"] = automate_rotation(record, result, monitor_owned, lease)
                except Exception as exc:
                    guard = store().rotation_guard(resource_key(record["account_id"], record["instance_id"])) if store().get("accounts", record["account_id"]) else {}
                    uncertain = guard.get("state") in {"in_progress", "awaiting_review"}
                    result["rotation"] = {"status": "awaiting_review" if uncertain else "skipped", "message": "更换结果未确认，自动更换暂停；请核对 AWS" if uncertain else (str(exc.detail) if isinstance(exc, HTTPException) else "自动更换流程未完成，请核对操作记录")}
                store().update_monitor(item_id, {"rotation_status": result["rotation"]["status"], "rotation_message": result["rotation"]["message"]}, expected_revision=record.get("config_revision", "legacy"), expected_lease=lease)
            store().put("results", result)
            final_status = result.get("rotation", {}).get("verification", {}).get("status", result["status"])
            store().complete_monitor(item_id, final_status, result["checked_at"], time.time(), lease)
        finally:
            keeper.__exit__(None, None, None)
            store().release_monitor(item_id, lease)
        return result

    @app.post("/api/monitors/{item_id}/run", dependencies=auth)
    async def manual_check(item_id: str):
        need("monitors", item_id)
        async with app.state.monitor_slots:
            return {"result": await asyncio.to_thread(run_check, item_id)}

    @app.post("/api/monitors/{item_id}/reset-rotation", dependencies=auth)
    def reset_rotation(item_id: str):
        monitor = need("monitors", item_id)
        key = resource_key(monitor["account_id"], monitor["instance_id"])
        with mutation_lock(monitor["account_id"], monitor["instance_id"]):
            if not store().reset_rotation(key, time.time()):
                raise HTTPException(409, "上次换 IP 仍在执行或未满 15 分钟，请先等待并核对 AWS")
            for item in store().list("monitors"):
                if store().get("accounts", item["account_id"]) and resource_key(item["account_id"], item["instance_id"]) == key:
                    store().update_monitor(item["id"], {"failure_streak": 0, "failure_ip": None, "rotation_status": "skipped", "rotation_message": "管理员已解除暂停，等待下次定时检测", "config_revision": uid()})
        store().audit("ec2.auto-rotate.reset", f"已解除 {monitor['instance_id']} 自动更换暂停；等待下一次定时检测")
        return {"ok": True, "message": "自动更换暂停已解除；失败计数清零，下一次定时检测按规则执行"}

    async def run_due_monitors():
        async def one(item_id):
            async with app.state.monitor_slots:
                try:
                    return await asyncio.to_thread(run_check, item_id, True)
                except HTTPException:
                    return None
        due = store().due_monitors(time.time())
        return [r for r in await asyncio.gather(*(one(m["id"]) for m in due)) if r]

    # Local cron CLI and tests reuse exactly the same worker as the web process.
    app.state.run_check = run_check
    app.state.run_due_monitors = run_due_monitors

    async def scheduler(app):
        while True:
            batch = asyncio.create_task(run_due_monitors())
            try:
                await asyncio.shield(batch)
            except asyncio.CancelledError:
                await batch
                raise
            except Exception:
                store().audit("scheduler.error", "调度执行异常，将在下次检查到期任务", "error")
            await asyncio.sleep(scheduler_tick)

    @app.post("/api/probes", dependencies=auth)
    def add_probe(body: Probe):
        if len(store().list("probes")) >= 4:
            raise HTTPException(409, "最多配置 4 个对照探针")
        try:
            validate_remote_url(body.url)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        record = {"id": uid(), "name": body.name, "region_type": body.region_type, "url": body.url.rstrip("/"), "enabled": True}
        store().put("probes", record, {"token": body.token})
        return record

    @app.delete("/api/probes/{item_id}", dependencies=auth)
    def delete_probe(item_id: str):
        need("probes", item_id)
        store().delete("probes", item_id)
        return {"ok": True}

    app.mount("/", StaticFiles(directory=BASE / "static", html=True), name="static")
    return app


app = create_app()
