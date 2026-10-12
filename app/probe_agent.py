"""Optional remote TCP probe. Put behind HTTPS and set PROBE_TOKEN."""

from contextlib import asynccontextmanager
import hmac
import os
import threading
from typing import Union

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt

from .probing import tcp_probe, validate_probe_request


_capacity = threading.BoundedSemaphore(4)


@asynccontextmanager
async def lifespan(application):
    token = os.environ.get("PROBE_TOKEN", "")
    if not 24 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise RuntimeError("PROBE_TOKEN 必须为 24–512 字符的随机令牌（无空白、仅 ASCII）")
    application.state.probe_token = token
    try:
        yield
    finally:
        application.state.probe_token = None


app = FastAPI(title="EC2 TCP Probe", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_ip: str
    port: StrictInt = Field(ge=1, le=65535)
    timeout_seconds: Union[StrictInt, StrictFloat] = Field(default=3, ge=1, le=10)
    samples: StrictInt = Field(default=3, ge=1, le=5)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/probe")
def probe(request: ProbeRequest, authorization: str | None = Header(default=None)):
    configured_token = getattr(app.state, "probe_token", None)
    scheme, _, supplied = (authorization or "").partition(" ")
    if (
        not configured_token
        or scheme.lower() != "bearer"
        or not hmac.compare_digest(supplied.encode("utf-8"), configured_token.encode("utf-8"))
    ):
        raise HTTPException(status_code=401, detail="探针认证失败", headers={"WWW-Authenticate": "Bearer"})
    try:
        values = validate_probe_request(request.target_ip, request.port, request.timeout_seconds, request.samples)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not _capacity.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="探针并发已满，请稍后重试", headers={"Retry-After": "5"})
    try:
        return tcp_probe(**values)
    finally:
        _capacity.release()
