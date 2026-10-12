from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Password(Input):
    password: str = Field(min_length=12, max_length=256)


class Account(Input):
    name: str = Field(min_length=1, max_length=80)
    access_key_id: str = Field(min_length=16, max_length=128)
    secret_access_key: str = Field(min_length=16, max_length=256)
    session_token: str | None = Field(default=None, max_length=8192)
    region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}(?:-[a-z]+)+-\d+$", max_length=40)


class Script(Input):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(max_length=16384)


class UserData(Input):
    script_id: str | None = None
    user_data: str | None = Field(default=None, max_length=16384)


class Launch(UserData):
    name: str = Field(min_length=1, max_length=100)
    image_id: str = Field(pattern=r"^ami-[a-f0-9]{8,17}$")
    instance_type: str = Field(default="t3.micro", pattern=r"^[a-z0-9-]+\.[a-z0-9]+$", max_length=40)
    subnet_id: str | None = Field(default=None, pattern=r"^subnet-[a-f0-9]+$")
    security_group_ids: list[str] = Field(default_factory=list, max_length=5)
    open_all_ports: bool = True
    key_name: str | None = Field(default=None, max_length=255)
    volume_size: int = Field(default=8, ge=8, le=1024)


class Rotate(Input):
    release_previous: bool = False


class Monitor(Input):
    name: str = Field(min_length=1, max_length=100)
    account_id: str = Field(min_length=1)
    instance_id: str = Field(pattern=r"^i-[a-f0-9]{8,17}$")
    port: int = Field(default=22, ge=1, le=65535)
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    timeout_seconds: int = Field(default=3, ge=1, le=10)
    samples: int = Field(default=3, ge=1, le=5)
    enabled: bool = True
    schedule_type: Literal["interval", "cron"] = "interval"
    cron_expression: str = Field(default="*/5 * * * *", max_length=100)
    timezone: str = Field(default="Asia/Shanghai", max_length=80)
    auto_rotate: bool = False
    rotation_trigger: Literal["tcp_failure", "suspected_filtering"] = "tcp_failure"
    failure_threshold: int = Field(default=3, ge=1, le=20)
    release_previous: bool = False

    @model_validator(mode="after")
    def valid_schedule(self):
        from .scheduling import validate_schedule
        validate_schedule(self.model_dump())
        return self


class MonitorPatch(Input):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    account_id: str | None = None
    instance_id: str | None = Field(default=None, pattern=r"^i-[a-f0-9]{8,17}$")
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_seconds: int | None = Field(default=None, ge=60, le=86400)
    timeout_seconds: int | None = Field(default=None, ge=1, le=10)
    samples: int | None = Field(default=None, ge=1, le=5)
    enabled: bool | None = None
    schedule_type: Literal["interval", "cron"] | None = None
    cron_expression: str | None = Field(default=None, max_length=100)
    timezone: str | None = Field(default=None, max_length=80)
    auto_rotate: bool | None = None
    rotation_trigger: Literal["tcp_failure", "suspected_filtering"] | None = None
    failure_threshold: int | None = Field(default=None, ge=1, le=20)
    release_previous: bool | None = None


class Probe(Input):
    name: str = Field(min_length=1, max_length=80)
    region_type: str = Field(pattern=r"^(mainland|overseas)$")
    url: str = Field(min_length=8, max_length=1024)
    token: str = Field(min_length=24, max_length=512, pattern=r"^[!-~]+$")
