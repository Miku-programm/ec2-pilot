"""Bounded five-field cron scheduling with explicit IANA time zones."""

from collections.abc import Mapping
from datetime import datetime
import math
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import CroniterBadCronError, CroniterBadDateError, croniter


DEFAULT_TIMEZONE = "Asia/Shanghai"
DEFAULT_CRON = "*/5 * * * *"
MAX_SEARCH_YEARS = 8  # Includes the eight-year leap-day gap around 2100.
_MONTHS = dict(zip("jan feb mar apr may jun jul aug sep oct nov dec".split(), range(1, 13)))
_DAYS = dict(zip("sun mon tue wed thu fri sat".split(), range(7)))
_FIELDS = ((0, 59, {}), (0, 23, {}), (1, 31, {}), (1, 12, _MONTHS), (0, 7, _DAYS))
_TERM = re.compile(r"(?P<start>\*|[0-9]{1,2}|[a-z]{3})(?:-(?P<end>[0-9]{1,2}|[a-z]{3}))?(?:/(?P<step>[0-9]{1,3}))?", re.ASCII)


def _cron_expression(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128 or len(value.split()) != 5:
        raise ValueError("Cron 必须是五段：分 时 日 月 星期，例如 */5 * * * *。")
    fields = value.lower().split()
    for field, (minimum, maximum, names) in zip(fields, _FIELDS):
        for term in field.split(","):
            match = _TERM.fullmatch(term)
            if match is None:
                raise ValueError("Cron 仅支持数字、月/星期缩写、*、逗号、递增范围和 / 步长。")
            start, end, step = match.group("start", "end", "step")
            if start == "*" and end is not None:
                raise ValueError("Cron 范围不能以 * 开始。")
            if step is not None and int(step) == 0:
                raise ValueError("Cron 步长必须大于零。")

            def number(atom: str) -> int:
                parsed = names.get(atom) if atom.isalpha() else int(atom)
                if parsed is None or not minimum <= parsed <= maximum:
                    raise ValueError("Cron 字段超出允许范围，或月份/星期缩写不正确。")
                return parsed

            first = minimum if start == "*" else number(start)
            if end is not None and number(end) < first:
                raise ValueError("Cron 范围的结束值必须大于或等于开始值。")
    return " ".join(fields)


def _configuration(record: Mapping) -> tuple[str, str | int, ZoneInfo]:
    schedule_type = record.get("schedule_type", "interval")
    if schedule_type not in ("cron", "interval"):
        raise ValueError("调度类型必须是 cron 或 interval。")
    zone_name = record.get("timezone", DEFAULT_TIMEZONE)
    if not isinstance(zone_name, str) or not 1 <= len(zone_name) <= 64:
        raise ValueError("时区必须是有效的 IANA 名称，例如 Asia/Shanghai。")
    try:
        zone = ZoneInfo(zone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("时区不存在，请使用 IANA 名称，例如 Asia/Shanghai。") from exc
    if schedule_type == "interval":
        interval = record.get("interval_seconds", 300)
        if isinstance(interval, bool) or not isinstance(interval, int) or not 60 <= interval <= 86400:
            raise ValueError("检测间隔必须是 60 至 86400 秒的整数。")
        return schedule_type, interval, zone
    return schedule_type, _cron_expression(record.get("cron_expression", DEFAULT_CRON)), zone


def _next_cron(expression: str, timestamp: float, zone: ZoneInfo) -> float:
    try:
        base = datetime.fromtimestamp(timestamp, zone)
        fields = expression.split()
        expressions = [expression]
        if fields[2] != "*" and fields[4] != "*":
            # Calculate each OR branch independently: an impossible DOM branch
            # must not suppress valid weekdays (e.g. February 31 OR Monday).
            expressions = [
                " ".join([*fields[:4], "*"]),
                " ".join([*fields[:2], "*", *fields[3:]]),
            ]
        candidates = []
        for candidate in expressions:
            try:
                candidates.append(croniter(
                    candidate, base, day_or=True,
                    max_years_between_matches=MAX_SEARCH_YEARS,
                    implement_cron_bug=False,
                ).get_next(float))
            except CroniterBadDateError:
                continue
        if not candidates:
            raise CroniterBadDateError("No matching date within the bounded horizon")
        result = min(candidates)
    except CroniterBadDateError as exc:
        raise ValueError("Cron 在未来八年内没有执行时间，请检查日期与月份组合。") from exc
    except (CroniterBadCronError, ValueError, OverflowError, OSError) as exc:
        raise ValueError("Cron 无法计算下次执行时间，请检查表达式、日期和时区。") from exc
    if not math.isfinite(result) or result <= timestamp:
        raise ValueError("Cron 未能得到严格晚于当前时间的执行时间。")
    return result


def validate_schedule(record: Mapping) -> None:
    """Validate without mutating a record; legacy records remain interval based.

    A bounded trial rejects impossible dates while retaining DOM/DOW OR rules.
    In particular, February 31 OR Monday is a valid February-Monday schedule.
    """
    schedule_type, value, zone = _configuration(record)
    if schedule_type == "cron":
        _next_cron(value, datetime(2024, 1, 1, tzinfo=zone).timestamp(), zone)


def next_run(record: Mapping, timestamp: float) -> float:
    """Return the next Unix timestamp, strictly after the supplied timestamp.

    Cron uses calendar boundaries in the configured time zone. Missed runs are
    skipped by callers supplying the current time after a restart/completion.
    """
    if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
        raise ValueError("基准时间必须是有效的 Unix 时间戳。")
    schedule_type, value, zone = _configuration(record)
    if schedule_type == "cron":
        return _next_cron(value, timestamp, zone)
    result = float(timestamp + value)
    if not math.isfinite(result) or result <= timestamp:
        raise ValueError("基准时间超出可计算范围。")
    return result
