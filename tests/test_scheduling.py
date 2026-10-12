from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from app.scheduling import next_run, validate_schedule


def epoch(value, zone="Asia/Shanghai"):
    return datetime.fromisoformat(value).replace(tzinfo=ZoneInfo(zone)).timestamp()


def cron(expression="*/5 * * * *", zone="Asia/Shanghai"):
    return {"schedule_type": "cron", "cron_expression": expression, "timezone": zone}


@pytest.mark.parametrize("zone", ["Asia/Shanghai", "UTC"])
def test_every_five_minutes_uses_wall_clock_boundaries(zone):
    record = cron(zone=zone)
    validate_schedule(record)
    assert next_run(record, epoch("2026-10-13T10:02:42", zone)) == epoch("2026-10-13T10:05:00", zone)
    assert next_run(record, epoch("2026-10-13T10:05:00", zone)) == epoch("2026-10-13T10:10:00", zone)
    assert next_run(record, epoch("2026-10-13T10:04:59.999999", zone)) == epoch("2026-10-13T10:05:00", zone)


def test_calendar_timezone_changes_daily_absolute_time():
    base = epoch("2026-10-13T00:30:00", "UTC")
    assert next_run(cron("0 9 * * *", "Asia/Shanghai"), base) == epoch("2026-10-13T01:00:00", "UTC")
    assert next_run(cron("0 9 * * *", "UTC"), base) == epoch("2026-10-13T09:00:00", "UTC")


def test_named_weekday_and_month_are_case_insensitive():
    record = cron("30 9 * OCT MON-FRI")
    validate_schedule(record)
    assert next_run(record, epoch("2026-10-16T09:30:00")) == epoch("2026-10-19T09:30:00")


@pytest.mark.parametrize("weekday", ["0", "7", "sun"])
def test_sunday_aliases(weekday):
    assert next_run(cron(f"0 0 * * {weekday}"), epoch("2026-10-13T12:00:00")) == epoch("2026-10-18T00:00:00")


def test_day_of_month_and_weekday_are_or_not_and():
    record = cron("0 9 1 * mon")
    base = epoch("2026-10-31T10:00:00")
    first = next_run(record, base)
    assert first == epoch("2026-11-01T09:00:00")  # Sunday, matches day of month.
    assert next_run(record, first) == epoch("2026-11-02T09:00:00")  # Monday, matches weekday.


def test_restricted_weekday_can_make_impossible_dom_valid():
    record = cron("0 9 31 feb mon")
    validate_schedule(record)
    assert next_run(record, epoch("2026-02-01T00:00:00")) == epoch("2026-02-02T09:00:00")


def test_leap_day_and_eight_year_century_gap():
    record = cron("0 0 29 2 *")
    validate_schedule(record)
    assert next_run(record, epoch("2026-10-13T00:00:00")) == epoch("2028-02-29T00:00:00")
    assert next_run(record, epoch("2096-02-29T00:00:00")) == epoch("2104-02-29T00:00:00")


def test_month_lists_allow_possible_subset():
    record = cron("0 0 31 feb,mar *")
    validate_schedule(record)
    assert next_run(record, epoch("2026-02-01T00:00:00")) == epoch("2026-03-31T00:00:00")


@pytest.mark.parametrize("expression", ["0 0 31 2 *", "0 0 31 4,6,9,11 *", "0 0 30 feb *"])
def test_impossible_dates_are_rejected(expression):
    with pytest.raises(ValueError, match="没有执行时间"):
        validate_schedule(cron(expression))


@pytest.mark.parametrize("expression", [
    "", "@hourly", "* * * *", "* * * * * *", "0 0 * * * 0 2027",
    "60 * * * *", "0 24 * * *", "0 0 0 * *", "0 0 * 13 *", "0 0 * * 8",
    "*/0 * * * *", "0 0 * * 5-1", "0 23-1 * * *", "0 0 * * mon#2",
    "0 0 L * *", "0 0 2W * *", "0 0 * * ?", "H * * * *", "R * * * *",
    "0 0 *-* * *", "0 0 * foo *", "0 0 * * jan", "0 0 * * mon,,fri",
    "0;reboot * * * *", "９ * * * *", "0 " * 100,
])
def test_invalid_or_nonstandard_cron_is_rejected(expression):
    with pytest.raises(ValueError):
        validate_schedule(cron(expression))


@pytest.mark.parametrize("zone", ["", "Imaginary/Region", "../etc/passwd", "/etc/passwd", None])
def test_invalid_timezone_is_rejected(zone):
    with pytest.raises(ValueError, match="时区"):
        validate_schedule(cron(zone=zone))


def test_old_interval_record_retains_existing_semantics():
    record = {"interval_seconds": 73}
    validate_schedule(record)
    assert record == {"interval_seconds": 73}
    assert next_run(record, 1000.5) == 1073.5
    assert next_run({}, 1000) == 1300


@pytest.mark.parametrize("value", [0, 59, 86401, True, 60.5, "300", None])
def test_invalid_interval_is_rejected(value):
    with pytest.raises(ValueError, match="间隔"):
        validate_schedule({"interval_seconds": value})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), "1000", None, True])
def test_invalid_timestamp_is_rejected(value):
    with pytest.raises(ValueError, match="时间戳"):
        next_run(cron(), value)


def test_unknown_schedule_type_rejected():
    with pytest.raises(ValueError, match="调度类型"):
        validate_schedule({"schedule_type": "unknown"})


def test_default_cron_fields():
    assert next_run({"schedule_type": "cron"}, epoch("2026-10-13T10:01:00")) == epoch("2026-10-13T10:05:00")


@pytest.mark.parametrize("previous,expected,hours", [
    ("2026-03-07T09:00:00", "2026-03-08T09:00:00", 23),
    ("2026-10-31T09:00:00", "2026-11-01T09:00:00", 25),
])
def test_daily_schedule_preserves_wall_time_across_dst(previous, expected, hours):
    zone = "America/New_York"
    base = epoch(previous, zone)
    result = next_run(cron("0 9 * * *", zone), base)
    assert result == epoch(expected, zone)
    assert result - base == hours * 3600


def test_dst_spring_gap_advances_to_first_existing_local_time():
    zone = "America/New_York"
    record = cron("30 2 * * *", zone)
    result = next_run(record, epoch("2026-03-07T02:30:00", zone))
    assert result == epoch("2026-03-08T03:00:00", zone)
    assert next_run(record, result) == epoch("2026-03-09T02:30:00", zone)


def test_dst_fall_fold_runs_at_each_distinct_instant_without_looping():
    zone = "America/New_York"
    record = cron("30 1 * * *", zone)
    first = next_run(record, epoch("2026-10-31T01:30:00", zone))
    second = next_run(record, first)
    assert first == epoch("2026-11-01T01:30:00", zone)
    assert second == first + 3600
    assert datetime.fromtimestamp(second, ZoneInfo(zone)).fold == 1
    assert next_run(record, second) == epoch("2026-11-02T01:30:00", zone)
