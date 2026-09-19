"""
Small helpers for working with time.

There is exactly one rule in this project: every datetime we handle is
timezone-aware and in UTC. Never naive, never local time.

Why be strict about this?
  * Comparing a naive datetime with an aware one raises TypeError in Python.
  * "Expires at 5pm" is meaningless without a timezone, and your laptop, the
    test runner and the Render server are not in the same one.

PostgreSQL stores these properly in a `TIMESTAMP WITH TIME ZONE` column.
SQLite (which the test suite can fall back on) has no real timezone support
and hands back naive values, so `ensure_utc` re-attaches UTC on the way out.
"""

from datetime import datetime, timedelta, timezone


def utc_now() -> datetime:
    """The current time, timezone-aware, in UTC."""
    return datetime.now(timezone.utc)


def utc_in(minutes: int) -> datetime:
    """The time `minutes` from now, timezone-aware, in UTC."""
    return utc_now() + timedelta(minutes=minutes)


def ensure_utc(value: datetime | None) -> datetime | None:
    """
    Guarantee that a datetime read back from the database is UTC-aware.

    PostgreSQL returns aware datetimes and this is a no-op. SQLite returns
    naive ones -- but we only ever *wrote* UTC into it, so attaching UTC is
    the correct interpretation rather than a guess.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
