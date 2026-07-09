"""Display formatting helpers for the web layer."""
from __future__ import annotations

from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..config import get_settings


def format_email_date(raw: str) -> str:
    """Turn a raw RFC-2822 email date header into a friendly local-time string.

    e.g. "Wed, 08 Jul 2026 23:22:45 +0000" -> "Jul 8, 2026 · 4:22 PM PDT"
    (in America/Los_Angeles). Falls back to the raw string if it can't parse.
    """
    if not raw:
        return ""
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return raw
    if dt is None:
        return raw
    if dt.tzinfo is None:  # header lacked an offset; assume UTC
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    try:
        tz = ZoneInfo(get_settings().display_timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return raw

    local = dt.astimezone(tz)
    hour12 = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    tzabbr = local.strftime("%Z")
    return f"{local:%b} {local.day}, {local.year} · {hour12}:{local:%M} {ampm} {tzabbr}"
