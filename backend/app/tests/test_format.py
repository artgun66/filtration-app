"""Tests for display formatting helpers."""
from __future__ import annotations

from app.config import get_settings
from app.web.format import format_email_date


def test_utc_header_converts_to_pacific(monkeypatch):
    monkeypatch.setenv("DISPLAY_TIMEZONE", "America/Los_Angeles")
    get_settings.cache_clear()
    # 23:22 UTC in July is PDT (-7) -> 16:22 local.
    out = format_email_date("Wed, 08 Jul 2026 23:22:45 +0000")
    assert out == "Jul 8, 2026 · 4:22 PM PDT"
    get_settings.cache_clear()


def test_midnight_utc_rolls_back_a_day_in_pacific(monkeypatch):
    monkeypatch.setenv("DISPLAY_TIMEZONE", "America/Los_Angeles")
    get_settings.cache_clear()
    # 00:34 UTC Jul 9 is still the evening of Jul 8 on the US west coast.
    out = format_email_date("Thu, 09 Jul 2026 00:34:24 +0000")
    assert out == "Jul 8, 2026 · 5:34 PM PDT"
    get_settings.cache_clear()


def test_garbage_input_falls_back_to_raw():
    assert format_email_date("not a date") == "not a date"
    assert format_email_date("") == ""
