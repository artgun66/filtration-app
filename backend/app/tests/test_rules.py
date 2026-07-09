"""Unit tests for the rules engine, driven by .eml fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.detection.models import Email, Link
from app.detection.rules import scoring
from app.gmail.parser import parse_eml

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> Email:
    return parse_eml((FIXTURES / name).read_bytes())


def _codes(email: Email) -> set[str]:
    return {s.code for s in scoring.run_rules(email)}


def test_phishing_paypal_triggers_strong_signals():
    email = _load("phishing_paypal.eml")
    codes = _codes(email)
    # Auth failures, lookalike domain, display-name mismatch, reply-to mismatch, IP link.
    assert "dmarc_fail" in codes
    assert "spf_fail" in codes
    assert "reply_to_mismatch" in codes
    assert "ip_url" in codes
    assert {"lookalike_domain", "display_name_domain_mismatch"} & codes
    score = scoring.combine_score(scoring.run_rules(email))
    assert score >= 65, score


def test_legit_newsletter_scores_low():
    email = _load("legit_newsletter.eml")
    score = scoring.combine_score(scoring.run_rules(email))
    assert score < 30, (score, _codes(email))


def test_giftcard_scam_flags_payment_and_urgency():
    # A BEC/gift-card scam that passes SPF/DKIM (real gmail) — the tell is the
    # content, not the headers.
    email = _load("giftcard_scam.eml")
    codes = _codes(email)
    assert "payment_scam_language" in codes
    assert "urgency_language" in codes
    score = scoring.combine_score(scoring.run_rules(email))
    assert score >= 30, (score, codes)


def test_link_text_mismatch_detected():
    email = Email(
        from_address="mail@shop.com",
        from_domain="shop.com",
        text_body="click",
        links=[Link(text="https://paypal.com/account", href="https://evil.example.org/x", host="evil.example.org")],
    )
    assert "link_text_mismatch" in _codes(email)


def test_dangerous_attachment_detected():
    from app.detection.models import Attachment

    email = Email(from_domain="x.com", attachments=[Attachment(filename="invoice.pdf.exe")])
    codes = _codes(email)
    assert "double_extension" in codes or "dangerous_attachment" in codes


def test_combine_score_bounds():
    from app.detection.models import RuleSignal

    assert scoring.combine_score([]) == 0.0
    huge = [RuleSignal(code="x", reason="r", weight=90) for _ in range(5)]
    assert scoring.combine_score(huge) <= 100.0
