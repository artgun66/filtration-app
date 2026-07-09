"""Rules based on the language / content of the message body and subject.

These catch social-engineering patterns: manufactured urgency, credential and
payment requests, and classic scam lures (gift cards, wire transfers, lottery
wins). They are intentionally conservative in weight because legitimate mail can
use similar language; the LLM stage resolves the ambiguous middle band.
"""
from __future__ import annotations

import re

from ..models import Category, Email, RuleSignal

URGENCY_PATTERNS = [
    r"urgent", r"immediat(e|ely)", r"act now", r"as soon as possible",
    r"within \d+ (hours|minutes)", r"final (notice|warning|reminder)",
    r"your account will be (suspended|closed|deactivated|terminated)",
    r"failure to (respond|act|comply)", r"last chance", r"expires? (today|soon)",
    r"limited time",
]

CREDENTIAL_PATTERNS = [
    r"verify your (account|identity|password|information)",
    r"confirm your (account|identity|password|details|payment)",
    r"update your (payment|billing|account|password)",
    r"log ?in to (verify|confirm|secure|restore)",
    r"unusual (activity|sign[- ]?in|login)", r"suspicious (activity|login|sign)",
    r"re-?activate your account", r"unlock your account",
    r"validate your (account|card|information)",
]

PAYMENT_SCAM_PATTERNS = [
    r"gift ?cards?", r"itunes card", r"google play card", r"steam card",
    r"wire transfer", r"western union", r"moneygram", r"bitcoin", r"crypto",
    r"cryptocurrency", r"bank transfer", r"routing number", r"ssn",
    r"social security number", r"you('?ve| have) won", r"lottery",
    r"inheritance", r"beneficiary", r"prince", r"tax refund", r"overpayment",
    r"invoice attached", r"payment is overdue",
]


def _count(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        if re.search(p, text, re.I):
            hits.append(p)
    return hits


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    text = f"{email.subject}\n{email.text_body}"

    urgency = _count(URGENCY_PATTERNS, text)
    if urgency:
        signals.append(
            RuleSignal(
                code="urgency_language",
                reason="The message uses pressure or urgency language to make you act quickly without thinking.",
                weight=15 if len(urgency) == 1 else 22,
                category=Category.scam,
            )
        )

    cred = _count(CREDENTIAL_PATTERNS, text)
    if cred:
        signals.append(
            RuleSignal(
                code="credential_request",
                reason="The message asks you to verify, confirm, or update account credentials or payment details.",
                weight=25,
                category=Category.phishing,
            )
        )

    pay = _count(PAYMENT_SCAM_PATTERNS, text)
    if pay:
        signals.append(
            RuleSignal(
                code="payment_scam_language",
                reason="The message references money-transfer or gift-card / prize patterns commonly used in scams.",
                weight=25,
                category=Category.scam,
            )
        )

    return signals
