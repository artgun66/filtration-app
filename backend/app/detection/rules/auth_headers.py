"""Rules based on email authentication headers (SPF / DKIM / DMARC).

Gmail stamps an ``Authentication-Results`` header on inbound mail. A DMARC or
SPF *fail* on a message that claims to be from a real brand is one of the
strongest phishing signals available, and it's free to compute locally.
"""
from __future__ import annotations

import re

from ..models import Category, Email, RuleSignal


def _extract(mechanism: str, header: str) -> str | None:
    """Return the result token for a mechanism, e.g. spf -> 'pass'/'fail'."""
    m = re.search(rf"\b{mechanism}=([a-zA-Z]+)", header)
    return m.group(1).lower() if m else None


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    header = (email.auth_results or "").lower()
    if not header and email.received_spf:
        header = email.received_spf.lower()

    if not header:
        # No auth header at all is mildly suspicious for a modern provider,
        # but common enough (internal/forwarded mail) that we keep it low.
        signals.append(
            RuleSignal(
                code="auth_missing",
                reason="No email-authentication results were present on this message.",
                weight=5,
            )
        )
        return signals

    dmarc = _extract("dmarc", header)
    spf = _extract("spf", header)
    dkim = _extract("dkim", header)

    if dmarc == "fail":
        signals.append(
            RuleSignal(
                code="dmarc_fail",
                reason="The message failed DMARC authentication, meaning the sender could not be verified as who they claim to be.",
                weight=40,
                category=Category.phishing,
            )
        )
    if spf == "fail" or spf == "softfail":
        signals.append(
            RuleSignal(
                code="spf_fail",
                reason="The message failed SPF authentication (it was not sent from an authorized mail server for that domain).",
                weight=25,
                category=Category.phishing,
            )
        )
    if dkim == "fail":
        signals.append(
            RuleSignal(
                code="dkim_fail",
                reason="The message failed DKIM signature verification (its contents may have been tampered with or forged).",
                weight=20,
                category=Category.phishing,
            )
        )

    return signals
