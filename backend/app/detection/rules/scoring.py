"""Runs every rule module and combines the signals into a 0-100 rule score."""
from __future__ import annotations

from collections import Counter

from ..models import Category, Email, RuleSignal
from . import attachments, auth_headers, content, domains, sender, urls

# Order is cosmetic; every module always runs.
RULE_MODULES = [auth_headers, sender, domains, urls, content, attachments]


def run_rules(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    for module in RULE_MODULES:
        try:
            signals.extend(module.check(email))
        except Exception:  # noqa: BLE001 - a broken rule must never break a scan
            continue
    return signals


def combine_score(signals: list[RuleSignal]) -> float:
    """Combine weighted signals into a 0-100 score.

    We use diminishing returns rather than a raw sum so that a message with many
    small signals doesn't overflow while a single strong signal still lands hard.
    Formula: 100 * (1 - product(1 - w/100)) over all signals.
    """
    remaining = 1.0
    for s in signals:
        w = max(0, min(100, s.weight)) / 100.0
        remaining *= (1.0 - w)
    return round(100.0 * (1.0 - remaining), 1)


def dominant_category(signals: list[RuleSignal]) -> Category:
    weighted = Counter()
    for s in signals:
        if s.category != Category.unknown:
            weighted[s.category] += s.weight
    if not weighted:
        return Category.unknown
    return weighted.most_common(1)[0][0]
