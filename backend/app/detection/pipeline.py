"""The detection pipeline: rules -> triage -> (optional) LLM -> Verdict.

``analyze(email)`` is the single entry point used by the on-demand scan today and
by the Phase-2 continuous-monitoring worker later. It is deliberately dependency-
light: rules always run locally; the LLM is only consulted for the ambiguous
mid-band, and any LLM failure degrades gracefully to a rules-only verdict.
"""
from __future__ import annotations

import logging

from ..config import get_settings
from .models import Category, Email, RiskLevel, Verdict
from .rules import scoring

logger = logging.getLogger(__name__)

# Map the LLM's risk label to a numeric score used to blend with the rule score.
_LLM_RISK_SCORE = {
    "safe": 5.0,
    "low": 25.0,
    "medium": 55.0,
    "high": 80.0,
    "critical": 95.0,
}


def analyze(email: Email) -> Verdict:
    settings = get_settings()

    # 1. Rules always run (free, local).
    signals = scoring.run_rules(email)
    rule_score = scoring.combine_score(signals)
    rule_category = scoring.dominant_category(signals)
    reasons = [s.reason for s in signals]

    # 2. Triage: escalate to the LLM only for the ambiguous mid-band.
    #    The chosen backend must actually be usable: Anthropic needs an API key;
    #    Ollama runs locally and needs none.
    if settings.llm_provider == "ollama":
        backend_ready = True
    else:
        backend_ready = bool(settings.anthropic_api_key)
    should_escalate = (
        settings.llm_enabled
        and backend_ready
        and settings.llm_escalate_low <= rule_score <= settings.llm_escalate_high
    )

    if not should_escalate:
        return Verdict(
            score=rule_score,
            risk=RiskLevel.from_score(rule_score),
            category=rule_category,
            reasons=reasons,
            recommended_action=_default_action(rule_score),
            used_llm=False,
        )

    # 3. LLM classification for the ambiguous band.
    try:
        from .llm import classifier

        llm = classifier.classify(email, signals)
    except Exception as exc:  # noqa: BLE001 - never let an LLM error fail a scan
        logger.warning("LLM classification failed, falling back to rules: %s", exc)
        return Verdict(
            score=rule_score,
            risk=RiskLevel.from_score(rule_score),
            category=rule_category,
            reasons=reasons,
            recommended_action=_default_action(rule_score),
            used_llm=False,
        )

    # 4. Combine: take the higher of the rule score and the LLM-implied score so
    #    a strong LLM signal is never diluted by a quiet rules pass.
    llm_score = _LLM_RISK_SCORE.get(llm.risk_level.value, rule_score)
    final_score = max(rule_score, llm_score)
    combined_reasons = reasons + [f"AI analysis: {llm.explanation}"] + list(llm.red_flags)

    try:
        category = Category(llm.category.value)
    except ValueError:
        category = rule_category

    return Verdict(
        score=round(final_score, 1),
        risk=RiskLevel.from_score(final_score),
        category=category,
        reasons=combined_reasons,
        recommended_action=llm.recommended_action or _default_action(final_score),
        used_llm=True,
        llm_confidence=llm.confidence,
    )


def _default_action(score: float) -> str:
    if score >= 65:
        return "Do not click any links or reply. Delete the message, or verify with the sender through a channel you trust."
    if score >= 40:
        return "Be cautious. Do not enter credentials or payment details; verify the sender before acting."
    if score >= 15:
        return "Probably fine, but stay alert for anything unexpected."
    return "No obvious signs of fraud were found."
