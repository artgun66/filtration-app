"""Pipeline tests: triage behavior and graceful LLM degradation.

We monkeypatch the settings and the LLM classifier so no network is used.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.config import get_settings
from app.detection import pipeline
from app.detection.llm.classifier import LLMCategory, LLMRisk, LLMVerdict
from app.detection.models import Email
from app.gmail.parser import parse_eml

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _load(name: str) -> Email:
    return parse_eml((FIXTURES / name).read_bytes())


def test_high_rule_score_does_not_call_llm(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    get_settings.cache_clear()

    called = {"n": 0}

    def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("LLM should not be called for a clearly-bad email")

    monkeypatch.setattr("app.detection.llm.classifier.classify", boom)

    verdict = pipeline.analyze(_load("phishing_paypal.eml"))
    assert verdict.used_llm is False
    assert called["n"] == 0
    assert verdict.risk.value in {"high", "critical"}


def test_ambiguous_score_escalates_to_llm(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    # Force everything into the escalation band so the mocked LLM always runs.
    monkeypatch.setenv("LLM_ESCALATE_LOW", "0")
    monkeypatch.setenv("LLM_ESCALATE_HIGH", "100")
    get_settings.cache_clear()

    fake = LLMVerdict(
        risk_level=LLMRisk.high,
        category=LLMCategory.phishing,
        confidence=0.9,
        red_flags=["fake flag"],
        explanation="looks like phishing",
        recommended_action="delete it",
    )
    monkeypatch.setattr("app.detection.llm.classifier.classify", lambda *a, **k: fake)

    verdict = pipeline.analyze(_load("legit_newsletter.eml"))
    assert verdict.used_llm is True
    assert verdict.recommended_action == "delete it"
    assert "AI analysis: looks like phishing" in verdict.reasons


def test_llm_failure_degrades_to_rules(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("LLM_ESCALATE_LOW", "0")
    monkeypatch.setenv("LLM_ESCALATE_HIGH", "100")
    get_settings.cache_clear()

    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr("app.detection.llm.classifier.classify", boom)

    verdict = pipeline.analyze(_load("legit_newsletter.eml"))
    assert verdict.used_llm is False  # gracefully degraded
    assert verdict.score < 30


def test_no_api_key_skips_llm(monkeypatch):
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_ESCALATE_LOW", "0")
    monkeypatch.setenv("LLM_ESCALATE_HIGH", "100")
    get_settings.cache_clear()

    verdict = pipeline.analyze(_load("giftcard_scam.eml"))
    assert verdict.used_llm is False


def test_ollama_provider_escalates_without_api_key(monkeypatch):
    # Ollama runs locally, so no ANTHROPIC_API_KEY is required to escalate.
    monkeypatch.setenv("LLM_ENABLED", "true")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LLM_ESCALATE_LOW", "0")
    monkeypatch.setenv("LLM_ESCALATE_HIGH", "100")
    get_settings.cache_clear()

    fake = LLMVerdict(
        risk_level=LLMRisk.critical,
        category=LLMCategory.scam,
        confidence=0.8,
        red_flags=["local flag"],
        explanation="local model says scam",
        recommended_action="delete it",
    )
    monkeypatch.setattr("app.detection.llm.classifier.classify", lambda *a, **k: fake)

    verdict = pipeline.analyze(_load("legit_newsletter.eml"))
    assert verdict.used_llm is True
    assert "AI analysis: local model says scam" in verdict.reasons


def test_classify_ollama_parses_structured_output(monkeypatch):
    # The local backend must turn Ollama's JSON string into a validated LLMVerdict.
    from app.detection.llm import classifier

    payload = LLMVerdict(
        risk_level=LLMRisk.high,
        category=LLMCategory.phishing,
        confidence=0.75,
        red_flags=["spoofed sender"],
        explanation="looks like phishing",
        recommended_action="do not click",
    )

    class _FakeClient:
        def chat(self, **kwargs):
            assert kwargs["format"] == LLMVerdict.model_json_schema()
            return {"message": {"content": payload.model_dump_json()}}

    monkeypatch.setattr(classifier, "_get_ollama_client", lambda: _FakeClient())

    email = _load("legit_newsletter.eml")
    verdict = classifier._classify_ollama(email, [], get_settings())
    assert verdict.risk_level is LLMRisk.high
    assert verdict.recommended_action == "do not click"
