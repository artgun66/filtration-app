"""LLM-based fraud classifier.

Two interchangeable backends produce the same validated ``LLMVerdict``:

* ``anthropic`` — the paid Claude API via ``client.messages.parse``. Haiku 4.5
  (the default) supports structured outputs; it does not support adaptive
  thinking / effort, so we deliberately omit those parameters.
* ``ollama`` — a model running locally (e.g. Gemma), completely free and fully
  private (nothing leaves the machine). We pass the ``LLMVerdict`` JSON schema
  as Ollama's ``format`` so the local model is likewise forced to return valid,
  schema-conforming JSON.

Which one runs is chosen by ``settings.llm_provider``. The rest of the pipeline
neither knows nor cares which backend answered.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from ...config import get_settings
from ..models import Email, RuleSignal
from . import prompts


class LLMRisk(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LLMCategory(str, Enum):
    legitimate = "legitimate"
    spam = "spam"
    phishing = "phishing"
    scam = "scam"
    bec = "bec"
    malware = "malware"
    unknown = "unknown"


class LLMVerdict(BaseModel):
    """Structured output schema the model must return."""

    risk_level: LLMRisk
    category: LLMCategory
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 confidence in this assessment")
    red_flags: list[str] = Field(default_factory=list, description="Concrete, user-readable warning signs")
    explanation: str = Field(description="One or two sentence plain-language explanation")
    recommended_action: str = Field(description="What the user should do")


# Lazily-created module-level clients so tests can run without an API key and so
# the optional SDKs are only imported when their provider is actually used.
_anthropic_client = None
_ollama_client = None


def _get_anthropic_client():
    global _anthropic_client
    if _anthropic_client is None:
        import anthropic  # imported lazily so the package works offline

        settings = get_settings()
        _anthropic_client = anthropic.Anthropic(api_key=settings.anthropic_api_key or None)
    return _anthropic_client


def _get_ollama_client():
    global _ollama_client
    if _ollama_client is None:
        from ollama import Client  # imported lazily; only needed for local mode

        settings = get_settings()
        _ollama_client = Client(host=settings.ollama_base_url)
    return _ollama_client


def classify(email: Email, signals: list[RuleSignal]) -> LLMVerdict:
    """Return a validated verdict for a sanitized email.

    Dispatches to the configured backend. Raises on API/network errors; the
    caller (pipeline) decides how to degrade.
    """
    settings = get_settings()
    if settings.llm_provider == "ollama":
        return _classify_ollama(email, signals, settings)
    return _classify_anthropic(email, signals, settings)


def _classify_anthropic(email: Email, signals: list[RuleSignal], settings) -> LLMVerdict:
    client = _get_anthropic_client()
    response = client.messages.parse(
        model=settings.llm_model,
        max_tokens=1024,
        system=prompts.SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": prompts.build_user_content(
                    email, signals, settings.llm_max_body_chars
                ),
            }
        ],
        output_format=LLMVerdict,
    )
    return response.parsed_output


def _classify_ollama(email: Email, signals: list[RuleSignal], settings) -> LLMVerdict:
    """Classify with a local Ollama model, forcing schema-valid JSON output.

    Passing ``LLMVerdict.model_json_schema()`` as ``format`` makes Ollama
    constrain generation to the schema, so we get the same structured object we
    get from Claude. temperature=0 keeps verdicts stable across runs.
    """
    client = _get_ollama_client()
    response = client.chat(
        model=settings.ollama_model,
        messages=[
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": prompts.build_user_content(
                    email, signals, settings.llm_max_body_chars
                ),
            },
        ],
        format=LLMVerdict.model_json_schema(),
        options={"temperature": 0},
    )
    return LLMVerdict.model_validate_json(response["message"]["content"])
