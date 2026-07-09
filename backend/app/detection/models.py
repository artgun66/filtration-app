"""Core data models shared across the detection pipeline.

These are deliberately provider-agnostic: the Gmail parser produces an ``Email``,
the rules engine produces ``RuleSignal`` objects, and the pipeline produces a
``Verdict``. Nothing here imports Gmail or Anthropic, so the rules engine can be
unit-tested from ``.eml`` fixtures with zero network access.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score >= 85:
            return cls.critical
        if score >= 65:
            return cls.high
        if score >= 40:
            return cls.medium
        if score >= 15:
            return cls.low
        return cls.safe


class Category(str, Enum):
    legitimate = "legitimate"
    spam = "spam"
    phishing = "phishing"
    scam = "scam"
    bec = "bec"  # business email compromise
    malware = "malware"
    unknown = "unknown"


class Link(BaseModel):
    """A hyperlink extracted from the email body."""

    text: str = ""          # anchor / display text
    href: str = ""          # actual URL
    host: str = ""          # registered domain of href (e.g. "example.com")


class Attachment(BaseModel):
    filename: str = ""
    mime_type: str = ""
    size: int = 0


class Email(BaseModel):
    """Normalized representation of a single message.

    Produced by ``gmail/parser.py`` but constructable directly from a raw
    ``.eml`` for tests.
    """

    message_id: str = ""
    from_name: str = ""             # display name in the From header
    from_address: str = ""          # bare address, e.g. "a@b.com"
    from_domain: str = ""           # registered domain of the From address
    reply_to: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    text_body: str = ""             # plain-text body (HTML stripped if needed)
    html_body: str = ""             # raw HTML body if present
    links: list[Link] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    # Raw values of relevant auth headers, lower-cased keys.
    auth_results: str = ""          # value of Authentication-Results header
    received_spf: str = ""          # value of Received-SPF header


class RuleSignal(BaseModel):
    """A single triggered detection heuristic.

    ``weight`` is the points this signal contributes toward the 0-100 rule
    score. ``code`` is a stable identifier for tests; ``reason`` is the
    human-readable explanation shown to the user.
    """

    code: str
    reason: str
    weight: int
    category: Category = Category.unknown


class Verdict(BaseModel):
    """Final assessment of an email, from rules and (optionally) the LLM."""

    score: float = 0.0                     # 0-100
    risk: RiskLevel = RiskLevel.safe
    category: Category = Category.unknown
    reasons: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    used_llm: bool = False
    llm_confidence: float | None = None    # 0-1 if the LLM ran
