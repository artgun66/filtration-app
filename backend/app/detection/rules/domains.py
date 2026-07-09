"""Rules that detect lookalike / homoglyph / punycode sender & link domains.

Scammers register domains that *look* like a trusted brand: ``paypa1.com``
(digit one), ``micros0ft.com``, IDN homoglyphs rendered via punycode
(``xn--...``), etc. We compare the sender domain and each link host against a
small set of high-value brand domains using an edit-distance ratio.
"""
from __future__ import annotations

from rapidfuzz import fuzz

from ..models import Category, Email, RuleSignal

# High-value domains attackers imitate. Kept small on purpose; expand as needed.
PROTECTED_DOMAINS = {
    "paypal.com", "apple.com", "microsoft.com", "amazon.com", "google.com",
    "netflix.com", "facebook.com", "instagram.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "citibank.com", "coinbase.com",
    "binance.com", "usps.com", "fedex.com", "ups.com", "dhl.com",
    "docusign.com", "dropbox.com", "linkedin.com", "walmart.com",
}


def _registrable(host: str) -> str:
    """Best-effort registrable domain without importing network-backed tldextract
    at rule time. Falls back to the last two labels."""
    host = (host or "").lower().strip().rstrip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _lookalike_of(domain: str) -> str | None:
    """Return the protected domain this one is impersonating, if any."""
    domain = _registrable(domain)
    if not domain or domain in PROTECTED_DOMAINS:
        return None
    for brand in PROTECTED_DOMAINS:
        # Compare the label before the TLD to avoid matching on the ".com".
        brand_label = brand.split(".")[0]
        dom_label = domain.split(".")[0]
        ratio = fuzz.ratio(dom_label, brand_label)
        # Very close but not equal -> likely a lookalike (e.g. paypa1 vs paypal).
        if 80 <= ratio < 100 and dom_label != brand_label:
            return brand
    return None


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    seen: set[str] = set()

    def emit_for(host: str, where: str) -> None:
        host = _registrable(host)
        if not host or host in seen:
            return
        seen.add(host)

        if host.startswith("xn--") or ".xn--" in host:
            signals.append(
                RuleSignal(
                    code="punycode_domain",
                    reason=f'The {where} uses a punycode/internationalized domain ("{host}"), often used to mimic real brands.',
                    weight=25,
                    category=Category.phishing,
                )
            )
        brand = _lookalike_of(host)
        if brand:
            signals.append(
                RuleSignal(
                    code="lookalike_domain",
                    reason=f'The {where} "{host}" closely imitates the legitimate domain "{brand}".',
                    weight=40,
                    category=Category.phishing,
                )
            )

    emit_for(email.from_domain, "sender domain")
    for link in email.links:
        emit_for(link.host, "linked domain")

    return signals
