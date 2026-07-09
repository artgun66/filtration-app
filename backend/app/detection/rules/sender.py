"""Rules based on the sender identity (From / Reply-To)."""
from __future__ import annotations

import re

from ..models import Category, Email, RuleSignal

# Free consumer mail providers. A message whose display name impersonates a brand
# but is sent from one of these is a classic scam pattern.
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "icloud.com", "protonmail.com",
    "proton.me", "mail.com", "gmx.com", "zoho.com", "yandex.com",
}

# Brand / authority names that scammers frequently impersonate.
IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "amazon", "google", "netflix", "facebook",
    "instagram", "bank", "chase", "wells fargo", "bank of america", "citibank",
    "coinbase", "binance", "irs", "usps", "fedex", "ups", "dhl", "docusign",
    "dropbox", "linkedin", "walmart", "costco", "geek squad", "norton",
    "mcafee", "social security", "hmrc", "revenue",
}

_EMAIL_RE = re.compile(r"[\w.+-]+@([\w.-]+)")


def _domain_of(address: str) -> str:
    m = _EMAIL_RE.search(address or "")
    return m.group(1).lower() if m else ""


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    name = (email.from_name or "").lower()
    from_domain = (email.from_domain or _domain_of(email.from_address)).lower()

    # 1) Display name contains a domain/email that differs from the real one.
    #    e.g. From: "security@paypal.com" <random@scam.ru>
    name_domain = _domain_of(name)
    if name_domain and from_domain and name_domain != from_domain:
        signals.append(
            RuleSignal(
                code="display_name_domain_mismatch",
                reason=f'The sender name shows "{name_domain}" but the message actually comes from "{from_domain}".',
                weight=35,
                category=Category.phishing,
            )
        )

    # 2) Display name impersonates a well-known brand while sent from freemail.
    if from_domain in FREEMAIL_DOMAINS:
        for brand in IMPERSONATED_BRANDS:
            if brand in name:
                signals.append(
                    RuleSignal(
                        code="brand_from_freemail",
                        reason=f'The sender claims to be "{brand}" but is emailing from a free personal account ({from_domain}).',
                        weight=30,
                        category=Category.scam,
                    )
                )
                break

    # 3) Reply-To points to a different domain than From (reply hijacking).
    reply_domain = _domain_of(email.reply_to)
    if reply_domain and from_domain and reply_domain != from_domain:
        signals.append(
            RuleSignal(
                code="reply_to_mismatch",
                reason=f'Replies would go to a different domain ("{reply_domain}") than the sender ("{from_domain}").',
                weight=20,
                category=Category.phishing,
            )
        )

    return signals
