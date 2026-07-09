"""Rules based on the hyperlinks in the email body."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..models import Category, Email, RuleSignal

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "benchurl.com",
}

# TLDs disproportionately used for abuse/free registration.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "club", "click", "link", "gq", "cf", "tk",
    "ml", "ga", "work", "rest", "fit", "loan", "country", "kim", "review",
}

_HOST_RE = re.compile(r"https?://([^/\s:]+)", re.I)


def _host(url: str) -> str:
    try:
        netloc = urlparse(url).netloc or ""
    except ValueError:
        m = _HOST_RE.search(url or "")
        netloc = m.group(1) if m else ""
    return netloc.split("@")[-1].split(":")[0].lower()


def _registrable(host: str) -> str:
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    sender_reg = _registrable((email.from_domain or "").lower())
    link_regs: set[str] = set()

    for link in email.links:
        host = link.host or _host(link.href)
        if not host:
            continue
        reg = _registrable(host)
        link_regs.add(reg)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""

        # 1) IP-literal URL.
        if _is_ip(host):
            signals.append(
                RuleSignal(
                    code="ip_url",
                    reason=f"A link points directly to an IP address ({host}) instead of a domain name.",
                    weight=30,
                    category=Category.phishing,
                )
            )

        # 2) Link shortener hides the true destination.
        if reg in URL_SHORTENERS:
            signals.append(
                RuleSignal(
                    code="url_shortener",
                    reason=f"A link uses a URL shortener ({reg}) that hides its real destination.",
                    weight=15,
                )
            )

        # 3) Suspicious TLD.
        if tld in SUSPICIOUS_TLDS:
            signals.append(
                RuleSignal(
                    code="suspicious_tld",
                    reason=f'A link uses the ".{tld}" domain ending, which is frequently abused for scams.',
                    weight=15,
                )
            )

        # 4) Anchor text shows one domain but href goes elsewhere.
        text = (link.text or "").strip()
        text_host = _host(text) if "http" in text.lower() else ""
        if text_host and _registrable(text_host) != reg:
            signals.append(
                RuleSignal(
                    code="link_text_mismatch",
                    reason=f'A link displays "{_registrable(text_host)}" but actually goes to "{reg}".',
                    weight=30,
                    category=Category.phishing,
                )
            )

    # 5) Excessive number of links.
    if len(email.links) >= 15:
        signals.append(
            RuleSignal(
                code="many_links",
                reason=f"The message contains an unusually large number of links ({len(email.links)}).",
                weight=10,
                category=Category.spam,
            )
        )

    # 6) No link shares the sender's domain (all links go off-brand).
    if sender_reg and link_regs and sender_reg not in link_regs and len(link_regs) >= 1:
        signals.append(
            RuleSignal(
                code="offdomain_links",
                reason=f'None of the links go to the sender\'s own domain ("{sender_reg}").',
                weight=10,
            )
        )

    return signals
