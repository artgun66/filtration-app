"""Convert a Gmail API message resource (format=full) into a normalized Email.

Kept independent of the Gmail client so it can be unit-tested against captured
JSON fixtures or hand-built dicts. Also exposes ``parse_eml`` for tests that work
from raw ``.eml`` files.
"""
from __future__ import annotations

import base64
import re
from email import message_from_bytes, message_from_string
from email.message import Message as PyMessage
from email.utils import parseaddr

from bs4 import BeautifulSoup

from ..detection.models import Attachment, Email, Link

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)


def _registrable(host: str) -> str:
    host = (host or "").lower().strip().rstrip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _host_of(url: str) -> str:
    from urllib.parse import urlparse

    try:
        netloc = urlparse(url).netloc
    except ValueError:
        netloc = ""
    return netloc.split("@")[-1].split(":")[0].lower()


def _links_from_html(html: str) -> list[Link]:
    links: list[Link] = []
    if not html:
        return links
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href.lower().startswith("http"):
            continue
        links.append(Link(text=a.get_text(strip=True), href=href, host=_host_of(href)))
    return links


def _links_from_text(text: str) -> list[Link]:
    links: list[Link] = []
    for m in _URL_RE.finditer(text or ""):
        href = m.group(0).rstrip(".,);]")
        links.append(Link(text=href, href=href, host=_host_of(href)))
    return links


def _html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text("\n", strip=True)


def _build_email(
    *,
    headers: dict[str, str],
    text_body: str,
    html_body: str,
    attachments: list[Attachment],
    message_id: str = "",
) -> Email:
    lower = {k.lower(): v for k, v in headers.items()}
    from_name, from_addr = parseaddr(lower.get("from", ""))
    from_domain = _registrable(from_addr.split("@")[-1]) if "@" in from_addr else ""

    if not text_body and html_body:
        text_body = _html_to_text(html_body)

    links = _links_from_html(html_body) if html_body else []
    if not links:
        links = _links_from_text(text_body)

    return Email(
        message_id=message_id or lower.get("message-id", ""),
        from_name=from_name,
        from_address=from_addr,
        from_domain=from_domain,
        reply_to=parseaddr(lower.get("reply-to", ""))[1],
        to=lower.get("to", ""),
        subject=lower.get("subject", ""),
        date=lower.get("date", ""),
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
        auth_results=lower.get("authentication-results", ""),
        received_spf=lower.get("received-spf", ""),
    )


# ---- Gmail API (format=full) -------------------------------------------------

def _decode_b64url(data: str) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _walk_parts(part: dict, out: dict) -> None:
    mime = part.get("mimeType", "")
    body = part.get("body", {})
    filename = part.get("filename", "")

    if filename:
        out["attachments"].append(
            Attachment(
                filename=filename,
                mime_type=mime,
                size=int(body.get("size", 0) or 0),
            )
        )
    elif mime == "text/plain" and body.get("data"):
        out["text"] += _decode_b64url(body["data"])
    elif mime == "text/html" and body.get("data"):
        out["html"] += _decode_b64url(body["data"])

    for sub in part.get("parts", []) or []:
        _walk_parts(sub, out)


def parse_gmail_message(msg: dict) -> Email:
    """Parse a Gmail ``users.messages.get(format='full')`` response."""
    payload = msg.get("payload", {})
    headers = {h["name"]: h["value"] for h in payload.get("headers", [])}

    out = {"text": "", "html": "", "attachments": []}
    _walk_parts(payload, out)

    return _build_email(
        headers=headers,
        text_body=out["text"],
        html_body=out["html"],
        attachments=out["attachments"],
        message_id=msg.get("id", ""),
    )


# ---- Raw .eml (used by tests) ------------------------------------------------

def _parse_pymessage(m: PyMessage) -> Email:
    headers = {k: v for k, v in m.items()}
    text_body = ""
    html_body = ""
    attachments: list[Attachment] = []

    if m.is_multipart():
        for part in m.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            if filename or "attachment" in disp.lower():
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    Attachment(
                        filename=filename or "attachment",
                        mime_type=ctype,
                        size=len(payload),
                    )
                )
            elif ctype == "text/plain":
                text_body += (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            elif ctype == "text/html":
                html_body += (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
    else:
        payload = (m.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if m.get_content_type() == "text/html":
            html_body = payload
        else:
            text_body = payload

    return _build_email(
        headers=headers,
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
    )


def parse_eml(raw: str | bytes) -> Email:
    m = message_from_bytes(raw) if isinstance(raw, bytes) else message_from_string(raw)
    return _parse_pymessage(m)
