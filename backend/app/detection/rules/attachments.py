"""Rules based on attachments."""
from __future__ import annotations

from ..models import Category, Email, RuleSignal

# Extensions that can execute code or are commonly weaponized.
DANGEROUS_EXTS = {
    "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "msi", "jar", "hta", "cpl", "dll", "lnk", "iso",
    "img",
}
# Extensions that are risky lures even though not directly executable.
RISKY_EXTS = {"html", "htm", "zip", "rar", "7z", "gz", "docm", "xlsm", "pptm"}


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def check(email: Email) -> list[RuleSignal]:
    signals: list[RuleSignal] = []
    for att in email.attachments:
        name = att.filename or ""
        ext = _ext(name)
        parts = name.lower().split(".")

        if ext in DANGEROUS_EXTS:
            signals.append(
                RuleSignal(
                    code="dangerous_attachment",
                    reason=f'The attachment "{name}" is an executable-type file that can run malicious code.',
                    weight=45,
                    category=Category.malware,
                )
            )
        elif ext in RISKY_EXTS:
            signals.append(
                RuleSignal(
                    code="risky_attachment",
                    reason=f'The attachment "{name}" is a file type ({ext}) often used to deliver phishing pages or malware.',
                    weight=20,
                    category=Category.malware,
                )
            )

        # Double extension e.g. invoice.pdf.exe
        if len(parts) >= 3 and parts[-1] in DANGEROUS_EXTS and parts[-2] in {
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"
        }:
            signals.append(
                RuleSignal(
                    code="double_extension",
                    reason=f'The attachment "{name}" hides its real (executable) file type behind a fake extension.',
                    weight=40,
                    category=Category.malware,
                )
            )

    return signals
