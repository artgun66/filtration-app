"""Scan and results routes (HTML fragments for the HTMX PWA)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..auth import google_oauth, session
from ..config import get_settings
from ..detection import pipeline
from ..storage import models
from ..storage.db import get_db
from ..web.format import format_email_date
from ..web.templates import templates

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scan"])

# Risk levels the dashboard surfaces as "flagged".
FLAGGED_RISKS = {"medium", "high", "critical"}


def _credentials_for(user: models.User, db: Session):
    if not user.encrypted_token:
        raise HTTPException(status_code=400, detail="No Gmail account connected.")
    creds = google_oauth.decrypt_credentials(user.encrypted_token)
    return creds


@router.post("/scan")
def scan(
    request: Request,
    limit: int | None = Form(default=None),
    user: models.User = Depends(session.require_user),
    db: Session = Depends(get_db),
):
    from ..gmail.client import GmailClient

    settings = get_settings()
    n = limit or settings.scan_default_limit
    # Keep it sane: at least 1, never more than the configured cap.
    n = max(1, min(n, settings.scan_max_limit))

    creds = _credentials_for(user, db)
    client = GmailClient(creds)

    try:
        ids = client.list_message_ids(max_results=n)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Gmail list failed")
        raise HTTPException(status_code=502, detail=f"Could not read Gmail: {exc}")

    # Persist possibly-refreshed credentials.
    user.encrypted_token = google_oauth.encrypt_credentials(creds)

    # Replace this user's previous results with the fresh scan.
    db.execute(delete(models.ScanResult).where(models.ScanResult.user_id == user.id))

    for mid in ids:
        try:
            email = client.get_email(mid)
            verdict = pipeline.analyze(email)
        except Exception:  # noqa: BLE001 - one bad message shouldn't kill the scan
            logger.exception("Failed to analyze message %s", mid)
            continue
        db.add(
            models.ScanResult(
                user_id=user.id,
                message_id=mid,
                from_name=email.from_name[:320],
                from_address=email.from_address[:320],
                subject=email.subject[:998],
                email_date=format_email_date(email.date)[:128],
                score=verdict.score,
                risk=verdict.risk.value,
                category=verdict.category.value,
                reasons="\n".join(verdict.reasons),
                recommended_action=verdict.recommended_action,
                used_llm=1 if verdict.used_llm else 0,
            )
        )
    db.commit()

    return _render_results(request, user, db)


@router.get("/results")
def results(
    request: Request,
    user: models.User = Depends(session.require_user),
    db: Session = Depends(get_db),
):
    return _render_results(request, user, db)


def _render_results(request: Request, user: models.User, db: Session):
    rows = db.scalars(
        select(models.ScanResult)
        .where(models.ScanResult.user_id == user.id)
        .order_by(models.ScanResult.score.desc())
    ).all()
    flagged = [r for r in rows if r.risk in FLAGGED_RISKS]
    safe_count = len(rows) - len(flagged)
    return templates.TemplateResponse(
        request,
        "partials/results.html",
        {
            "flagged": flagged,
            "total": len(rows),
            "safe_count": safe_count,
        },
    )


@router.get("/results/{result_id}")
def result_detail(
    result_id: int,
    request: Request,
    user: models.User = Depends(session.require_user),
    db: Session = Depends(get_db),
):
    row = db.get(models.ScanResult, result_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Result not found")
    reasons = [r for r in (row.reasons or "").split("\n") if r.strip()]
    return templates.TemplateResponse(
        request, "detail.html", {"r": row, "reasons": reasons}
    )
