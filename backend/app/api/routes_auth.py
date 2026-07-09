"""OAuth login / callback / logout routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import google_oauth, session
from ..config import get_settings
from ..storage import models
from ..storage.db import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login")
def login():
    settings = get_settings()
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
        )
    url, state, code_verifier = google_oauth.authorization_url()
    response = RedirectResponse(url)
    # Stash the OAuth state (validated on callback) and the PKCE code_verifier
    # (needed to complete the token exchange) in the signed cookie.
    session.write_session(response, {"oauth_state": state, "oauth_code_verifier": code_verifier})
    return response


@router.get("/callback")
def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    sess: dict = Depends(session.get_session),
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"Google returned an error: {error}")
    if not code or not state or state != sess.get("oauth_state"):
        raise HTTPException(status_code=400, detail="Invalid OAuth state or missing code.")

    creds = google_oauth.exchange_code(
        code=code, state=state, code_verifier=sess.get("oauth_code_verifier")
    )

    # The whole app is useless without read access to Gmail. If Google didn't
    # grant it (scope not on the consent screen, or the user unticked it), say so
    # clearly instead of failing later with an opaque 403.
    if google_oauth.GMAIL_READONLY_SCOPE not in (creds.scopes or []):
        raise HTTPException(
            status_code=400,
            detail=(
                "Gmail read permission was not granted. On the Google consent "
                "screen, allow access to 'Read your email messages and settings', "
                "and make sure the gmail.readonly scope is added under APIs & "
                "Services > OAuth consent screen > Data access."
            ),
        )

    # Identify the account.
    from googleapiclient.errors import HttpError

    from ..gmail.client import GmailClient

    try:
        email = GmailClient(creds).get_profile_email()
    except HttpError as exc:
        if exc.resp.status == 403 and "accessNotConfigured" in str(exc):
            raise HTTPException(
                status_code=400,
                detail=(
                    "The Gmail API is not enabled for your Google Cloud project. "
                    "Enable it at console.cloud.google.com (APIs & Services > "
                    "Library > Gmail API > Enable), wait ~1 minute, then reconnect."
                ),
            ) from exc
        raise HTTPException(status_code=400, detail=f"Gmail API error: {exc}") from exc

    user = db.scalar(select(models.User).where(models.User.email == email))
    if user is None:
        user = models.User(email=email)
        db.add(user)
    user.encrypted_token = google_oauth.encrypt_credentials(creds)
    db.commit()
    db.refresh(user)

    response = RedirectResponse("/dashboard", status_code=303)
    session.write_session(response, {"uid": user.id})
    return response


@router.post("/logout")
@router.get("/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    session.clear_session(response)
    return response
