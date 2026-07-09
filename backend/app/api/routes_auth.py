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
    url, state = google_oauth.authorization_url()
    response = RedirectResponse(url)
    # Stash the OAuth state in the signed cookie to validate on callback.
    session.write_session(response, {"oauth_state": state})
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

    creds = google_oauth.exchange_code(code=code, state=state)

    # Identify the account.
    from ..gmail.client import GmailClient

    email = GmailClient(creds).get_profile_email()

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
