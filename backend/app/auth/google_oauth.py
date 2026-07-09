"""Google OAuth 2.0 (authorization-code) flow and encrypted token storage.

Scope is the restricted ``gmail.readonly`` plus basic profile so we can label the
connected account. Tokens are encrypted at rest with Fernet before they touch the
database.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.fernet import Fernet
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from ..config import get_settings


def _fernet() -> Fernet:
    settings = get_settings()
    key = settings.token_encryption_key.strip()
    if not key:
        # Dev fallback: derive a stable Fernet key from the secret key so the app
        # runs without extra setup. Set TOKEN_ENCRYPTION_KEY in production.
        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_credentials(creds: Credentials) -> str:
    payload = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    return _fernet().encrypt(json.dumps(payload).encode()).decode()


def decrypt_credentials(blob: str) -> Credentials:
    data = json.loads(_fernet().decrypt(blob.encode()).decode())
    return Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        scopes=data.get("scopes"),
    )


def _client_config() -> dict:
    settings = get_settings()
    return {
        "web": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.redirect_uri],
        }
    }


def build_flow(state: str | None = None) -> Flow:
    settings = get_settings()
    flow = Flow.from_client_config(
        _client_config(),
        scopes=settings.gmail_scopes,
        state=state,
    )
    flow.redirect_uri = settings.redirect_uri
    return flow


def authorization_url() -> tuple[str, str]:
    """Return (url, state). We request offline access so we get a refresh token."""
    flow = build_flow()
    url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return url, state


def exchange_code(code: str, state: str) -> Credentials:
    flow = build_flow(state=state)
    flow.fetch_token(code=code)
    return flow.credentials
