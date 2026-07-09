"""Signed-cookie sessions and the current-user dependency.

We keep a tiny signed cookie holding the user id (and a transient OAuth ``state``
during the login round-trip). The signing key is ``SECRET_KEY``.
"""
from __future__ import annotations

from fastapi import Cookie, Depends, HTTPException, Response, status
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy.orm import Session

from ..config import get_settings
from ..storage import models
from ..storage.db import get_db

COOKIE_NAME = "session"
_serializer = URLSafeSerializer(get_settings().secret_key, salt="filtration-session")


def _read(cookie: str | None) -> dict:
    if not cookie:
        return {}
    try:
        return _serializer.loads(cookie)
    except BadSignature:
        return {}


def write_session(response: Response, data: dict) -> None:
    value = _serializer.dumps(data)
    secure = get_settings().base_url.startswith("https")
    response.set_cookie(
        COOKIE_NAME,
        value,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )


def clear_session(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME)


def get_session(session: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> dict:
    return _read(session)


def current_user_optional(
    sess: dict = Depends(get_session),
    db: Session = Depends(get_db),
) -> models.User | None:
    uid = sess.get("uid")
    if not uid:
        return None
    return db.get(models.User, uid)


def require_user(
    user: models.User | None = Depends(current_user_optional),
) -> models.User:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not signed in")
    return user
