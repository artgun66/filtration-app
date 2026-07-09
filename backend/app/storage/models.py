"""Database models.

Privacy note: we intentionally do NOT store email bodies. A ScanResult keeps
only metadata (sender, subject, date), the computed verdict, and the reasons —
enough to show the user why something was flagged, nothing more. OAuth tokens
are stored encrypted (see auth/google_oauth.py).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    # Encrypted OAuth token blob (Fernet ciphertext of the credentials JSON).
    encrypted_token: Mapped[str] = mapped_column(Text, default="")

    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)

    # Email metadata (never the body).
    message_id: Mapped[str] = mapped_column(String(255), index=True)
    from_name: Mapped[str] = mapped_column(String(320), default="")
    from_address: Mapped[str] = mapped_column(String(320), default="")
    subject: Mapped[str] = mapped_column(String(998), default="")
    email_date: Mapped[str] = mapped_column(String(128), default="")

    # Verdict.
    score: Mapped[float] = mapped_column(Float, default=0.0)
    risk: Mapped[str] = mapped_column(String(16), default="safe")
    category: Mapped[str] = mapped_column(String(16), default="unknown")
    reasons: Mapped[str] = mapped_column(Text, default="")  # newline-joined
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    used_llm: Mapped[int] = mapped_column(Integer, default=0)

    user: Mapped["User"] = relationship(back_populates="results")
