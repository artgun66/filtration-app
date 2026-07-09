"""Thin wrapper over the Gmail API for listing and fetching messages.

Builds a Gmail service from stored OAuth credentials and returns normalized
``Email`` objects via ``gmail/parser.py``. Network-touching; unit tests mock at
the pipeline boundary instead of here.
"""
from __future__ import annotations

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from ..detection.models import Email
from . import parser


class GmailClient:
    def __init__(self, credentials: Credentials):
        # cache_discovery=False avoids a noisy warning and a file-cache dependency.
        self._service = build("gmail", "v1", credentials=credentials, cache_discovery=False)

    def list_message_ids(self, max_results: int = 25, query: str = "in:inbox") -> list[str]:
        """Return up to ``max_results`` recent message ids matching ``query``."""
        ids: list[str] = []
        page_token = None
        while len(ids) < max_results:
            resp = (
                self._service.users()
                .messages()
                .list(
                    userId="me",
                    q=query,
                    maxResults=min(100, max_results - len(ids)),
                    pageToken=page_token,
                )
                .execute()
            )
            ids.extend(m["id"] for m in resp.get("messages", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return ids[:max_results]

    def get_email(self, message_id: str) -> Email:
        msg = (
            self._service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )
        return parser.parse_gmail_message(msg)

    def get_profile_email(self) -> str:
        profile = self._service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress", "")
