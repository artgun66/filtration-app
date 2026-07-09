"""Smoke tests for the web app (no Google / Anthropic needed)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_index_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "Filtration" in r.text
    assert "Connect Gmail" in r.text


def test_manifest_served():
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200
    assert "Filtration" in r.text


def test_dashboard_requires_login_redirects():
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"


def test_scan_requires_auth():
    r = client.post("/scan", data={"limit": 10})
    assert r.status_code == 401
