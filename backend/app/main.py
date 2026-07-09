"""FastAPI application entry point.

Serves the PWA (HTML pages + static assets) and registers the auth/scan APIs.
Run locally:  uvicorn app.main:app --reload
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import routes_auth, routes_scan
from .auth import session
from .storage import models
from .storage.db import init_db
from .web.templates import templates

STATIC_DIR = Path(__file__).parent / "web" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Filtration — Fraudulent Email Checker", lifespan=lifespan)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.include_router(routes_auth.router)
app.include_router(routes_scan.router)


# ---- Pages -------------------------------------------------------------------

@app.get("/")
def index(request: Request, user: models.User | None = Depends(session.current_user_optional)):
    if user is not None:
        from fastapi.responses import RedirectResponse

        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "index.html")


@app.get("/dashboard")
def dashboard(request: Request, user: models.User | None = Depends(session.current_user_optional)):
    if user is None:
        from fastapi.responses import RedirectResponse

        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "dashboard.html", {"user": user}
    )


@app.get("/privacy")
def privacy(request: Request):
    return templates.TemplateResponse(request, "privacy.html")


# ---- PWA files served at root scope -----------------------------------------

@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/service-worker.js")
def service_worker():
    # Served at root so its scope covers the whole app.
    return FileResponse(STATIC_DIR / "service-worker.js", media_type="application/javascript")


@app.get("/health")
def health():
    return {"status": "ok"}
