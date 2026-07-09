# Filtration — Fraudulent Email Checker

A phone-based (PWA) app that scans your Gmail inbox and flags fraudulent
(phishing / scam / BEC) emails. All logic lives in a Python **FastAPI** backend;
the phone client is a mobile-friendly web app (Jinja2 + HTMX) served by that same
backend and installable to the home screen.

Detection is **hybrid**: fast local rules run first (spoofed senders, lookalike
domains, bad links, failed SPF/DKIM/DMARC, scam language), and only *ambiguous*
messages are sent to Claude for a second opinion. Emails clearly safe or clearly
malicious never cost an LLM call.

> Status: **Phase 1 — on-demand inbox scan.** The pipeline and storage are
> structured so Phase 2 (continuous monitoring + push alerts) can be added
> without a rewrite.

## Architecture

```
Phone browser (PWA) ──HTTPS──> FastAPI backend
                                 ├─ auth/       Google OAuth, encrypted tokens
                                 ├─ gmail/      Gmail API client + MIME parser
                                 ├─ detection/  rules -> triage -> Claude -> verdict
                                 ├─ storage/    SQLAlchemy (verdicts + metadata only)
                                 └─ api/ + web/ routes + HTMX templates
                                      ├──> Gmail API (read-only)
                                      └──> Anthropic Claude API
```

Key modules:
- `app/detection/pipeline.py` — `analyze(email) -> Verdict` (the core; also the Phase-2 worker entry point)
- `app/detection/rules/` — one module per heuristic + `scoring.py`
- `app/detection/llm/classifier.py` — Claude structured-output classifier
- `app/gmail/` — `client.py` (list/get) + `parser.py` (MIME → `Email`)

## Setup

Requires Python 3.11+.

```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate       macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
cp .env.example .env   # then edit .env (see below)
```

### Configure `.env`

Generate the two secrets:

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('TOKEN_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

Add your `ANTHROPIC_API_KEY`, and the Google OAuth client below.

### Google OAuth (Gmail read-only)

1. In the [Google Cloud Console](https://console.cloud.google.com/): create a
   project → enable the **Gmail API**.
2. **OAuth consent screen**: External, add yourself under **Test users**
   (unverified apps allow up to 100 test users — enough for development).
3. **Credentials → Create OAuth client ID → Web application**. Set the authorized
   redirect URI to `{BASE_URL}/auth/callback`.
4. Put the client id/secret into `.env`.

> ⚠️ `gmail.readonly` is a Google **restricted scope**. It works for test users
> immediately, but a public launch requires OAuth verification + a paid annual
> third-party security assessment (CASA) and a published privacy policy. Design
> for this as a launch gate, not a code change.

## Run

```bash
cd backend
uvicorn app.main:app --reload
```

Open http://localhost:8000. For testing on your **phone** (and because Google
requires an HTTPS redirect for OAuth), expose it with ngrok and set `BASE_URL`
to the https URL, then use that same URL as the Google redirect URI base:

```bash
ngrok http 8000
# set BASE_URL=https://<subdomain>.ngrok-free.app in .env and restart uvicorn
```

On the phone, open the ngrok URL → **Connect Gmail** → **Scan inbox**. Use
"Add to Home Screen" to install the PWA.

## Test

```bash
cd backend
python -m pytest
```

- `app/tests/test_rules.py` — rules engine against `.eml` fixtures
- `app/tests/test_pipeline.py` — triage + graceful LLM degradation (LLM mocked)
- `app/tests/test_app.py` — web app smoke tests

## Privacy

We store **verdicts and metadata only — never email bodies**. OAuth tokens are
encrypted at rest (Fernet). See `/privacy` in the running app.
