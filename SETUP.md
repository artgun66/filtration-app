# Setup — running Filtration locally

This gets a fresh clone running from scratch. Assumes **Python 3.11+** and
**Windows** (PowerShell); macOS/Linux notes are inline. Takes ~15–30 min, mostly
the one-time model download and Google OAuth.

---

## 1. Install Python dependencies

```bash
cd backend
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

python -m pip install -e ".[dev]"
```

## 2. Create your `.env`

The real `.env` is **not** in the repo (it holds secrets). Copy the template and
fill it in:

```bash
cp .env.example .env
```

Generate the two required secrets and paste them into `.env`:

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print('TOKEN_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

## 3. Pick your LLM backend

The app only calls an LLM for *ambiguous* emails; clearly-safe and clearly-bad
ones are decided by local rules for free. Two backends:

### Option A — Ollama (free, local, private) — recommended for dev

Nothing leaves your machine and there's no cost.

1. Install Ollama: <https://ollama.com/download> (or `winget install Ollama.Ollama`)
2. Pull the model:
   ```bash
   ollama pull gemma3:4b
   ```
3. In `.env`, set:
   ```
   LLM_PROVIDER=ollama
   OLLAMA_MODEL=gemma3:4b
   ```

> Gemma 3 4B (~3.3 GB) runs on modest hardware. It's less accurate than Claude,
> so if you see false positives, raise `LLM_ESCALATE_LOW` (e.g. to 40) to send
> fewer borderline emails to the model.

### Option B — Anthropic Claude (paid, more accurate)

1. Get an API key: <https://console.anthropic.com/>
2. In `.env`, set:
   ```
   LLM_PROVIDER=anthropic
   ANTHROPIC_API_KEY=sk-ant-...
   LLM_MODEL=claude-haiku-4-5
   ```

> You can also set `LLM_ENABLED=false` for a totally offline, rules-only mode
> (no LLM at all).

## 4. Google OAuth (to scan a real Gmail inbox)

Each developer needs their **own** Google credentials — you can't share these.

1. Go to <https://console.cloud.google.com/> → create/select a project.
2. **APIs & Services → Enable APIs** → enable the **Gmail API**.
3. **OAuth consent screen** → External → add your own Google account under
   **Test users** (required while the app is unverified; free for ≤100 users).
4. **Credentials → Create Credentials → OAuth client ID → Web application.**
   - Authorized redirect URI: `http://localhost:8000/auth/callback`
5. Copy the client ID/secret into `.env`:
   ```
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   ```

## 5. Run it

```bash
cd backend
uvicorn app.main:app --reload
```

Open <http://localhost:8000>, connect your Gmail, and run a scan.

## 6. Run the tests

```bash
cd backend
pytest -q
```

---

## Troubleshooting

- **`ollama` connection refused** — make sure Ollama is running (the desktop app
  or `ollama serve`) and reachable at `OLLAMA_BASE_URL` (default
  `http://localhost:11434`).
- **Google "app not verified" / access blocked** — confirm your account is added
  as a **Test user** on the OAuth consent screen.
- **LLM never runs** — check `LLM_ENABLED=true`, the provider's credential is set
  (API key for anthropic; nothing needed for ollama), and the email's rule score
  falls in the `LLM_ESCALATE_LOW`–`LLM_ESCALATE_HIGH` band.
