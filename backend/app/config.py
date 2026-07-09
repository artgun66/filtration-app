"""Application settings loaded from environment / .env file."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # App
    base_url: str = "http://localhost:8000"
    secret_key: str = "dev-insecure-secret-change-me"
    token_encryption_key: str = ""  # Fernet key; if empty a dev key is derived from secret_key
    database_url: str = "sqlite:///./filtration.db"

    # Google OAuth
    google_client_id: str = ""
    google_client_secret: str = ""

    # Anthropic
    anthropic_api_key: str = ""

    # Detection tuning
    llm_escalate_low: int = 30
    llm_escalate_high: int = 70
    scan_default_limit: int = 25
    scan_max_limit: int = 200  # hard cap on how many emails one scan will fetch
    # Timezone email timestamps are displayed in (IANA name).
    display_timezone: str = "America/Los_Angeles"
    llm_enabled: bool = True
    # Which backend answers the ambiguous mid-band: "anthropic" (paid Claude API)
    # or "ollama" (a free model running locally, e.g. Gemma). Both return the same
    # validated LLMVerdict, so the rest of the pipeline is unchanged.
    llm_provider: str = "anthropic"
    # Model used for per-email classification. Haiku 4.5 is the cheap default;
    # bump to "claude-sonnet-5" or "claude-opus-4-8" for higher accuracy.
    llm_model: str = "claude-haiku-4-5"
    llm_max_body_chars: int = 6000  # truncate very long bodies before sending to the LLM

    # Ollama (local, free) — used when llm_provider == "ollama".
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3:4b"

    @property
    def redirect_uri(self) -> str:
        return f"{self.base_url.rstrip('/')}/auth/callback"

    @property
    def gmail_scopes(self) -> list[str]:
        # Restricted scope: read-only access to Gmail.
        return [
            "https://www.googleapis.com/auth/gmail.readonly",
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
        ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
