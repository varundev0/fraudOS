"""Centralised settings — reads from environment variables and .env files."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from pydantic import field_validator
from pydantic_settings import BaseSettings

# Load .env files into os.environ so os.getenv() callers see them too.
# Never overrides variables already set in the real environment.
_BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(_BACKEND_DIR.parent / ".env")
load_dotenv(_BACKEND_DIR / ".env")


class Settings(BaseSettings):
    # SECURITY: defaults to production so a missing FRAUDOS_ENV can never
    # silently disable secret validation, expose /docs, or seed dev passwords.
    # Set FRAUDOS_ENV=development explicitly for local work.
    fraudos_env: str = "production"

    session_hours: int = 8
    audit_model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 1500
    rate_limit_max: int = 60
    rate_limit_window: float = 60.0
    webhook_rate_limit_max: int = 120       # per-IP webhook requests per window
    webhook_rate_limit_window: float = 60.0
    db_pool_min: int = 2
    db_pool_max: int = 10
    allowed_origins: list[str] = ["http://localhost:5173"]

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v: object) -> object:
        if isinstance(v, str):
            parsed = [o.strip() for o in v.split(",") if o.strip()]
            return parsed or ["http://localhost:5173"]
        return v

    @property
    def is_development(self) -> bool:
        return self.fraudos_env == "development"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "env_prefix": "",
        # .env also holds vars read via os.getenv (DATABASE_URL, secrets) —
        # ignore anything that isn't a Settings field instead of erroring.
        "extra": "ignore",
    }


settings = Settings()
