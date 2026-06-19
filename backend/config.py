"""Centralised settings — reads from environment variables and .env file."""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    session_hours: int = 8
    audit_model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 1500
    rate_limit_max: int = 60
    rate_limit_window: float = 60.0
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

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
