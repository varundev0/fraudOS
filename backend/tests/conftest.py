"""Shared test fixtures — sets required env vars before any backend import."""

from __future__ import annotations

import os

# Must be set before importing backend modules (engine_instance creates the
# Anthropic client at import time; pii_filter reads the token secret).
os.environ.setdefault("FRAUDOS_ENV", "development")
os.environ.setdefault("FRAUDOS_TOKEN_SECRET", "unit-test-secret-0123456789abcdef0123456789")
os.environ.setdefault("FRAUDOS_WEBHOOK_SECRET", "unit-test-webhook-secret")
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-unit-test-not-a-real-key")
os.environ.setdefault("DATABASE_URL", "postgresql://localhost/fraudos_test")
