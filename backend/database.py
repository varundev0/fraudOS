"""PostgreSQL persistence layer using asyncpg."""

from __future__ import annotations

import contextlib
import json
import logging
import os
from typing import TYPE_CHECKING, AsyncGenerator

import asyncpg

from .config import settings

if TYPE_CHECKING:
    from .models import FraudAlert, InvestigationReport

_logger = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None
_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/fraudos")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'ANALYST' CHECK (role IN ('ANALYST', 'SUPERVISOR', 'ADMIN')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS investigations (
    case_id TEXT PRIMARY KEY,
    alert_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    recommended_action TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    currency TEXT DEFAULT 'INR',
    confidence NUMERIC,
    flags TEXT[],
    entity_profile JSONB,
    transaction_pattern JSONB,
    risk_assessment TEXT,
    investigation_narrative TEXT,
    processing_time_ms INTEGER,
    model_used TEXT,
    canary TEXT,
    constitutional_check_passed BOOLEAN,
    tokenized_payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS analyst_decisions (
    id SERIAL PRIMARY KEY,
    case_id TEXT REFERENCES investigations(case_id),
    analyst_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('CLEAR','REVIEW','ESCALATE','BLOCK')),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    case_id TEXT,
    analyst_id TEXT,
    api_key_suffix TEXT,
    details JSONB,
    ip_address TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    session_token TEXT PRIMARY KEY,
    api_key_suffix TEXT,
    user_id UUID REFERENCES users(id),
    user_email TEXT,
    user_role TEXT,
    full_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_alert_type ON investigations(alert_type);
CREATE INDEX IF NOT EXISTS idx_investigations_risk_level ON investigations(risk_level);
CREATE INDEX IF NOT EXISTS idx_investigations_action ON investigations(recommended_action);
CREATE INDEX IF NOT EXISTS idx_investigations_sla ON investigations(sla_notified_at, created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_analyst_decisions_case_id ON analyst_decisions(case_id);
CREATE INDEX IF NOT EXISTS idx_investigations_narrative_fts ON investigations
    USING GIN(to_tsvector('english', coalesce(investigation_narrative, '')));
"""

# Idempotent migrations for existing installs
_MIGRATIONS = [
    # Multi-user auth (v0.4): add user columns to sessions
    "ALTER TABLE sessions ALTER COLUMN api_key_suffix DROP NOT NULL",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id)",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_email TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_role TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS full_name TEXT",
    # Real-time + notifications (v0.5): track which cases triggered SLA alerts
    "ALTER TABLE investigations ADD COLUMN IF NOT EXISTS sla_notified_at TIMESTAMPTZ",
]


async def _init_connection(conn: asyncpg.Connection) -> None:
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )


async def init_db() -> None:
    global _pool
    _pool = await asyncpg.create_pool(
        _DATABASE_URL,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
        init=_init_connection,
    )
    async with _pool.acquire() as conn:
        await conn.execute(_SCHEMA)
        for migration in _MIGRATIONS:
            try:
                await conn.execute(migration)
            except Exception as exc:
                # Migrations are best-effort; log but don't crash
                _logger.debug("Migration skipped (%s): %s", migration[:60], exc)
    _logger.info("Database pool initialised (%s)", _DATABASE_URL)


@contextlib.asynccontextmanager
async def get_db() -> AsyncGenerator[asyncpg.Connection, None]:
    if _pool is None:
        raise RuntimeError("Database pool not initialised — call init_db() first")
    async with _pool.acquire() as conn:
        yield conn


async def close_db() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def store_investigation(
    conn: asyncpg.Connection,
    report: InvestigationReport,
    alert: FraudAlert,
) -> None:
    await conn.execute(
        """
        INSERT INTO investigations
            (case_id, alert_type, risk_level, risk_score, recommended_action,
             amount, currency, confidence, flags, entity_profile,
             transaction_pattern, risk_assessment, investigation_narrative,
             processing_time_ms, model_used, canary, constitutional_check_passed,
             tokenized_payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        ON CONFLICT (case_id) DO NOTHING
        """,
        str(report.case_id),
        alert.alert_type.value,
        report.risk_level.value,
        report.risk_score,
        report.recommended_action.value,
        alert.amount,
        alert.currency,
        report.confidence,
        report.flags,
        report.entity_profile,
        report.transaction_pattern,
        report.risk_assessment,
        report.investigation_narrative,
        report.processing_time_ms,
        report.model_used,
        report.canary,
        report.constitutional_check_passed,
        report.tokenized_payload,
    )
