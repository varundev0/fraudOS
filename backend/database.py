"""PostgreSQL persistence layer using asyncpg."""

from __future__ import annotations

import contextlib
import json
import logging
import os
from typing import TYPE_CHECKING, AsyncGenerator

import asyncpg

if TYPE_CHECKING:
    from .models import FraudAlert, InvestigationReport

_logger = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None
_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost/fraudos")

_SCHEMA = """
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
    api_key_suffix TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
"""


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
        min_size=2,
        max_size=10,
        init=_init_connection,
    )
    async with _pool.acquire() as conn:
        await conn.execute(_SCHEMA)
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
             processing_time_ms, model_used, canary, constitutional_check_passed)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
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
    )
