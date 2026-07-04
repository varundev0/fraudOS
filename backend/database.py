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
    sla_notified_at TIMESTAMPTZ,
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

CREATE TABLE IF NOT EXISTS pii_vault (
    case_id TEXT PRIMARY KEY REFERENCES investigations(case_id),
    encrypted_map TEXT NOT NULL,
    token_count INTEGER NOT NULL DEFAULT 0,
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
                # Migrations are best-effort; surface failures so they aren't invisible
                _logger.warning("Migration failed (%s): %s", migration[:60], exc)
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

    # Persist the encrypted PII map alongside the investigation (non-fatal)
    if report.pii_map:
        try:
            from .pii_vault import store_pii_map
            await store_pii_map(conn, str(report.case_id), report.pii_map)
        except Exception:
            _logger.exception("Failed to store PII map for case=%s", report.case_id)


# ── Analyst feedback loop ─────────────────────────────────────────────────────

_FEEDBACK_STATS_QUERY = """
SELECT i.alert_type,
       COUNT(*) AS decided,
       COUNT(*) FILTER (WHERE ad.decision = i.recommended_action) AS agreed,
       i.recommended_action AS ai_action,
       ad.decision AS analyst_action,
       COUNT(*) AS pair_count
FROM investigations i
JOIN (
    SELECT DISTINCT ON (case_id) case_id, decision
    FROM analyst_decisions ORDER BY case_id, created_at DESC
) ad ON ad.case_id = i.case_id
GROUP BY i.alert_type, i.recommended_action, ad.decision
"""


async def get_feedback_stats(conn: asyncpg.Connection) -> dict:
    """AI-vs-analyst agreement stats derived from analyst_decisions.

    Returns {overall: {...}, by_alert_type: {...}, overrides: [...]}.
    Only enum values and counts — no free text.
    """
    rows = await conn.fetch(_FEEDBACK_STATS_QUERY)

    by_type: dict[str, dict] = {}
    overrides: list[dict] = []
    total = agreed_total = 0

    for r in rows:
        t = r["alert_type"]
        stats = by_type.setdefault(t, {"decided": 0, "agreed": 0})
        count = r["pair_count"]
        is_agreement = r["ai_action"] == r["analyst_action"]
        stats["decided"] += count
        total += count
        if is_agreement:
            stats["agreed"] += count
            agreed_total += count
        else:
            overrides.append({
                "alert_type": t,
                "ai_action": r["ai_action"],
                "analyst_action": r["analyst_action"],
                "count": count,
            })

    for stats in by_type.values():
        stats["agreement_rate"] = (
            round(stats["agreed"] / stats["decided"], 3) if stats["decided"] else None
        )

    overrides.sort(key=lambda o: o["count"], reverse=True)
    return {
        "overall": {
            "decided": total,
            "agreed": agreed_total,
            "agreement_rate": round(agreed_total / total, 3) if total else None,
        },
        "by_alert_type": by_type,
        "overrides": overrides,
    }


async def get_feedback_context(
    conn: asyncpg.Connection,
    alert_type: str,
    min_cases: int = 5,
) -> str | None:
    """Build a short, injection-safe calibration string for one alert type.

    Composed exclusively of enum values and integer counts from the DB —
    never analyst notes or other free text. Returns None when there is not
    enough decision history to be meaningful.
    """
    stats = await get_feedback_stats(conn)
    type_stats = stats["by_alert_type"].get(alert_type)
    if not type_stats or type_stats["decided"] < min_cases:
        return None

    pct = round((type_stats["agreement_rate"] or 0) * 100)
    context = (
        f"For {alert_type} alerts, human analysts reviewed {type_stats['decided']} "
        f"AI recommendations and agreed with {pct}% of them."
    )

    type_overrides = [o for o in stats["overrides"] if o["alert_type"] == alert_type]
    if type_overrides:
        top = type_overrides[0]
        context += (
            f" Most common analyst override: AI recommended {top['ai_action']} "
            f"but analysts chose {top['analyst_action']} ({top['count']} case"
            f"{'s' if top['count'] != 1 else ''})."
        )
    return context
