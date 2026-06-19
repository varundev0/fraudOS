"""FraudOS FastAPI application."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import get_current_session, require_role, seed_admin_user, router as auth_router
from .config import settings
from .database import close_db, get_db, init_db, store_investigation
from .investigation.engine_instance import engine as _engine
from .models import InvestigateRequest, InvestigateResponse
from .notifications import notify_critical_case, notification_status
from .sar_formatter import format_sar
from .tests.synthetic_alerts import SYNTHETIC_ALERTS
from .webhook import prune_seen_signatures, router as webhook_router
from .ws import manager as _ws_manager

_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

_FRAUDOS_ENV = os.getenv("FRAUDOS_ENV", "development")
_MODEL = os.getenv("MODEL", "claude-opus-4-6")
_VERSION = "0.5.0"

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


class _RateLimitExceeded(Exception):
    pass


def _check_rate_limit(key: str) -> None:
    now = time.time()
    cutoff = now - settings.rate_limit_window
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if t > cutoff]
    if not _rate_limit_store[key]:
        del _rate_limit_store[key]
    if len(_rate_limit_store[key]) >= settings.rate_limit_max:
        raise _RateLimitExceeded
    _rate_limit_store[key].append(now)


_login_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_LOGIN_RATE_LIMIT_MAX = 10
_LOGIN_RATE_LIMIT_WINDOW = 60  # 1 minute


# ── SLA computation ───────────────────────────────────────────────────────────

_SLA_HOURS: dict[str, int] = {
    "CRITICAL": 4,    # 4 hours  — immediate action
    "HIGH": 24,       # 24 hours — same business day
    "MEDIUM": 72,     # 3 days
    "LOW": 168,       # 7 days
}


def _compute_sla(row: dict) -> dict:
    """Return sla_deadline, sla_status, sla_hours_remaining for a case row."""
    risk_level = row.get("risk_level", "LOW")
    total_hours = _SLA_HOURS.get(risk_level, 168)
    created_at = row.get("received_at") or row.get("created_at")

    if not created_at:
        return {"sla_deadline": None, "sla_status": "UNKNOWN", "sla_hours_remaining": None}

    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    deadline = created_at + timedelta(hours=total_hours)
    now = datetime.now(timezone.utc)

    if row.get("decision"):
        return {
            "sla_deadline": deadline.isoformat(),
            "sla_status": "RESOLVED",
            "sla_hours_remaining": None,
        }

    hours_remaining = (deadline - now).total_seconds() / 3600
    if hours_remaining < 0:
        sla_status = "OVERDUE"
    elif hours_remaining < total_hours * 0.25:
        sla_status = "DUE_SOON"
    else:
        sla_status = "ON_TRACK"

    return {
        "sla_deadline": deadline.isoformat(),
        "sla_status": sla_status,
        "sla_hours_remaining": round(hours_remaining, 1),
    }


# ── Startup secret validation ─────────────────────────────────────────────────

_INSECURE_API_KEY = "dev-key-change-in-production"
_INSECURE_TOKEN_SECRETS = {
    "change-this-to-a-long-random-string",
    "default-insecure-secret-change-me",
}


def _validate_secrets() -> None:
    """Refuse to start in production with default/insecure secret values."""
    if _FRAUDOS_ENV == "development":
        return
    if os.getenv("FRAUDOS_API_KEY", _INSECURE_API_KEY) == _INSECURE_API_KEY:
        raise RuntimeError(
            "FRAUDOS_API_KEY is still set to the default value. "
            "Set a strong random key before running in production."
        )
    token_secret = os.getenv("FRAUDOS_TOKEN_SECRET", "")
    if not token_secret or token_secret in _INSECURE_TOKEN_SECRETS:
        raise RuntimeError(
            "FRAUDOS_TOKEN_SECRET is missing or set to the default value. "
            "Set a strong random secret before running in production."
        )


# ── Session cleanup background task ──────────────────────────────────────────

async def _session_cleanup_loop() -> None:
    """Delete expired sessions and send SLA-overdue notifications every 10 minutes."""
    while True:
        await asyncio.sleep(600)

        # ── Session cleanup ──────────────────────────────────────────────────
        try:
            async with get_db() as conn:
                result = await conn.execute("DELETE FROM sessions WHERE expires_at < NOW()")
            _logger.info("Session cleanup complete: %s", result)
        except Exception:
            _logger.exception("Session cleanup failed")

        # ── Rate limit store pruning ─────────────────────────────────────────
        try:
            _now = time.time()
            for _store, _window in [
                (_rate_limit_store, settings.rate_limit_window),
                (_login_rate_limit_store, float(_LOGIN_RATE_LIMIT_WINDOW)),
            ]:
                _stale = [k for k, ts in _store.items() if not any(t > _now - _window for t in ts)]
                for k in _stale:
                    del _store[k]
            prune_seen_signatures()
        except Exception:
            _logger.exception("Rate limit store cleanup failed")

        # ── SLA overdue notifications ────────────────────────────────────────
        # Find cases that just crossed their SLA deadline and haven't been notified yet.
        overdue_rows = []
        try:
            async with get_db() as conn:
                async with conn.transaction():
                    overdue_rows = await conn.fetch(
                        """
                        SELECT i.case_id, i.alert_type, i.risk_level, i.risk_score,
                               i.recommended_action, i.amount, i.currency
                        FROM investigations i
                        WHERE i.sla_notified_at IS NULL
                          AND NOT EXISTS (
                              SELECT 1 FROM analyst_decisions ad WHERE ad.case_id = i.case_id
                          )
                          AND i.created_at < NOW() - (
                              CASE i.risk_level
                                  WHEN 'CRITICAL' THEN INTERVAL '4 hours'
                                  WHEN 'HIGH'     THEN INTERVAL '24 hours'
                                  WHEN 'MEDIUM'   THEN INTERVAL '72 hours'
                                  ELSE                 INTERVAL '168 hours'
                              END
                          )
                        """,
                    )
                    if overdue_rows:
                        # Mark as notified before sending (prevents duplicate on failure)
                        ids = [r["case_id"] for r in overdue_rows]
                        await conn.execute(
                            "UPDATE investigations SET sla_notified_at = NOW() WHERE case_id = ANY($1::text[])",
                            ids,
                        )
                        _logger.info("SLA overdue: marking %d case(s) and sending alerts", len(ids))

            # Send notifications outside the DB transaction
            for row in overdue_rows:
                asyncio.create_task(
                    notify_critical_case(
                        case_id=row["case_id"],
                        alert_type=row["alert_type"],
                        risk_level=row["risk_level"],
                        risk_score=row["risk_score"],
                        action=row["recommended_action"],
                        amount=float(row["amount"]),
                        currency=row["currency"] or "INR",
                        trigger="SLA_OVERDUE",
                    )
                )
                # Also broadcast overdue event to connected analysts
                asyncio.create_task(
                    _ws_manager.broadcast({
                        "type": "SLA_OVERDUE",
                        "case_id": row["case_id"],
                        "risk_level": row["risk_level"],
                        "alert_type": row["alert_type"],
                    })
                )
        except Exception:
            _logger.exception("SLA overdue notification check failed")


# ── Application setup ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    _validate_secrets()
    await init_db()
    await seed_admin_user()
    cleanup_task = asyncio.create_task(_session_cleanup_loop())
    try:
        yield
    finally:
        cleanup_task.cancel()
        await close_db()


app = FastAPI(
    title="FraudOS",
    description="AI-native fraud investigation engine",
    version=_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if _FRAUDOS_ENV == "development" else None,
    redoc_url="/redoc" if _FRAUDOS_ENV == "development" else None,
    openapi_url="/openapi.json" if _FRAUDOS_ENV == "development" else None,
)


# ── Security headers middleware ───────────────────────────────────────────────

class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Tight CSP for a pure JSON API — no scripts, no frames
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        if _FRAUDOS_ENV != "development":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class _AddRequestID(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class _LoginRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.url.path == "/auth":
            ip = request.client.host if request.client else "unknown"
            now = time.time()
            cutoff = now - _LOGIN_RATE_LIMIT_WINDOW
            timestamps = [t for t in _login_rate_limit_store[ip] if t > cutoff]
            if len(timestamps) >= _LOGIN_RATE_LIMIT_MAX:
                return JSONResponse(status_code=429, content={"error": "Too many login attempts"})
            timestamps.append(now)
            _login_rate_limit_store[ip] = timestamps
        return await call_next(request)


app.add_middleware(_SecurityHeaders)
app.add_middleware(_AddRequestID)
app.add_middleware(_LoginRateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,   # required for HttpOnly session cookies
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(_RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: _RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


app.include_router(auth_router)
app.include_router(webhook_router)


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time case update stream — authenticated via session cookie."""
    token = websocket.cookies.get("fraudos_session")
    if not token:
        await websocket.close(code=4001)
        return

    # Validate session
    try:
        async with get_db() as conn:
            row = await conn.fetchrow(
                "SELECT session_token FROM sessions WHERE session_token = $1 AND expires_at > NOW()",
                token,
            )
    except Exception:
        await websocket.close(code=4011)
        return

    if row is None:
        await websocket.close(code=4001)
        return

    await _ws_manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive by awaiting data (clients send pings or we block)
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health(session: dict = Depends(get_current_session)):
    return {
        "status": "ok",
        "model": _MODEL,
        "version": _VERSION,
        "ws_clients": _ws_manager.connected_count,
        "notifications": notification_status(),
    }


@app.get("/api/test-cases")
async def test_cases(session: dict = Depends(get_current_session)):
    return {"cases": [alert.model_dump(mode="json") for alert in SYNTHETIC_ALERTS]}


@app.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(
    request: InvestigateRequest,
    session: dict = Depends(get_current_session),
):
    _check_rate_limit(session.get("user_email", "unknown"))

    try:
        report = await _engine.investigate(request.alert)
    except Exception:
        _logger.exception("Unhandled error in investigate endpoint")
        return InvestigateResponse(success=False, error="Investigation failed — contact support")

    # Persist to DB; non-fatal if DB is unavailable
    try:
        async with get_db() as conn:
            await store_investigation(conn, report, request.alert)
            await conn.execute(
                "INSERT INTO audit_log (event_type, case_id, analyst_id, details)"
                " VALUES ($1, $2, $3, $4)",
                "INVESTIGATE",
                str(report.case_id),
                session.get("user_email", "unknown"),
                {
                    "alert_type": request.alert.alert_type.value,
                    "risk_score": report.risk_score,
                    "action": report.recommended_action.value,
                    "constitutional_ok": report.constitutional_check_passed,
                },
            )
    except Exception:
        _logger.exception("Failed to persist investigation %s", report.case_id)

    # Broadcast to all connected analysts (fire-and-forget)
    asyncio.create_task(_ws_manager.broadcast({
        "type": "CASE_ADDED",
        "case_id": str(report.case_id),
        "alert_type": request.alert.alert_type.value,
        "risk_level": report.risk_level.value,
        "risk_score": report.risk_score,
        "recommended_action": report.recommended_action.value,
        "amount": float(request.alert.amount),
        "currency": request.alert.currency,
    }))

    # Notify on CRITICAL risk or BLOCK action
    if report.risk_level.value in ("CRITICAL", "HIGH") or report.recommended_action.value == "BLOCK":
        asyncio.create_task(notify_critical_case(
            case_id=str(report.case_id),
            alert_type=request.alert.alert_type.value,
            risk_level=report.risk_level.value,
            risk_score=report.risk_score,
            action=report.recommended_action.value,
            amount=float(request.alert.amount),
            currency=request.alert.currency,
        ))

    _audit_log.info(
        "INVESTIGATE user=%s alert_type=%s txn_hash=%s risk_score=%s action=%s ms=%s",
        session.get("user_email", "unknown"),
        request.alert.alert_type.value,
        hashlib.sha256(request.alert.transaction_id.encode()).hexdigest()[:16],
        report.risk_score,
        report.recommended_action.value,
        report.processing_time_ms,
    )

    return InvestigateResponse(success=True, report=report)


# ── Investigation CRUD ────────────────────────────────────────────────────────

@app.get("/api/investigations")
async def list_investigations(
    alert_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    recommended_action: Optional[str] = None,
    search: Optional[str] = Query(default=None, max_length=500),
    date_from: Optional[str] = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    date_to: Optional[str] = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    amount_min: Optional[float] = None,
    amount_max: Optional[float] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: dict = Depends(get_current_session),
):
    conditions = ["1=1"]
    params: list = []
    idx = 1

    if alert_type:
        conditions.append(f"i.alert_type = ${idx}")
        params.append(alert_type); idx += 1
    if risk_level:
        conditions.append(f"i.risk_level = ${idx}")
        params.append(risk_level); idx += 1
    if recommended_action:
        conditions.append(f"i.recommended_action = ${idx}")
        params.append(recommended_action); idx += 1
    if date_from:
        conditions.append(f"i.created_at >= ${idx}")
        params.append(date_from); idx += 1
    if date_to:
        # include the full end day
        conditions.append(f"i.created_at < (${idx}::date + interval '1 day')")
        params.append(date_to); idx += 1
    if amount_min is not None:
        conditions.append(f"i.amount >= ${idx}")
        params.append(amount_min); idx += 1
    if amount_max is not None:
        conditions.append(f"i.amount <= ${idx}")
        params.append(amount_max); idx += 1
    if search:
        conditions.append(
            f"(to_tsvector('english', coalesce(i.investigation_narrative, '')) @@ plainto_tsquery('english', ${idx})"
            f" OR array_to_string(i.flags, ' ') ILIKE ${idx + 1})"
        )
        params.append(search)
        params.append(f"%{search}%")
        idx += 2

    where = " AND ".join(conditions)
    query = (
        # LEFT JOIN latest analyst decision so we can mark resolved SLAs
        f"SELECT i.case_id, i.alert_type, i.risk_level, i.risk_score, i.recommended_action,"
        f" i.amount, i.currency, i.confidence, i.flags, i.investigation_narrative,"
        f" i.created_at AS received_at,"
        f" ad.decision, ad.decided_at"
        f" FROM investigations i"
        f" LEFT JOIN ("
        f"   SELECT DISTINCT ON (case_id) case_id, decision, created_at AS decided_at"
        f"   FROM analyst_decisions ORDER BY case_id, created_at DESC"
        f" ) ad ON ad.case_id = i.case_id"
        f" WHERE {where}"
        f" ORDER BY i.created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
    )
    params.extend([limit, offset])

    async with get_db() as conn:
        rows = await conn.fetch(query, *params)

    result = []
    for r in rows:
        row = dict(r)
        row.update(_compute_sla(row))
        result.append(row)
    return result


@app.get("/api/investigations/{case_id}")
async def get_investigation(case_id: str, session: dict = Depends(get_current_session)):
    async with get_db() as conn:
        row = await conn.fetchrow("SELECT * FROM investigations WHERE case_id = $1", case_id)

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    return dict(row)


class _DecisionRequest(BaseModel):
    decision: str
    notes: Optional[str] = None


@app.post("/api/investigations/{case_id}/decision")
async def submit_decision(
    case_id: str,
    body: _DecisionRequest,
    session: dict = Depends(get_current_session),
):
    valid = {"CLEAR", "REVIEW", "ESCALATE", "BLOCK"}
    if body.decision not in valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid decision value")

    analyst_id = session.get("user_email", "unknown")

    async with get_db() as conn:
        exists = await conn.fetchval("SELECT 1 FROM investigations WHERE case_id = $1", case_id)
        if not exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

        await conn.execute(
            "INSERT INTO analyst_decisions (case_id, analyst_id, decision, notes)"
            " VALUES ($1, $2, $3, $4)",
            case_id,
            analyst_id,
            body.decision,
            body.notes,
        )
        await conn.execute(
            "INSERT INTO audit_log (event_type, case_id, analyst_id, details)"
            " VALUES ($1, $2, $3, $4)",
            "ANALYST_DECISION",
            case_id,
            analyst_id,
            {"decision": body.decision, "has_notes": bool(body.notes)},
        )

    _audit_log.info("DECISION case=%s analyst=****%s decision=%s", case_id, analyst_id, body.decision)
    return {"success": True, "decision": body.decision}


@app.get("/api/notifications/status")
async def get_notification_status(session: dict = Depends(require_role("ADMIN", "SUPERVISOR"))):
    return notification_status()


@app.get("/api/investigations/{case_id}/sar")
async def export_sar(case_id: str, session: dict = Depends(get_current_session)):
    async with get_db() as conn:
        row = await conn.fetchrow("SELECT * FROM investigations WHERE case_id = $1", case_id)

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    sar_text = format_sar(dict(row))
    return Response(
        content=sar_text,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="SAR_DRAFT_{case_id}.txt"'},
    )
