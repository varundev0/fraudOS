"""FraudOS FastAPI application."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import get_current_session, router as auth_router
from .database import close_db, get_db, init_db, store_investigation
from .investigation.engine import InvestigationEngine
from .models import InvestigateRequest, InvestigateResponse
from .sar_formatter import format_sar
from .tests.synthetic_alerts import SYNTHETIC_ALERTS
from .webhook import router as webhook_router

_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_MAX = 60
_RATE_LIMIT_WINDOW = 60.0


class _RateLimitExceeded(Exception):
    pass


def _check_rate_limit(key: str) -> None:
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW
    _rate_limit_store[key] = [t for t in _rate_limit_store[key] if t > cutoff]
    if len(_rate_limit_store[key]) >= _RATE_LIMIT_MAX:
        raise _RateLimitExceeded
    _rate_limit_store[key].append(now)


# ── Application setup ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title="FraudOS",
    description="AI-native fraud investigation engine",
    version="0.3.0",
    lifespan=lifespan,
)


class _AddRequestID(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(_AddRequestID)
# allow_credentials must be False when allow_origins=["*"]; browser clients use
# the Vite proxy so no credentialed cross-origin requests are made from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(_RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: _RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


app.include_router(auth_router)
app.include_router(webhook_router)

_engine = InvestigationEngine()
_MODEL = os.getenv("MODEL", "claude-opus-4-6")
_VERSION = "0.3.0"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "model": _MODEL, "version": _VERSION}


@app.get("/api/test-cases")
async def test_cases(session: dict = Depends(get_current_session)):
    return {"cases": [alert.model_dump(mode="json") for alert in SYNTHETIC_ALERTS]}


@app.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(
    request: InvestigateRequest,
    session: dict = Depends(get_current_session),
):
    _check_rate_limit(session["api_key_suffix"])

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
                "INSERT INTO audit_log (event_type, case_id, api_key_suffix, details)"
                " VALUES ($1, $2, $3, $4)",
                "INVESTIGATE",
                str(report.case_id),
                session["api_key_suffix"],
                {
                    "alert_type": request.alert.alert_type.value,
                    "risk_score": report.risk_score,
                    "action": report.recommended_action.value,
                    "constitutional_ok": report.constitutional_check_passed,
                },
            )
    except Exception:
        _logger.exception("Failed to persist investigation %s", report.case_id)

    _audit_log.info(
        "INVESTIGATE key=****%s alert_type=%s txn_hash=%s risk_score=%s action=%s ms=%s",
        session["api_key_suffix"],
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
    limit: int = 50,
    offset: int = 0,
    session: dict = Depends(get_current_session),
):
    conditions = ["1=1"]
    params: list = []
    idx = 1

    if alert_type:
        conditions.append(f"alert_type = ${idx}")
        params.append(alert_type)
        idx += 1
    if risk_level:
        conditions.append(f"risk_level = ${idx}")
        params.append(risk_level)
        idx += 1
    if recommended_action:
        conditions.append(f"recommended_action = ${idx}")
        params.append(recommended_action)
        idx += 1

    where = " AND ".join(conditions)
    query = (
        f"SELECT case_id, alert_type, risk_level, risk_score, recommended_action,"
        f" amount, currency, confidence, flags, investigation_narrative,"
        f" created_at AS received_at"
        f" FROM investigations WHERE {where}"
        f" ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
    )
    params.extend([limit, offset])

    async with get_db() as conn:
        rows = await conn.fetch(query, *params)

    return [dict(r) for r in rows]


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

    analyst_id = session.get("api_key_suffix", "unknown")

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
