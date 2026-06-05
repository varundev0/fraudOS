"""FraudOS FastAPI application."""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from collections import defaultdict
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .investigation.engine import InvestigationEngine
from .models import InvestigateRequest, InvestigateResponse
from .tests.synthetic_alerts import SYNTHETIC_ALERTS

_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

# ── Rate limiting ─────────────────────────────────────────────────────────────
# In-memory store; safe for single-process deployments.
_rate_limit_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_MAX = 60
_RATE_LIMIT_WINDOW = 60.0  # seconds


class _RateLimitExceeded(Exception):
    pass


def _check_rate_limit(api_key: str) -> None:
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW
    timestamps = _rate_limit_store[api_key]
    # Prune expired timestamps in-place
    _rate_limit_store[api_key] = [t for t in timestamps if t > cutoff]
    if len(_rate_limit_store[api_key]) >= _RATE_LIMIT_MAX:
        raise _RateLimitExceeded
    _rate_limit_store[api_key].append(now)


# ── Application setup ─────────────────────────────────────────────────────────

app = FastAPI(
    title="FraudOS",
    description="AI-native fraud investigation engine",
    version="0.2.0",
)


class _AddRequestID(BaseHTTPMiddleware):
    """Attach a unique X-Request-ID header to every response."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


app.add_middleware(_AddRequestID)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(_RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: _RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})


_engine = InvestigationEngine()
_MODEL = os.getenv("MODEL", "claude-opus-4-6")
_VERSION = "0.2.0"


# ── Auth dependency ───────────────────────────────────────────────────────────

def _get_api_key(x_api_key: Annotated[str | None, Header()] = None) -> str:
    expected = os.getenv("FRAUDOS_API_KEY", "dev-key-change-in-production")
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return x_api_key  # type: ignore[return-value]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "model": _MODEL, "version": _VERSION}


@app.get("/api/test-cases")
async def test_cases(_: str = Depends(_get_api_key)):
    return {"cases": [alert.model_dump(mode="json") for alert in SYNTHETIC_ALERTS]}


@app.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(
    request: InvestigateRequest,
    api_key: str = Depends(_get_api_key),
):
    # Layer 6a: rate limiting
    _check_rate_limit(api_key)

    try:
        report = await _engine.investigate(request.alert)
    except Exception:
        _logger.exception("Unhandled error in investigate endpoint")
        return InvestigateResponse(
            success=False,
            error="Investigation failed — contact support",
        )

    # Layer 6b: audit log (no PII — key suffix + hashed txn ID only)
    _audit_log.info(
        "INVESTIGATE "
        "key=****%s "
        "alert_type=%s "
        "txn_hash=%s "
        "risk_score=%s "
        "action=%s "
        "processing_ms=%s "
        "constitutional_ok=%s "
        "flags=%s",
        api_key[-4:],
        request.alert.alert_type.value,
        hashlib.sha256(request.alert.transaction_id.encode()).hexdigest()[:16],
        report.risk_score,
        report.recommended_action.value,
        report.processing_time_ms,
        report.constitutional_check_passed,
        ",".join(report.flags) if report.flags else "none",
    )

    return InvestigateResponse(success=True, report=report)
