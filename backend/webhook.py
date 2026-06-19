"""Webhook ingestion — receives external fraud alerts and runs investigations."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .database import get_db, store_investigation
from .investigation.engine_instance import engine as _engine
from .models import FraudAlert
from .notifications import notify_critical_case
from .ws import manager as _ws_manager

_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

router = APIRouter()

_MAX_WEBHOOK_BODY_BYTES = 64 * 1024  # 64 KB
_REPLAY_WINDOW_SECONDS = 300         # 5 minutes


async def _investigate_and_store(alert: FraudAlert, client_ip: str, received_at: datetime) -> None:
    """Background coroutine: run investigation, persist, broadcast, notify."""
    try:
        report = await _engine.investigate(alert)
    except Exception:
        _logger.exception("Webhook investigation failed for txn=%s", alert.transaction_id)
        return

    try:
        async with get_db() as conn:
            await store_investigation(conn, report, alert)
            await conn.execute(
                "INSERT INTO audit_log (event_type, case_id, details, ip_address, created_at)"
                " VALUES ($1, $2, $3, $4, $5)",
                "WEBHOOK_INVESTIGATED",
                str(report.case_id),
                {"risk_score": report.risk_score, "action": report.recommended_action.value},
                client_ip,
                received_at,
            )
    except Exception:
        _logger.exception("Webhook DB persistence failed for case=%s", report.case_id)

    asyncio.create_task(_ws_manager.broadcast({
        "type": "CASE_ADDED",
        "case_id": str(report.case_id),
        "alert_type": alert.alert_type.value,
        "risk_level": report.risk_level.value,
        "risk_score": report.risk_score,
        "recommended_action": report.recommended_action.value,
        "amount": float(alert.amount),
        "currency": alert.currency,
    }))

    if report.risk_level.value in ("CRITICAL", "HIGH") or report.recommended_action.value == "BLOCK":
        asyncio.create_task(notify_critical_case(
            case_id=str(report.case_id),
            alert_type=alert.alert_type.value,
            risk_level=report.risk_level.value,
            risk_score=report.risk_score,
            action=report.recommended_action.value,
            amount=float(alert.amount),
            currency=alert.currency,
        ))


@router.post("/webhook/alert", status_code=202)
async def webhook_alert(request: Request):
    secret = os.getenv("FRAUDOS_WEBHOOK_SECRET", "")
    sig_header = request.headers.get("X-Webhook-Signature", "")
    ts_header = request.headers.get("X-Webhook-Timestamp", "")

    if not secret or not sig_header or not ts_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing webhook credentials")

    # Replay protection: reject requests with a timestamp older than 5 minutes
    try:
        ts = int(ts_header)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid timestamp")

    if abs(time.time() - ts) > _REPLAY_WINDOW_SECONDS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Request timestamp too old")

    # Enforce body size limit before reading
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_WEBHOOK_BODY_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")

    body_bytes = await request.body()
    if len(body_bytes) > _MAX_WEBHOOK_BODY_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Request body too large")

    # HMAC-SHA256 of "<timestamp>.<body>" — covers both freshness and body integrity
    expected_mac = hmac.new(
        secret.encode(),
        f"{ts_header}.".encode() + body_bytes,
        hashlib.sha256,
    ).hexdigest()
    expected_sig = f"sha256={expected_mac}"

    if not hmac.compare_digest(sig_header, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook signature")

    try:
        body = json.loads(body_bytes)
        alert = FraudAlert(**body)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc)

    try:
        async with get_db() as conn:
            await conn.execute(
                "INSERT INTO audit_log (event_type, details, ip_address, created_at)"
                " VALUES ($1, $2, $3, $4)",
                "WEBHOOK_RECEIVED",
                {"alert_type": alert.alert_type.value, "transaction_id": alert.transaction_id},
                client_ip,
                now,
            )
    except Exception:
        _logger.exception("Webhook audit log failed")

    _audit_log.info("WEBHOOK alert_type=%s txn=%s ip=%s", alert.alert_type.value, alert.transaction_id, client_ip)

    asyncio.create_task(_investigate_and_store(alert, client_ip, now))

    return JSONResponse(status_code=202, content={"status": "accepted"})
