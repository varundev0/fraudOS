"""Webhook ingestion — receives external fraud alerts and runs investigations."""

from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, status

from .database import get_db, store_investigation
from .investigation.engine import InvestigationEngine
from .models import FraudAlert

_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

router = APIRouter()
_engine = InvestigationEngine()


@router.post("/webhook/alert")
async def webhook_alert(request: Request):
    secret = request.headers.get("X-Webhook-Secret")
    expected = os.getenv("FRAUDOS_WEBHOOK_SECRET", "")
    if not secret or not expected or not hmac.compare_digest(secret, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook secret")

    body = await request.json()
    try:
        alert = FraudAlert(**body)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc)

    async with get_db() as conn:
        await conn.execute(
            "INSERT INTO audit_log (event_type, details, ip_address, created_at)"
            " VALUES ($1, $2, $3, $4)",
            "WEBHOOK_RECEIVED",
            {"alert_type": alert.alert_type.value, "transaction_id": alert.transaction_id},
            client_ip,
            now,
        )

    _audit_log.info("WEBHOOK alert_type=%s txn=%s ip=%s", alert.alert_type.value, alert.transaction_id, client_ip)

    report = await _engine.investigate(alert)

    async with get_db() as conn:
        await store_investigation(conn, report, alert)
        await conn.execute(
            "INSERT INTO audit_log (event_type, case_id, details, ip_address, created_at)"
            " VALUES ($1, $2, $3, $4, $5)",
            "WEBHOOK_INVESTIGATED",
            str(report.case_id),
            {"risk_score": report.risk_score, "action": report.recommended_action.value},
            client_ip,
            now,
        )

    return report.model_dump(mode="json")
