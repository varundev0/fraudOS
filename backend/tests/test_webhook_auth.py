"""Tests for webhook HMAC authentication, replay protection, and rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from .. import webhook as webhook_module
from ..main import app

SECRET = os.environ["FRAUDOS_WEBHOOK_SECRET"]

VALID_BODY = {
    "transaction_id": "TXN-WH-001",
    "amount": 99000.0,
    "currency": "INR",
    "entity_data": {"account_age_days": "2"},
    "rule_trigger": "AMOUNT > 50000",
    "alert_type": "UPI_FRAUD",
}


@pytest.fixture()
def client(monkeypatch):
    # Don't run real investigations (no DB / no Anthropic in unit tests)
    async def _noop(alert, client_ip, received_at):
        return None

    monkeypatch.setattr(webhook_module, "_investigate_and_store", _noop)
    webhook_module._seen_signatures.clear()
    webhook_module._webhook_rate_store.clear()
    # TestClient without context manager => lifespan (DB init) is not run;
    # the webhook's audit-log write fails soft, which is what we want here.
    return TestClient(app, raise_server_exceptions=False)


def _sign(body: bytes, ts: str, secret: str = SECRET) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _post(client, body: dict, *, ts: str | None = None, sig: str | None = None):
    raw = json.dumps(body).encode()
    ts = ts if ts is not None else str(int(time.time()))
    sig = sig if sig is not None else _sign(raw, ts)
    return client.post(
        "/webhook/alert",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Signature": sig,
            "X-Webhook-Timestamp": ts,
        },
    )


def test_missing_credentials_rejected(client):
    r = client.post("/webhook/alert", json=VALID_BODY)
    assert r.status_code == 401


def test_valid_signature_accepted(client):
    r = _post(client, VALID_BODY)
    assert r.status_code == 202


def test_invalid_signature_rejected(client):
    r = _post(client, VALID_BODY, sig="sha256=" + "0" * 64)
    assert r.status_code == 401


def test_wrong_secret_rejected(client):
    raw = json.dumps(VALID_BODY).encode()
    ts = str(int(time.time()))
    r = _post(client, VALID_BODY, ts=ts, sig=_sign(raw, ts, secret="wrong-secret"))
    assert r.status_code == 401


def test_stale_timestamp_rejected(client):
    r = _post(client, VALID_BODY, ts=str(int(time.time()) - 600))
    assert r.status_code == 401


def test_garbage_timestamp_rejected(client):
    r = _post(client, VALID_BODY, ts="not-a-number")
    assert r.status_code == 401


def test_replay_rejected(client):
    raw = json.dumps(VALID_BODY).encode()
    ts = str(int(time.time()))
    sig = _sign(raw, ts)
    assert _post(client, VALID_BODY, ts=ts, sig=sig).status_code == 202
    assert _post(client, VALID_BODY, ts=ts, sig=sig).status_code == 409


def test_tampered_body_rejected(client):
    raw = json.dumps(VALID_BODY).encode()
    ts = str(int(time.time()))
    sig = _sign(raw, ts)
    tampered = dict(VALID_BODY, amount=1.0)
    r = _post(client, tampered, ts=ts, sig=sig)
    assert r.status_code == 401


def test_invalid_payload_schema_rejected(client):
    r = _post(client, {"not": "an alert"})
    assert r.status_code == 400


def test_rate_limit_enforced(client, monkeypatch):
    from ..config import settings

    monkeypatch.setattr(settings, "webhook_rate_limit_max", 3)
    statuses = [_post(client, VALID_BODY).status_code for _ in range(4)]
    # First succeeds, replays get 409, 4th blocked by rate limit regardless
    assert statuses[-1] == 429


def test_healthz_unauthenticated(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
