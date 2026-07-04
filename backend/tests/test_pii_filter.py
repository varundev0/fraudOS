"""Unit tests for PII tokenization (Layer 2)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from ..investigation.pii_filter import tokenize_alert
from ..models import AlertType, FraudAlert


def _alert(entity_data: dict) -> FraudAlert:
    return FraudAlert(
        transaction_id="TXN-001",
        amount=50000.0,
        currency="INR",
        entity_data=entity_data,
        rule_trigger="AMOUNT > 10000",
        alert_type=AlertType.UPI_FRAUD,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_name_fields_tokenized():
    payload, mapping = tokenize_alert(_alert({"account_holder": "Rajesh Kumar"}))
    assert "Rajesh Kumar" not in json.dumps(payload)
    token = payload["entity_data"]["account_holder"]
    assert token.startswith("USR-")
    assert mapping[token] == "Rajesh Kumar"


def test_email_and_phone_tokenized_inline():
    payload, mapping = tokenize_alert(
        _alert({"notes": "contact rajesh.k@gmail.com or 9876543210"})
    )
    raw = json.dumps(payload)
    assert "rajesh.k@gmail.com" not in raw
    assert "9876543210" not in raw
    assert "rajesh.k@gmail.com" in mapping.values()
    assert "9876543210" in mapping.values()


def test_upi_id_tokenized():
    payload, mapping = tokenize_alert(_alert({"payment_ref": "rajesh@okicici"}))
    raw = json.dumps(payload)
    assert "rajesh@okicici" not in raw
    assert any(t.startswith("UPI-") for t in mapping)


def test_nested_and_list_values_tokenized():
    payload, mapping = tokenize_alert(
        _alert({"beneficiaries": [{"name": "Amit Shah"}], "device": {"owner_name": "X"}})
    )
    raw = json.dumps(payload)
    assert "Amit Shah" not in raw
    assert "Amit Shah" in mapping.values()


def test_deterministic_tokens():
    _, m1 = tokenize_alert(_alert({"name": "Same Person"}))
    _, m2 = tokenize_alert(_alert({"name": "Same Person"}))
    assert set(m1.keys()) == set(m2.keys())


def test_non_pii_fields_left_intact():
    payload, _ = tokenize_alert(_alert({"account_age_days": 3}))
    assert payload["entity_data"]["account_age_days"] == 3
    assert payload["transaction_id"] == "TXN-001"
    assert payload["amount"] == 50000.0


def test_oversized_field_rejected():
    with pytest.raises(ValueError):
        tokenize_alert(_alert({"notes": "x" * 501}))
