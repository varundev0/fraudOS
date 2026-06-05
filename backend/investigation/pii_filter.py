"""PII tokenization — strips identifiable data before sending to Claude."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ..models import FraudAlert


_PHONE_RE = re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_NAME_FIELDS = {"name", "full_name", "account_holder", "customer_name", "beneficiary_name"}
_ADDRESS_FIELDS = {"address", "billing_address", "residential_address", "registered_address"}


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8].upper()


def _tokenize_value(key: str, value: Any, mapping: dict[str, str]) -> Any:
    if not isinstance(value, str):
        return value

    lower_key = key.lower()

    if lower_key in _NAME_FIELDS:
        token = f"USR-{_short_hash(value)}"
        mapping[token] = value
        return token

    if lower_key in _ADDRESS_FIELDS:
        token = f"ADDR-{_short_hash(value)}"
        mapping[token] = value
        return token

    # Replace phone numbers embedded in string values
    def replace_phone(m: re.Match) -> str:
        tok = f"PHN-{_short_hash(m.group())}"
        mapping[tok] = m.group()
        return tok

    value = _PHONE_RE.sub(replace_phone, value)

    def replace_email(m: re.Match) -> str:
        tok = f"EML-{_short_hash(m.group())}"
        mapping[tok] = m.group()
        return tok

    value = _EMAIL_RE.sub(replace_email, value)

    return value


def _walk_dict(data: dict, mapping: dict[str, str]) -> dict:
    result = {}
    for k, v in data.items():
        if isinstance(v, dict):
            result[k] = _walk_dict(v, mapping)
        elif isinstance(v, list):
            result[k] = [
                _walk_dict(item, mapping) if isinstance(item, dict) else _tokenize_value(k, item, mapping)
                for item in v
            ]
        else:
            result[k] = _tokenize_value(k, v, mapping)
    return result


def tokenize_alert(alert: FraudAlert) -> tuple[dict, dict[str, str]]:
    """Return (tokenized_payload, token_to_original_mapping).

    The mapping is stored server-side only and must never be sent to Claude.
    Amounts, transaction IDs, merchant IDs, and timestamps are left intact.
    """
    mapping: dict[str, str] = {}
    tokenized_entity = _walk_dict(alert.entity_data, mapping)

    payload = {
        "transaction_id": alert.transaction_id,
        "amount": alert.amount,
        "currency": alert.currency,
        "rule_trigger": alert.rule_trigger,
        "alert_type": alert.alert_type.value,
        "merchant_id": alert.merchant_id,
        "timestamp": alert.timestamp.isoformat(),
        "entity_data": tokenized_entity,
    }
    return payload, mapping
