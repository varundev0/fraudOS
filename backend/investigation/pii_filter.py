"""PII tokenization — strips identifiable data before sending to Claude."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

from ..models import FraudAlert

_MAX_FIELD_LEN = 500

# Field-key sets that trigger whole-value tokenization
_NAME_FIELDS = {"name", "full_name", "account_holder", "customer_name"}
_MERCHANT_FIELDS = {"merchant_name", "payee_name", "beneficiary_name"}
_ADDRESS_FIELDS = {"address", "billing_address", "residential_address", "registered_address"}

# Inline-regex patterns (applied when no key match)
# Email must come before UPI so that foo@gmail.com (has TLD) is caught first
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
# UPI IDs: word@word with NO dot in the domain part (e.g. rajesh@okicici)
_UPI_RE = re.compile(r"\b[a-zA-Z0-9._+\-]+@[a-zA-Z0-9]+\b")
_PHONE_RE = re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")


def _hmac_hash(value: str) -> str:
    secret = os.getenv("FRAUDOS_TOKEN_SECRET", "default-insecure-secret-change-me")
    return hmac.new(
        secret.encode(), value.encode(), hashlib.sha256
    ).hexdigest()[:12].upper()


def _tokenize_value(key: str, value: Any, mapping: dict[str, str]) -> Any:
    if not isinstance(value, str):
        return value

    if len(value) > _MAX_FIELD_LEN:
        raise ValueError("Field exceeds maximum length")

    lower_key = key.lower()

    if lower_key in _NAME_FIELDS:
        token = f"USR-{_hmac_hash(value)}"
        mapping[token] = value
        return token

    if lower_key in _MERCHANT_FIELDS:
        token = f"MER-{_hmac_hash(value)}"
        mapping[token] = value
        return token

    if lower_key in _ADDRESS_FIELDS:
        token = f"ADDR-{_hmac_hash(value)}"
        mapping[token] = value
        return token

    # Inline regex replacements — email before UPI to avoid double-matching
    def _replace_email(m: re.Match) -> str:
        tok = f"EML-{_hmac_hash(m.group())}"
        mapping[tok] = m.group()
        return tok

    value = _EMAIL_RE.sub(_replace_email, value)

    def _replace_upi(m: re.Match) -> str:
        # Skip if already tokenized (token format won't match UPI pattern, but guard anyway)
        if m.group().startswith(("EML-", "USR-", "MER-", "ADDR-", "PHN-", "UPI-")):
            return m.group()
        tok = f"UPI-{_hmac_hash(m.group())}"
        mapping[tok] = m.group()
        return tok

    value = _UPI_RE.sub(_replace_upi, value)

    def _replace_phone(m: re.Match) -> str:
        tok = f"PHN-{_hmac_hash(m.group())}"
        mapping[tok] = m.group()
        return tok

    value = _PHONE_RE.sub(_replace_phone, value)

    return value


def _walk_dict(data: dict, mapping: dict[str, str]) -> dict:
    result = {}
    for k, v in data.items():
        if isinstance(v, dict):
            result[k] = _walk_dict(v, mapping)
        elif isinstance(v, list):
            result[k] = [
                _walk_dict(item, mapping) if isinstance(item, dict)
                else _tokenize_value(k, item, mapping)
                for item in v
            ]
        else:
            result[k] = _tokenize_value(k, v, mapping)
    return result


def tokenize_alert(alert: FraudAlert) -> tuple[dict, dict[str, str]]:
    """Return (tokenized_payload, token_to_original_mapping).

    The mapping is stored server-side only and must never be sent to Claude.
    Amounts, transaction IDs, merchant IDs, and timestamps are left intact.
    Raises ValueError if any field exceeds the maximum allowed length.
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
