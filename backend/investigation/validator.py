"""Layer 2: Input validation — sanitises alert fields before processing."""

from __future__ import annotations

import logging
import re

from ..models import FraudAlert

_logger = logging.getLogger(__name__)

# Allowed characters in entity_data string values
_ENTITY_DATA_RE = re.compile(r"^[a-zA-Z0-9@._\-\s/,]*$")
# Allowed characters in transaction_id
_TXN_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]+$")
# Allowed characters in rule_trigger — rule-engine expressions, not free prose.
# SECURITY: rule_trigger is sent to Claude untokenized, so restrict its charset
# to close it off as a prompt-injection channel.
_RULE_TRIGGER_RE = re.compile(r"^[a-zA-Z0-9 ._\-:,;()><=%/&+*'\"\[\]]*$")

_MAX_ENTITY_FIELD_LEN = 500
_MAX_RULE_TRIGGER_LEN = 1000


def _check_entity_dict(data: dict, path: str = "entity_data") -> None:
    """Recursively validate all string fields inside entity_data."""
    for key, value in data.items():
        field_path = f"{path}.{key}"
        if isinstance(value, dict):
            _check_entity_dict(value, field_path)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    _check_entity_dict(item, f"{field_path}[{i}]")
                elif isinstance(item, str):
                    _validate_entity_string(item, f"{field_path}[{i}]")
        elif isinstance(value, str):
            _validate_entity_string(value, field_path)


def _validate_entity_string(value: str, path: str) -> None:
    if len(value) > _MAX_ENTITY_FIELD_LEN:
        raise ValueError(f"Field '{path}' exceeds {_MAX_ENTITY_FIELD_LEN} characters")
    if not _ENTITY_DATA_RE.match(value):
        raise ValueError(f"Field '{path}' contains disallowed characters")


def validate_alert(alert: FraudAlert) -> None:
    """Validate a FraudAlert and raise ValueError if any constraint is violated.

    Logs a WARNING on failure but the caller is responsible for not propagating
    the detailed message to API consumers.
    """
    try:
        _do_validate(alert)
    except ValueError as exc:
        _logger.warning("Input validation failed: %s", exc)
        raise


def _do_validate(alert: FraudAlert) -> None:
    if alert.amount <= 0:
        raise ValueError("amount must be positive")

    if not _TXN_ID_RE.match(alert.transaction_id):
        raise ValueError("transaction_id contains disallowed characters")

    if len(alert.rule_trigger) > _MAX_RULE_TRIGGER_LEN:
        raise ValueError(f"rule_trigger exceeds {_MAX_RULE_TRIGGER_LEN} characters")

    if not _RULE_TRIGGER_RE.match(alert.rule_trigger):
        raise ValueError("rule_trigger contains disallowed characters")

    _check_entity_dict(alert.entity_data)
