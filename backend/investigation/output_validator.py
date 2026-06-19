"""Layer 3: Output sanitization — validates and sanitises Claude's JSON response."""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field, field_validator, ValidationError

_logger = logging.getLogger(__name__)

_FORBIDDEN_FRAGMENTS = [
    "CRITICAL DIRECTIVES",
    "DATA_PAYLOAD",
    "system prompt",
    "system instructions",
    "FRAUDOS_",
    "your instructions",
]

_MAX_FLAGS = 20
_MAX_FLAG_LEN = 200
_MAX_NARRATIVE_LEN = 2000
_MAX_RISK_ASSESSMENT_LEN = 2000
_MAX_RAW_OUTPUT_BYTES = 32_768   # 32 KB hard ceiling on total Claude response
_MAX_NESTED_STR_LEN = 1000       # per-string limit inside entity_profile / transaction_pattern

_VALID_ACTIONS = {"CLEAR", "REVIEW", "ESCALATE", "BLOCK"}


def _check_nested_dict_strings(data: dict, path: str = "") -> None:
    """Recursively validate string lengths inside untyped nested dicts."""
    for k, v in data.items():
        field_path = f"{path}.{k}" if path else k
        if isinstance(v, str) and len(v) > _MAX_NESTED_STR_LEN:
            raise ValueError(f"Field '{field_path}' exceeds {_MAX_NESTED_STR_LEN} characters")
        elif isinstance(v, dict):
            _check_nested_dict_strings(v, field_path)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, str) and len(item) > _MAX_NESTED_STR_LEN:
                    raise ValueError(f"Field '{field_path}[{i}]' exceeds {_MAX_NESTED_STR_LEN} characters")
                elif isinstance(item, dict):
                    _check_nested_dict_strings(item, f"{field_path}[{i}]")


class _ClaudeOutput(BaseModel):
    entity_profile: dict
    transaction_pattern: dict
    risk_assessment: str
    recommended_action: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    flags: list[str]
    investigation_narrative: str

    @field_validator("recommended_action")
    @classmethod
    def _check_action(cls, v: str) -> str:
        if v not in _VALID_ACTIONS:
            raise ValueError(f"Invalid recommended_action '{v}'")
        return v

    @field_validator("risk_assessment")
    @classmethod
    def _check_risk_assessment(cls, v: str) -> str:
        if len(v) > _MAX_RISK_ASSESSMENT_LEN:
            raise ValueError(f"risk_assessment exceeds {_MAX_RISK_ASSESSMENT_LEN} characters")
        return v

    @field_validator("flags")
    @classmethod
    def _check_flags(cls, v: list[str]) -> list[str]:
        if len(v) > _MAX_FLAGS:
            raise ValueError(f"flags list exceeds maximum of {_MAX_FLAGS} items")
        for flag in v:
            if len(flag) > _MAX_FLAG_LEN:
                raise ValueError(f"flag item exceeds {_MAX_FLAG_LEN} characters")
        return v

    @field_validator("investigation_narrative")
    @classmethod
    def _check_narrative(cls, v: str) -> str:
        if len(v) > _MAX_NARRATIVE_LEN:
            raise ValueError(f"investigation_narrative exceeds {_MAX_NARRATIVE_LEN} characters")
        return v

    @field_validator("entity_profile", "transaction_pattern")
    @classmethod
    def _check_nested_dicts(cls, v: dict) -> dict:
        _check_nested_dict_strings(v)
        return v


def validate_claude_output(raw_text: str) -> dict | None:
    """Validate Claude's raw JSON response.

    Returns the validated dict on success, or None if any security or schema
    check fails.  Logs CRITICAL on security violations.
    """
    # Hard ceiling on total response size before any parsing
    if len(raw_text.encode()) > _MAX_RAW_OUTPUT_BYTES:
        _logger.critical("SECURITY: Claude output exceeds max size (%d bytes)", len(raw_text.encode()))
        return None

    # Scan the raw string for forbidden fragments before parsing
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in raw_text:
            _logger.critical(
                "SECURITY: Forbidden fragment %r found in Claude output — "
                "possible prompt injection or data leakage",
                fragment,
            )
            return None

    try:
        parsed = _ClaudeOutput.model_validate_json(raw_text)
    except ValidationError as exc:
        _logger.critical("SECURITY: Output schema validation failed: %s", exc)
        return None
    except Exception as exc:
        _logger.critical("SECURITY: Unexpected error parsing Claude output: %s", exc)
        return None

    return parsed.model_dump()
