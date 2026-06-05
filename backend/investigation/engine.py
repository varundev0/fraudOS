"""Core fraud investigation engine — calls Claude and assembles the report."""

from __future__ import annotations

import json
import os
import time
import uuid

import anthropic

from ..models import (
    FraudAlert,
    InvestigationReport,
    RecommendedAction,
    RiskLevel,
)
from .pii_filter import tokenize_alert
from .prompts import SYSTEM_PROMPT, build_investigation_prompt


def _risk_level_from_score(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


_FALLBACK_REPORT_KWARGS = {
    "risk_score": 50,
    "risk_level": RiskLevel.MEDIUM,
    "entity_profile": {"summary": "Unavailable", "risk_indicators": [], "account_age_assessment": "Unavailable"},
    "transaction_pattern": {"pattern_type": "Unknown", "anomalies": [], "velocity_assessment": "Unavailable"},
    "risk_assessment": "Automated investigation unavailable — manual review required.",
    "recommended_action": RecommendedAction.REVIEW,
    "confidence": 0.0,
    "investigation_narrative": "Automated investigation unavailable — manual review required.",
    "flags": ["INVESTIGATION_ENGINE_ERROR"],
}


class InvestigationEngine:
    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = os.getenv("MODEL", "claude-opus-4-6")

    async def investigate(self, alert: FraudAlert) -> InvestigationReport:
        start_ms = int(time.time() * 1000)

        try:
            tokenized_payload, _pii_map = tokenize_alert(alert)
            user_prompt = build_investigation_prompt(tokenized_payload)

            response = self._client.messages.create(
                model=self._model,
                max_tokens=1500,
                temperature=0,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            raw_text = next(
                (block.text for block in response.content if block.type == "text"),
                "",
            )
            parsed = json.loads(raw_text)

        except anthropic.APIError as exc:
            elapsed = int(time.time() * 1000) - start_ms
            return InvestigationReport(
                alert_id=alert.transaction_id,
                processing_time_ms=elapsed,
                model_used=self._model,
                **_FALLBACK_REPORT_KWARGS,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            elapsed = int(time.time() * 1000) - start_ms
            return InvestigationReport(
                alert_id=alert.transaction_id,
                processing_time_ms=elapsed,
                model_used=self._model,
                **_FALLBACK_REPORT_KWARGS,
            )

        elapsed = int(time.time() * 1000) - start_ms

        risk_score = int(parsed.get("risk_score", 50))
        risk_score = max(0, min(100, risk_score))

        return InvestigationReport(
            case_id=uuid.uuid4(),
            alert_id=alert.transaction_id,
            risk_score=risk_score,
            risk_level=_risk_level_from_score(risk_score),
            entity_profile=parsed.get("entity_profile", {}),
            transaction_pattern=parsed.get("transaction_pattern", {}),
            risk_assessment=parsed.get("risk_assessment", ""),
            recommended_action=RecommendedAction(
                parsed.get("recommended_action", RecommendedAction.REVIEW)
            ),
            confidence=float(parsed.get("confidence", 0.5)),
            investigation_narrative=parsed.get("investigation_narrative", ""),
            flags=parsed.get("flags", []),
            processing_time_ms=elapsed,
            model_used=response.model,
        )
