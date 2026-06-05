from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AlertType(str, Enum):
    UPI_FRAUD = "UPI_FRAUD"
    CARD_FRAUD = "CARD_FRAUD"
    AML = "AML"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    SYNTHETIC_IDENTITY = "SYNTHETIC_IDENTITY"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendedAction(str, Enum):
    CLEAR = "CLEAR"
    REVIEW = "REVIEW"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class FraudAlert(BaseModel):
    transaction_id: str
    amount: float
    currency: str = "INR"
    entity_data: dict
    rule_trigger: str
    alert_type: AlertType
    merchant_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class InvestigationReport(BaseModel):
    case_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    alert_id: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    entity_profile: dict
    transaction_pattern: dict
    risk_assessment: str
    recommended_action: RecommendedAction
    confidence: float = Field(ge=0.0, le=1.0)
    investigation_narrative: str
    flags: list[str]
    processing_time_ms: int
    model_used: str
    constitutional_check_passed: bool = True
    canary: str = ""


class InvestigateRequest(BaseModel):
    alert: FraudAlert
    include_narrative: bool = True


class InvestigateResponse(BaseModel):
    success: bool
    report: Optional[InvestigationReport] = None
    error: Optional[str] = None
