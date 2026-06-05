"""FraudOS FastAPI application."""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .investigation.engine import InvestigationEngine
from .models import InvestigateRequest, InvestigateResponse, FraudAlert
from .tests.synthetic_alerts import SYNTHETIC_ALERTS

app = FastAPI(
    title="FraudOS",
    description="AI-native fraud investigation engine",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_engine = InvestigationEngine()

_MODEL = os.getenv("MODEL", "claude-opus-4-6")
_VERSION = "0.1.0"


def _verify_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    expected = os.getenv("FRAUDOS_API_KEY", "dev-key-change-in-production")
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )


@app.get("/api/health")
async def health():
    return {"status": "ok", "model": _MODEL, "version": _VERSION}


@app.get("/api/test-cases")
async def test_cases(_: None = Depends(_verify_api_key)):
    return {"cases": [alert.model_dump(mode="json") for alert in SYNTHETIC_ALERTS]}


@app.post("/api/investigate", response_model=InvestigateResponse)
async def investigate(
    request: InvestigateRequest,
    _: None = Depends(_verify_api_key),
):
    try:
        report = await _engine.investigate(request.alert)
        return InvestigateResponse(success=True, report=report)
    except Exception as exc:
        return InvestigateResponse(success=False, error=str(exc))
