"""Session-cookie authentication for FraudOS."""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from .database import get_db

_SESSION_HOURS = 8
_FRAUDOS_ENV = os.getenv("FRAUDOS_ENV", "development")

router = APIRouter()


class _LoginRequest(BaseModel):
    api_key: str


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="fraudos_session",
        value=token,
        httponly=True,
        secure=True,  # browsers exempt localhost from Secure requirement
        samesite="strict",
        path="/",
        max_age=_SESSION_HOURS * 3600,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie("fraudos_session", path="/")


@router.post("/auth")
async def login(body: _LoginRequest, response: Response):
    expected = os.getenv("FRAUDOS_API_KEY", "dev-key-change-in-production")
    if body.api_key != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=_SESSION_HOURS)

    async with get_db() as conn:
        await conn.execute(
            "INSERT INTO sessions (session_token, api_key_suffix, created_at, expires_at)"
            " VALUES ($1, $2, $3, $4)",
            token,
            body.api_key[-4:],
            now,
            expires,
        )

    _set_session_cookie(response, token)
    return {"authenticated": True}


@router.get("/auth/me")
async def me(request: Request):
    session = await get_current_session(request)
    return {"authenticated": True, "api_key_suffix": session["api_key_suffix"]}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("fraudos_session")
    if token:
        async with get_db() as conn:
            await conn.execute("DELETE FROM sessions WHERE session_token = $1", token)
    _clear_session_cookie(response)
    return {"logged_out": True}


async def get_current_session(request: Request) -> dict:
    """FastAPI dependency — validates session cookie, returns session row or raises 401."""
    token = request.cookies.get("fraudos_session")

    # Development fallback: accept X-API-Key header when FRAUDOS_ENV=development
    if token is None and _FRAUDOS_ENV == "development":
        api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
        if api_key:
            expected = os.getenv("FRAUDOS_API_KEY", "dev-key-change-in-production")
            if api_key == expected:
                return {"api_key_suffix": api_key[-4:]}

    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    async with get_db() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sessions WHERE session_token = $1 AND expires_at > NOW()",
            token,
        )

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    return dict(row)
