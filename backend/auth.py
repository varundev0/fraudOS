"""Session-cookie authentication for FraudOS — multi-user email/password auth."""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from passlib.context import CryptContext
from pydantic import BaseModel

from .config import settings
from .database import get_db

_FRAUDOS_ENV = os.getenv("FRAUDOS_ENV", "development")
_logger = logging.getLogger(__name__)
_audit_log = logging.getLogger("fraudos.audit")

# bcrypt password hashing — auto-rehashes on verify if cost factor changes
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()


# ── Request / response models ─────────────────────────────────────────────────

class _LoginRequest(BaseModel):
    email: str
    password: str


class _CreateUserRequest(BaseModel):
    email: str
    password: str
    full_name: str = ""
    role: str = "ANALYST"


class _UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None


# ── Cookie helpers ─────────────────────────────────────────────────────────────

def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key="fraudos_session",
        value=token,
        httponly=True,
        secure=_FRAUDOS_ENV != "development",
        samesite="strict",
        path="/",
        max_age=settings.session_hours * 3600,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie("fraudos_session", path="/")


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/auth")
async def login(body: _LoginRequest, response: Response, request: Request):
    email = body.email.lower().strip()
    async with get_db() as conn:
        user = await conn.fetchrow(
            "SELECT id, email, password_hash, full_name, role, is_active FROM users WHERE email = $1",
            email,
        )

    # Constant-time path — always run verify even if user not found (prevents timing oracle)
    dummy_hash = "$2b$12$KIXHj1HxIVHVvKoL1i3Cz.LQVzGvF5kDmMfkH5KANpYlNjWJFE/rC"
    password_hash = user["password_hash"] if user else dummy_hash
    valid = _pwd_ctx.verify(body.password, password_hash)

    if not user or not valid:
        _audit_log.warning("LOGIN_FAILED email=%s ip=%s", email, request.client.host if request.client else "unknown")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=settings.session_hours)

    async with get_db() as conn:
        await conn.execute(
            "INSERT INTO sessions (session_token, user_id, user_email, user_role, full_name, created_at, expires_at)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7)",
            token,
            user["id"],
            user["email"],
            user["role"],
            user["full_name"],
            now,
            expires,
        )
        await conn.execute(
            "UPDATE users SET last_login = $1 WHERE id = $2",
            now, user["id"],
        )

    _audit_log.info("LOGIN email=%s role=%s ip=%s", email, user["role"], request.client.host if request.client else "unknown")
    _set_session_cookie(response, token)
    return {
        "authenticated": True,
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        },
    }


@router.get("/auth/me")
async def me(request: Request):
    session = await get_current_session(request)
    return {
        "authenticated": True,
        "email": session.get("user_email"),
        "full_name": session.get("full_name", ""),
        "role": session.get("user_role"),
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("fraudos_session")
    if token:
        async with get_db() as conn:
            await conn.execute("DELETE FROM sessions WHERE session_token = $1", token)
    _clear_session_cookie(response)
    return {"logged_out": True}


# ── Session dependency ────────────────────────────────────────────────────────

async def get_current_session(request: Request) -> dict:
    """FastAPI dependency — validates session cookie, returns session row or raises 401."""
    token = request.cookies.get("fraudos_session")

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


def require_role(*roles: str):
    """FastAPI dependency factory — enforces that the session user has one of the given roles."""
    async def _dep(session: dict = Depends(get_current_session)) -> dict:
        if session.get("user_role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {' or '.join(roles)}",
            )
        return session
    return _dep


# ── User management (admin only) ──────────────────────────────────────────────

_VALID_ROLES = {"ANALYST", "SUPERVISOR", "ADMIN"}


@router.get("/users")
async def list_users(session: dict = Depends(require_role("ADMIN", "SUPERVISOR"))):
    async with get_db() as conn:
        rows = await conn.fetch(
            "SELECT id, email, full_name, role, is_active, created_at, last_login"
            " FROM users ORDER BY created_at ASC"
        )
    return [dict(r) for r in rows]


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: _CreateUserRequest,
    session: dict = Depends(require_role("ADMIN")),
):
    if body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(_VALID_ROLES)}")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    email = body.email.lower().strip()
    password_hash = _pwd_ctx.hash(body.password)

    try:
        async with get_db() as conn:
            row = await conn.fetchrow(
                "INSERT INTO users (email, password_hash, full_name, role)"
                " VALUES ($1, $2, $3, $4)"
                " RETURNING id, email, full_name, role, is_active, created_at",
                email, password_hash, body.full_name, body.role,
            )
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Email already exists") from exc
        raise

    _audit_log.info("USER_CREATED email=%s role=%s by=%s", email, body.role, session.get("user_email"))
    return dict(row)


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str,
    body: _UpdateUserRequest,
    session: dict = Depends(require_role("ADMIN")),
):
    if body.role is not None and body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(_VALID_ROLES)}")

    # Validate UUID format before hitting the DB
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

    # Prevent admin from deactivating their own account
    async with get_db() as conn:
        target = await conn.fetchrow("SELECT email FROM users WHERE id = $1", user_uuid)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found")
        if body.is_active is False and target["email"] == session.get("user_email"):
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

        updates, params = [], []
        idx = 1
        if body.role is not None:
            updates.append(f"role = ${idx}"); params.append(body.role); idx += 1
        if body.is_active is not None:
            updates.append(f"is_active = ${idx}"); params.append(body.is_active); idx += 1
        if body.full_name is not None:
            updates.append(f"full_name = ${idx}"); params.append(body.full_name); idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        params.append(uuid.UUID(user_id))
        row = await conn.fetchrow(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ${idx}"
            " RETURNING id, email, full_name, role, is_active",
            *params,
        )

    _audit_log.info("USER_UPDATED id=%s by=%s changes=%s", user_id, session.get("user_email"), body.model_dump(exclude_none=True))
    return dict(row)


# ── Admin seeding (called from lifespan) ─────────────────────────────────────

async def seed_admin_user() -> None:
    """Create the default admin account if no users exist yet."""
    password = os.getenv("FRAUDOS_ADMIN_PASSWORD", "")
    if not password:
        if _FRAUDOS_ENV == "development":
            password = "admin123"
            _logger.warning(
                "No FRAUDOS_ADMIN_PASSWORD set — using default dev password."
                " Login: admin@fraudos.local / admin123"
            )
        else:
            raise RuntimeError(
                "FRAUDOS_ADMIN_PASSWORD must be set before first startup in production."
            )

    async with get_db() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM users")
        if count == 0:
            hashed = _pwd_ctx.hash(password)
            await conn.execute(
                "INSERT INTO users (email, password_hash, full_name, role)"
                " VALUES ($1, $2, $3, $4)",
                "admin@fraudos.local",
                hashed,
                "System Admin",
                "ADMIN",
            )
            _logger.info("Seeded default admin: admin@fraudos.local")
