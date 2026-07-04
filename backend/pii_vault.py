"""Encrypted PII vault — server-side storage of token→original mappings.

The pii_map produced by tokenize_alert() is encrypted with Fernet
(AES-128-CBC + HMAC-SHA256) before it touches PostgreSQL. The key is
derived from FRAUDOS_TOKEN_SECRET, so raw PII is never stored in
plaintext and is only recoverable by the running application.

Retrieval is restricted to ADMIN/SUPERVISOR roles and every access is
audit-logged (see the /api/investigations/{case_id}/pii endpoint).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os

import asyncpg
from cryptography.fernet import Fernet, InvalidToken

_logger = logging.getLogger(__name__)

_fernet_instance: Fernet | None = None


def _get_fernet() -> Fernet:
    """Derive a stable Fernet key from FRAUDOS_TOKEN_SECRET."""
    global _fernet_instance
    if _fernet_instance is None:
        secret = os.getenv("FRAUDOS_TOKEN_SECRET")
        if not secret:
            raise RuntimeError("FRAUDOS_TOKEN_SECRET environment variable must be set")
        # Domain-separated derivation so the vault key differs from the HMAC tokenization key
        digest = hashlib.sha256(f"fraudos-pii-vault:{secret}".encode()).digest()
        _fernet_instance = Fernet(base64.urlsafe_b64encode(digest))
    return _fernet_instance


async def store_pii_map(
    conn: asyncpg.Connection,
    case_id: str,
    pii_map: dict[str, str],
) -> None:
    """Encrypt and persist the token→original mapping for a case."""
    if not pii_map:
        return
    ciphertext = _get_fernet().encrypt(json.dumps(pii_map).encode()).decode()
    await conn.execute(
        """
        INSERT INTO pii_vault (case_id, encrypted_map, token_count)
        VALUES ($1, $2, $3)
        ON CONFLICT (case_id) DO NOTHING
        """,
        case_id,
        ciphertext,
        len(pii_map),
    )


async def fetch_pii_map(
    conn: asyncpg.Connection,
    case_id: str,
) -> dict[str, str] | None:
    """Decrypt and return the token→original mapping, or None if absent."""
    row = await conn.fetchrow(
        "SELECT encrypted_map FROM pii_vault WHERE case_id = $1", case_id
    )
    if row is None:
        return None
    try:
        plaintext = _get_fernet().decrypt(row["encrypted_map"].encode())
    except InvalidToken:
        _logger.error(
            "PII vault decryption failed for case=%s — FRAUDOS_TOKEN_SECRET may have changed",
            case_id,
        )
        return None
    return json.loads(plaintext)
