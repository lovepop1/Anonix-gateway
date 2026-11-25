"""Admin session JWT issuance and verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt


def create_admin_token(
    *,
    admin_id: str,
    email: str,
    role: str,
    tenant_id: str,
    secret: str,
    ttl_minutes: int = 480,
) -> str:
    """Create a signed HS256 JWT for an authenticated admin user."""
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": admin_id,
        "email": email,
        "role": role,
        "tenant_id": tenant_id,
        "typ": "anonix_admin",
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_admin_token(token: str, secret: str) -> dict[str, Any]:
    """Verify and decode an admin JWT; raises ``jwt.PyJWTError`` on failure."""
    decoded: dict[str, Any] = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"require": ["sub", "role", "tenant_id", "exp", "typ"]},
    )
    if decoded.get("typ") != "anonix_admin":
        raise jwt.InvalidTokenError("Invalid admin token type.")
    return decoded
