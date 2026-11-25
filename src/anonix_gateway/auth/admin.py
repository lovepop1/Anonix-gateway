"""Control-plane administrator authentication and RBAC dependencies."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.config import get_settings
from anonix_gateway.db.models import AdminUser
from anonix_gateway.db.session import get_session
from anonix_gateway.security.tokens import decode_admin_token

_bearer = HTTPBearer(auto_error=False)

VALID_ADMIN_ROLES = frozenset({"platform_admin", "policy_author", "auditor"})


@dataclass(frozen=True)
class AdminContext:
    """Authenticated control-plane administrator context."""

    admin_id: str
    email: str
    role: str
    tenant_id: str


async def get_current_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_session),
) -> AdminContext:
    """Validate the admin Bearer JWT and return :class:`AdminContext`."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required.",
        )

    settings = get_settings()
    _, jwt_secret = settings.resolve_secrets()
    try:
        payload = decode_admin_token(credentials.credentials, jwt_secret)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid admin token: {exc}",
        ) from exc

    stmt = select(AdminUser).where(
        AdminUser.id == payload["sub"],
        AdminUser.is_active.is_(True),
    )
    res = await session.execute(stmt)
    admin = res.scalars().first()
    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin account is inactive or does not exist.",
        )

    return AdminContext(
        admin_id=admin.id,
        email=admin.email,
        role=admin.role,
        tenant_id=admin.tenant_id,
    )


def require_admin_roles(
    *allowed_roles: str,
) -> Callable[[AdminContext], Coroutine[Any, Any, AdminContext]]:
    """Return a FastAPI dependency enforcing one of *allowed_roles*."""
    allowed = frozenset(allowed_roles)

    async def _dependency(admin: AdminContext = Depends(get_current_admin)) -> AdminContext:
        if admin.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient admin role '{admin.role}'. Required: {sorted(allowed)}.",
            )
        return admin

    return _dependency
