"""Shared validation and transaction helpers for control-plane admin routes."""

from __future__ import annotations

import ipaddress

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.db.models import AdminUser, MaskingPolicy, Upstream


async def commit_or_409(session: AsyncSession, conflict_detail: str) -> None:
    """Commit the current transaction or rollback and raise 409 Conflict."""
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=conflict_detail,
        ) from exc


def validate_cidrs(cidrs: list[str]) -> list[str]:
    """Validate and normalize IP/CIDR strings."""
    cleaned: list[str] = []
    for raw in cidrs:
        item = raw.strip()
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid CIDR or IP address '{item}': {exc}",
            ) from exc
        cleaned.append(item)
    return cleaned


async def ensure_targets_exist(
    session: AsyncSession,
    *,
    tenant_id: str,
    upstream_id: str | None = None,
    policy_id: str | None = None,
) -> None:
    """Ensure referenced Upstream and MaskingPolicy belong to *tenant_id*."""
    if upstream_id is not None:
        up = (
            await session.execute(
                select(Upstream.id).where(
                    Upstream.id == upstream_id,
                    Upstream.tenant_id == tenant_id,
                )
            )
        ).first()
        if up is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Selected upstream does not exist.",
            )
    if policy_id is not None:
        pol = (
            await session.execute(
                select(MaskingPolicy.id).where(
                    MaskingPolicy.id == policy_id,
                    MaskingPolicy.tenant_id == tenant_id,
                )
            )
        ).first()
        if pol is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Selected policy does not exist.",
            )


async def count_active_platform_admins(session: AsyncSession, tenant_id: str) -> int:
    """Return the count of active ``platform_admin`` accounts in *tenant_id*."""
    stmt = select(func.count(AdminUser.id)).where(
        AdminUser.tenant_id == tenant_id,
        AdminUser.role == "platform_admin",
        AdminUser.is_active.is_(True),
    )
    return int((await session.execute(stmt)).scalar_one() or 0)
