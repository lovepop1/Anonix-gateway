"""Control-plane ApiKey CRUD and revocation routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.db.models import ApiKey
from anonix_gateway.db.session import get_session
from anonix_gateway.schemas.admin import (
    ApiKeyCreateOut,
    ApiKeyOut,
    ApiKeyRevokeOut,
    ApiKeyUpdateOut,
)
from anonix_gateway.security.crypto import generate_api_key

router = APIRouter()


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    groups: list[str] = Field(min_length=1)
    allowed_policy_ids: list[str] | None = None
    expires_at: datetime | None = None


class ApiKeyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    groups: list[str] | None = None
    is_active: bool | None = None


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[ApiKeyOut]:
    stmt = select(ApiKey).where(ApiKey.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        ApiKeyOut(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            groups=k.groups,
            allowed_policy_ids=k.allowed_policy_ids,
            is_active=k.is_active,
            expires_at=k.expires_at,
            last_used_at=k.last_used_at,
        )
        for k in rows
    ]


@router.post(
    "/api-keys",
    response_model=ApiKeyCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    body: ApiKeyCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyCreateOut:
    groups = [g.strip() for g in body.groups if g.strip()]
    if not groups:
        raise HTTPException(status_code=422, detail="At least one non-empty group is required.")
    raw_key, key_prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        tenant_id=admin.tenant_id,
        name=body.name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        groups=groups,
        allowed_policy_ids=body.allowed_policy_ids,
        is_active=True,
        expires_at=body.expires_at,
    )
    session.add(api_key)
    await session.commit()
    return ApiKeyCreateOut(
        id=api_key.id,
        name=api_key.name,
        key_prefix=key_prefix,
        raw_key=raw_key,
        groups=api_key.groups,
    )


@router.post("/api-keys/{key_id}/revoke", response_model=ApiKeyRevokeOut)
async def revoke_api_key(
    key_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyRevokeOut:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == admin.tenant_id)
    api_key = (await session.execute(stmt)).scalars().first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    api_key.is_active = False
    await session.commit()
    return ApiKeyRevokeOut(status="revoked", id=api_key.id)


@router.patch("/api-keys/{key_id}", response_model=ApiKeyUpdateOut)
async def update_api_key(
    key_id: str,
    body: ApiKeyUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> ApiKeyUpdateOut:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == admin.tenant_id)
    api_key = (await session.execute(stmt)).scalars().first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    if body.name is not None:
        api_key.name = body.name.strip()
    if body.groups is not None:
        groups = [g.strip() for g in body.groups if g.strip()]
        if not groups:
            raise HTTPException(status_code=422, detail="At least one non-empty group is required.")
        api_key.groups = groups
    if body.is_active is not None:
        api_key.is_active = body.is_active
    await session.commit()
    return ApiKeyUpdateOut(
        id=api_key.id,
        name=api_key.name,
        groups=api_key.groups,
        is_active=api_key.is_active,
    )


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == admin.tenant_id)
    api_key = (await session.execute(stmt)).scalars().first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    await session.delete(api_key)
    await session.commit()
