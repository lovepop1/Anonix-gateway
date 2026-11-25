"""Control-plane Upstream CRUD routes with SSRF validation and credential encryption."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.config import get_settings
from anonix_gateway.db.models import Upstream
from anonix_gateway.db.session import get_session
from anonix_gateway.proxy.ssrf import validate_upstream_url
from anonix_gateway.routes.admin.helpers import commit_or_409
from anonix_gateway.schemas.admin import UpstreamOut, UpstreamRefOut
from anonix_gateway.security.crypto import encrypt_secret

router = APIRouter()


class UpstreamCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_url: str = Field(min_length=1, max_length=512)
    auth_type: str = Field(default="none", pattern="^(none|bearer|api_key_header|basic)$")
    auth_header_name: str | None = None
    credential: str | None = None
    timeout_seconds: float = Field(default=15.0, ge=0.5, le=120.0)


class UpstreamUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    base_url: str | None = Field(default=None, min_length=1, max_length=512)
    auth_type: str | None = Field(default=None, pattern="^(none|bearer|api_key_header|basic)$")
    auth_header_name: str | None = None
    credential: str | None = None
    timeout_seconds: float | None = Field(default=None, ge=0.5, le=120.0)
    is_active: bool | None = None


@router.get("/upstreams", response_model=list[UpstreamOut])
async def list_upstreams(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[UpstreamOut]:
    stmt = select(Upstream).where(Upstream.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        UpstreamOut(
            id=u.id,
            name=u.name,
            base_url=u.base_url,
            auth_type=u.auth_type,
            auth_header_name=u.auth_header_name,
            has_credential=bool(u.encrypted_credential),
            timeout_seconds=u.timeout_seconds,
            is_active=u.is_active,
        )
        for u in rows
    ]


@router.post(
    "/upstreams",
    response_model=UpstreamRefOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_upstream(
    body: UpstreamCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> UpstreamRefOut:
    settings = get_settings()
    try:
        clean_url = validate_upstream_url(
            body.base_url, allow_private=settings.allow_private_upstreams
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    master_key, _ = settings.resolve_secrets()
    cred_value = body.credential
    if body.auth_type == "basic" and cred_value and ":" in cred_value:
        cred_value = base64.b64encode(cred_value.encode("utf-8")).decode("ascii")
    encrypted_cred = encrypt_secret(cred_value, master_key) if cred_value else None

    upstream = Upstream(
        tenant_id=admin.tenant_id,
        name=body.name.strip(),
        base_url=clean_url,
        auth_type=body.auth_type,
        auth_header_name=body.auth_header_name.strip() if body.auth_header_name else None,
        encrypted_credential=encrypted_cred,
        timeout_seconds=body.timeout_seconds,
        is_active=True,
    )
    session.add(upstream)
    await commit_or_409(session, f"Upstream '{upstream.name}' already exists.")
    return UpstreamRefOut(id=upstream.id, name=upstream.name, base_url=upstream.base_url)


@router.patch("/upstreams/{upstream_id}", response_model=UpstreamRefOut)
async def update_upstream(
    upstream_id: str,
    body: UpstreamUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> UpstreamRefOut:
    stmt = select(Upstream).where(
        Upstream.id == upstream_id,
        Upstream.tenant_id == admin.tenant_id,
    )
    upstream = (await session.execute(stmt)).scalars().first()
    if upstream is None:
        raise HTTPException(status_code=404, detail="Upstream not found.")

    settings = get_settings()
    if body.name is not None:
        upstream.name = body.name.strip()
    if body.base_url is not None:
        try:
            upstream.base_url = validate_upstream_url(
                body.base_url, allow_private=settings.allow_private_upstreams
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    if body.auth_type is not None:
        upstream.auth_type = body.auth_type
        if body.auth_type == "none":
            upstream.encrypted_credential = None
    if body.auth_header_name is not None:
        upstream.auth_header_name = body.auth_header_name.strip() or None
    if body.credential:
        master_key, _ = settings.resolve_secrets()
        cred_value = body.credential
        if upstream.auth_type == "basic" and ":" in cred_value:
            cred_value = base64.b64encode(cred_value.encode("utf-8")).decode("ascii")
        upstream.encrypted_credential = encrypt_secret(cred_value, master_key)
    if body.timeout_seconds is not None:
        upstream.timeout_seconds = body.timeout_seconds
    if body.is_active is not None:
        upstream.is_active = body.is_active

    await commit_or_409(session, f"Upstream '{upstream.name}' already exists.")
    return UpstreamRefOut(id=upstream.id, name=upstream.name, base_url=upstream.base_url)


@router.delete("/upstreams/{upstream_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_upstream(
    upstream_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(Upstream).where(
        Upstream.id == upstream_id,
        Upstream.tenant_id == admin.tenant_id,
    )
    upstream = (await session.execute(stmt)).scalars().first()
    if upstream is None:
        raise HTTPException(status_code=404, detail="Upstream not found.")
    await session.delete(upstream)
    await session.commit()
