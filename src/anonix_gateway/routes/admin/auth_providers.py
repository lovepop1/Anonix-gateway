"""Control-plane AuthProvider (OIDC / Trusted-Proxy) CRUD routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.config import get_settings
from anonix_gateway.db.models import AuthProvider
from anonix_gateway.db.session import get_session
from anonix_gateway.routes.admin.helpers import commit_or_409, validate_cidrs
from anonix_gateway.schemas.admin import AuthProviderOut, AuthProviderRefOut
from anonix_gateway.security.crypto import encrypt_secret

router = APIRouter()


class AuthProviderCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider_type: str = Field(pattern="^(oidc|trusted_proxy)$")
    is_enabled: bool = True
    issuer_url: str | None = None
    audience: str | None = None
    jwks_url: str | None = None
    groups_claim: str = "groups"
    sub_claim: str = "sub"
    trusted_cidrs: list[str] = Field(default_factory=list)
    proxy_secret: str | None = None


class AuthProviderUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    is_enabled: bool | None = None
    issuer_url: str | None = None
    audience: str | None = None
    jwks_url: str | None = None
    groups_claim: str | None = None
    sub_claim: str | None = None
    trusted_cidrs: list[str] | None = None
    proxy_secret: str | None = None


@router.get("/auth-providers", response_model=list[AuthProviderOut])
async def list_auth_providers(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[AuthProviderOut]:
    stmt = select(AuthProvider).where(AuthProvider.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        AuthProviderOut(
            id=p.id,
            name=p.name,
            provider_type=p.provider_type,
            is_enabled=p.is_enabled,
            issuer_url=p.issuer_url,
            audience=p.audience,
            jwks_url=p.jwks_url,
            groups_claim=p.groups_claim,
            sub_claim=p.sub_claim,
            trusted_cidrs=p.trusted_cidrs,
            has_proxy_secret=bool(p.encrypted_proxy_secret),
            created_at=p.created_at,
        )
        for p in rows
    ]


@router.post(
    "/auth-providers",
    response_model=AuthProviderRefOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_auth_provider(
    body: AuthProviderCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> AuthProviderRefOut:
    if body.provider_type == "oidc" and not (body.issuer_url and body.issuer_url.strip()):
        raise HTTPException(status_code=422, detail="OIDC provider requires issuer_url.")
    cidrs = validate_cidrs(body.trusted_cidrs)
    if body.provider_type == "trusted_proxy" and (not cidrs or not body.proxy_secret):
        raise HTTPException(
            status_code=422,
            detail="Trusted-proxy provider requires at least one valid CIDR and proxy_secret.",
        )

    master_key, _ = get_settings().resolve_secrets()
    encrypted_secret = encrypt_secret(body.proxy_secret, master_key) if body.proxy_secret else None

    provider = AuthProvider(
        tenant_id=admin.tenant_id,
        name=body.name.strip(),
        provider_type=body.provider_type,
        is_enabled=body.is_enabled,
        issuer_url=body.issuer_url.strip() if body.issuer_url else None,
        audience=body.audience.strip() if body.audience else None,
        jwks_url=body.jwks_url.strip() if body.jwks_url else None,
        groups_claim=body.groups_claim.strip() or "groups",
        sub_claim=body.sub_claim.strip() or "sub",
        trusted_cidrs=cidrs,
        encrypted_proxy_secret=encrypted_secret,
    )
    session.add(provider)
    await commit_or_409(session, f"Auth provider '{provider.name}' already exists.")
    return AuthProviderRefOut(
        id=provider.id,
        name=provider.name,
        provider_type=provider.provider_type,
        is_enabled=provider.is_enabled,
    )


@router.patch("/auth-providers/{provider_id}", response_model=AuthProviderRefOut)
async def update_auth_provider(
    provider_id: str,
    body: AuthProviderUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> AuthProviderRefOut:
    stmt = select(AuthProvider).where(
        AuthProvider.id == provider_id,
        AuthProvider.tenant_id == admin.tenant_id,
    )
    provider = (await session.execute(stmt)).scalars().first()
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found.")

    if body.name is not None:
        provider.name = body.name.strip()
    if body.is_enabled is not None:
        provider.is_enabled = body.is_enabled
    if body.issuer_url is not None:
        provider.issuer_url = body.issuer_url.strip() or None
    if body.audience is not None:
        provider.audience = body.audience.strip() or None
    if body.jwks_url is not None:
        provider.jwks_url = body.jwks_url.strip() or None
    if body.groups_claim is not None:
        provider.groups_claim = body.groups_claim.strip() or "groups"
    if body.sub_claim is not None:
        provider.sub_claim = body.sub_claim.strip() or "sub"
    if body.trusted_cidrs is not None:
        provider.trusted_cidrs = validate_cidrs(body.trusted_cidrs)
    if body.proxy_secret:
        master_key, _ = get_settings().resolve_secrets()
        provider.encrypted_proxy_secret = encrypt_secret(body.proxy_secret, master_key)

    await commit_or_409(session, f"Auth provider '{provider.name}' already exists.")
    return AuthProviderRefOut(
        id=provider.id,
        name=provider.name,
        provider_type=provider.provider_type,
        is_enabled=provider.is_enabled,
    )


@router.delete("/auth-providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_auth_provider(
    provider_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(AuthProvider).where(
        AuthProvider.id == provider_id,
        AuthProvider.tenant_id == admin.tenant_id,
    )
    provider = (await session.execute(stmt)).scalars().first()
    if provider is None:
        raise HTTPException(status_code=404, detail="Auth provider not found.")
    await session.delete(provider)
    await session.commit()
