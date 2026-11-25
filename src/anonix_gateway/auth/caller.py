"""Unified inbound caller authentication and GroupMapping role/policy resolver."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.oidc import extract_claim_values, validate_oidc_jwt
from anonix_gateway.auth.trusted_proxy import authenticate_trusted_proxy
from anonix_gateway.config import get_settings
from anonix_gateway.db.bootstrap import DEFAULT_TENANT_SLUG
from anonix_gateway.db.models import ApiKey, AuthProvider, GroupMapping, Tenant
from anonix_gateway.db.session import get_session
from anonix_gateway.security.crypto import hash_api_key


@dataclass(frozen=True)
class CallerIdentity:
    """Verified inbound caller identity before role/policy resolution."""

    tenant_id: str
    caller_id: str
    auth_method: str  # api_key | oidc | trusted_proxy
    groups: list[str]
    provider_id: str | None = None
    api_key_allowed_policy_ids: list[str] | None = None


@dataclass(frozen=True)
class ResolvedAuthorization:
    """Resolved policy role (None = policy default rules) and required policy_id."""

    role: str | None
    mapped_policy_id: str


async def _resolve_tenant(request: Request, session: AsyncSession) -> Tenant:
    """Resolve active tenant (single_org uses 'default'; multi_tenant uses X-Anonix-Tenant)."""
    settings = get_settings()
    slug = DEFAULT_TENANT_SLUG
    if settings.tenancy_mode == "multi_tenant":
        header_slug = request.headers.get("X-Anonix-Tenant", "").strip()
        if header_slug:
            slug = header_slug

    stmt = select(Tenant).where(Tenant.slug == slug, Tenant.is_active.is_(True))
    res = await session.execute(stmt)
    tenant = res.scalars().first()
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{slug}' not found or inactive.",
        )
    return tenant


async def _authenticate_api_key(
    raw_key: str,
    tenant_id: str,
    session: AsyncSession,
) -> CallerIdentity:
    """Verify an API key against active, non-expired ``ApiKey`` rows."""
    key_hash = hash_api_key(raw_key)
    stmt = select(ApiKey).where(
        ApiKey.tenant_id == tenant_id,
        ApiKey.key_hash == key_hash,
        ApiKey.is_active.is_(True),
    )
    res = await session.execute(stmt)
    api_key = res.scalars().first()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key.",
        )

    now = datetime.now(UTC)
    if api_key.expires_at is not None:
        exp = api_key.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if exp <= now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired.",
            )

    api_key.last_used_at = now
    await session.commit()

    return CallerIdentity(
        tenant_id=tenant_id,
        caller_id=f"apikey:{api_key.name}",
        auth_method="api_key",
        groups=list(api_key.groups or []),
        provider_id=None,
        api_key_allowed_policy_ids=(
            list(api_key.allowed_policy_ids) if api_key.allowed_policy_ids is not None else None
        ),
    )


async def authenticate_caller(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> CallerIdentity:
    """Fail-closed inbound authentication supporting API Key, OIDC JWT, and Trusted-Proxy."""
    tenant = await _resolve_tenant(request, session)

    api_key_header = request.headers.get("X-API-Key", "").strip()
    auth_header = request.headers.get("Authorization", "").strip()
    bearer_token = ""
    if auth_header.lower().startswith("bearer "):
        bearer_token = auth_header[7:].strip()

    # 1. Explicit X-API-Key or Bearer axk_* API key
    if api_key_header:
        return await _authenticate_api_key(api_key_header, tenant.id, session)
    if bearer_token.startswith("axk_"):
        return await _authenticate_api_key(bearer_token, tenant.id, session)

    # Load enabled AuthProviders for this tenant
    p_stmt = select(AuthProvider).where(
        AuthProvider.tenant_id == tenant.id,
        AuthProvider.is_enabled.is_(True),
    )
    p_res = await session.execute(p_stmt)
    providers = list(p_res.scalars().all())

    # 2. OIDC / JWT Bearer token
    if bearer_token:
        oidc_providers = [p for p in providers if p.provider_type == "oidc"]
        if not oidc_providers:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer JWT provided, but no OIDC AuthProvider is enabled.",
            )
        last_err = "Token verification failed."
        for provider in oidc_providers:
            try:
                claims = await validate_oidc_jwt(bearer_token, provider)
                caller_id = str(
                    claims.get(provider.sub_claim) or claims.get("email") or "oidc_user"
                )
                groups = extract_claim_values(claims, provider.groups_claim)
                return CallerIdentity(
                    tenant_id=tenant.id,
                    caller_id=caller_id,
                    auth_method="oidc",
                    groups=groups,
                    provider_id=provider.id,
                )
            except Exception as exc:
                last_err = str(exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OIDC JWT authentication failed: {last_err}",
        )

    # 3. Trusted-Proxy Headers
    settings = get_settings()
    master_key, _ = settings.resolve_secrets()
    try:
        tp_result = authenticate_trusted_proxy(request, providers, master_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    if tp_result is not None:
        caller_id, groups, provider_id = tp_result
        return CallerIdentity(
            tenant_id=tenant.id,
            caller_id=caller_id,
            auth_method="trusted_proxy",
            groups=groups,
            provider_id=provider_id,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide X-API-Key, Bearer JWT, or trusted-proxy headers.",
    )


async def resolve_group_mapping(
    session: AsyncSession,
    identity: CallerIdentity,
    *,
    target_policy_id: str | None = None,
) -> ResolvedAuthorization:
    """Resolve ``identity.groups`` via ``GroupMapping`` sorted by ``priority DESC``.

    When *target_policy_id* is provided, only mappings bound to that policy are
    accepted. Fails closed with 403 Forbidden if no matching mapping exists.
    """
    if not identity.groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Caller has no group claims; cannot resolve masking role.",
        )

    stmt = (
        select(GroupMapping)
        .where(
            GroupMapping.tenant_id == identity.tenant_id,
            GroupMapping.external_group.in_(identity.groups),
        )
        .order_by(GroupMapping.priority.desc())
    )
    res = await session.execute(stmt)
    mappings = list(res.scalars().all())

    matched_any_provider = False
    for mapping in mappings:
        if mapping.provider_id is not None and mapping.provider_id != identity.provider_id:
            continue
        matched_any_provider = True
        if target_policy_id is not None and mapping.policy_id != target_policy_id:
            continue
        return ResolvedAuthorization(
            role=mapping.policy_role,
            mapped_policy_id=mapping.policy_id,
        )

    if matched_any_provider and target_policy_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Caller groups are not mapped to the target policy.",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="No GroupMapping matched the caller's groups.",
    )
