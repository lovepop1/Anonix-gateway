"""Control-plane CRUD routes for policies, auth, keys, upstreams, routes, and audit."""

from __future__ import annotations

import base64
import ipaddress
from datetime import datetime
from typing import Any

from anonix.engine import MaskingEngine
from anonix.exceptions import PolicyValidationError
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from anonix_gateway.auth.admin import VALID_ADMIN_ROLES, AdminContext, require_admin_roles
from anonix_gateway.config import get_settings
from anonix_gateway.db.models import (
    AdminUser,
    ApiKey,
    AuditEvent,
    AuthProvider,
    GroupMapping,
    MaskingPolicy,
    PolicyVersion,
    ProxyRoute,
    Upstream,
)
from anonix_gateway.db.session import get_session
from anonix_gateway.masking.engine_cache import validate_policy_yaml
from anonix_gateway.proxy.ssrf import validate_upstream_url
from anonix_gateway.security.crypto import encrypt_secret, generate_api_key, hash_password

router = APIRouter(prefix="/api/admin", tags=["admin"])


async def _commit_or_409(session: AsyncSession, conflict_detail: str) -> None:
    """Commit transaction or rollback and raise 409 Conflict on IntegrityError."""
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=conflict_detail) from exc


def _validate_cidrs(cidrs: list[str]) -> list[str]:
    """Validate CIDR / IP strings and return normalized list."""
    cleaned: list[str] = []
    for raw in cidrs:
        item = raw.strip()
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail=f"Invalid CIDR or IP address '{item}': {exc}"
            ) from exc
        cleaned.append(item)
    return cleaned


async def _ensure_route_targets(
    session: AsyncSession,
    *,
    tenant_id: str,
    upstream_id: str | None,
    policy_id: str | None,
) -> None:
    """Verify upstream_id and policy_id exist within *tenant_id*."""
    if upstream_id is not None:
        up = (
            await session.execute(
                select(Upstream.id).where(
                    Upstream.id == upstream_id, Upstream.tenant_id == tenant_id
                )
            )
        ).first()
        if up is None:
            raise HTTPException(status_code=422, detail="Selected upstream does not exist.")
    if policy_id is not None:
        pol = (
            await session.execute(
                select(MaskingPolicy.id).where(
                    MaskingPolicy.id == policy_id, MaskingPolicy.tenant_id == tenant_id
                )
            )
        ).first()
        if pol is None:
            raise HTTPException(status_code=422, detail="Selected policy does not exist.")


# ---------------------------------------------------------------------------
# Policies & Live Playground
# ---------------------------------------------------------------------------


class PolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1000)
    yaml_content: str = Field(min_length=1)


class PolicyVersionCreateRequest(BaseModel):
    yaml_content: str = Field(min_length=1)
    activate: bool = True


class PlaygroundRequest(BaseModel):
    yaml_content: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    format: str = Field(default="json")
    role: str | None = None


@router.get("/policies")
async def list_policies(
    admin: AdminContext = Depends(
        require_admin_roles("platform_admin", "policy_author", "auditor")
    ),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = (
        select(MaskingPolicy)
        .where(MaskingPolicy.tenant_id == admin.tenant_id)
        .options(selectinload(MaskingPolicy.versions))
        .order_by(MaskingPolicy.name.asc())
    )
    res = await session.execute(stmt)
    policies = res.scalars().all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "created_at": p.created_at.isoformat(),
            "versions": [
                {
                    "id": v.id,
                    "version_number": v.version_number,
                    "status": v.status,
                    "yaml_content": v.yaml_content,
                    "created_by": v.created_by,
                    "created_at": v.created_at.isoformat(),
                }
                for v in p.versions
            ],
        }
        for p in policies
    ]


@router.post("/policies", status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        validate_policy_yaml(body.yaml_content)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid policy YAML: {exc}") from exc

    existing = await session.execute(
        select(MaskingPolicy).where(
            MaskingPolicy.tenant_id == admin.tenant_id,
            MaskingPolicy.name == body.name.strip(),
        )
    )
    if existing.scalars().first() is not None:
        raise HTTPException(status_code=409, detail=f"Policy '{body.name}' already exists.")

    policy = MaskingPolicy(
        tenant_id=admin.tenant_id,
        name=body.name.strip(),
        description=body.description.strip(),
    )
    session.add(policy)
    await session.flush()

    version = PolicyVersion(
        policy_id=policy.id,
        version_number=1,
        yaml_content=body.yaml_content,
        status="active",
        created_by=admin.email,
    )
    session.add(version)
    await session.commit()
    return {"id": policy.id, "name": policy.name, "version_number": 1, "status": "active"}


@router.post("/policies/{policy_id}/versions", status_code=status.HTTP_201_CREATED)
async def add_policy_version(
    policy_id: str,
    body: PolicyVersionCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        validate_policy_yaml(body.yaml_content)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid policy YAML: {exc}") from exc

    stmt = (
        select(MaskingPolicy)
        .where(MaskingPolicy.id == policy_id, MaskingPolicy.tenant_id == admin.tenant_id)
        .options(selectinload(MaskingPolicy.versions))
    )
    policy = (await session.execute(stmt)).scalars().first()
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")

    next_num = max((v.version_number for v in policy.versions), default=0) + 1
    if body.activate:
        for v in policy.versions:
            if v.status == "active":
                v.status = "archived"

    new_ver = PolicyVersion(
        policy_id=policy.id,
        version_number=next_num,
        yaml_content=body.yaml_content,
        status="active" if body.activate else "draft",
        created_by=admin.email,
    )
    session.add(new_ver)
    await session.commit()
    return {
        "policy_id": policy.id,
        "version_number": next_num,
        "status": new_ver.status,
    }


@router.post("/policies/{policy_id}/versions/{version_number}/activate")
async def activate_policy_version(
    policy_id: str,
    version_number: int,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = (
        select(MaskingPolicy)
        .where(MaskingPolicy.id == policy_id, MaskingPolicy.tenant_id == admin.tenant_id)
        .options(selectinload(MaskingPolicy.versions))
    )
    policy = (await session.execute(stmt)).scalars().first()
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")

    target = next((v for v in policy.versions if v.version_number == version_number), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Policy version not found.")

    for v in policy.versions:
        v.status = "active" if v.version_number == version_number else "archived"
    await session.commit()
    return {"policy_id": policy.id, "active_version": version_number}


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(MaskingPolicy).where(
        MaskingPolicy.id == policy_id,
        MaskingPolicy.tenant_id == admin.tenant_id,
    )
    policy = (await session.execute(stmt)).scalars().first()
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found.")
    await session.delete(policy)
    await session.commit()


@router.post("/policies/playground")
async def policy_playground(
    body: PlaygroundRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
) -> dict[str, Any]:
    """Dry-run a policy YAML against sample data in memory (zero persistence)."""
    try:
        policy = validate_policy_yaml(body.yaml_content)
        engine = MaskingEngine(policy, salt=f"playground:{admin.tenant_id}")
        result = engine.mask(body.payload, format=body.format, role=body.role)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "format": result.format_name,
        "role": body.role,
        "output": result.output_text,
        "k_achieved": result.k_achieved,
        "conflict_count": result.conflict_count,
        "uncovered_count": result.uncovered_count,
    }


# ---------------------------------------------------------------------------
# Auth Providers (OIDC / Trusted-Proxy)
# ---------------------------------------------------------------------------


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


@router.get("/auth-providers")
async def list_auth_providers(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = select(AuthProvider).where(AuthProvider.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "provider_type": p.provider_type,
            "is_enabled": p.is_enabled,
            "issuer_url": p.issuer_url,
            "audience": p.audience,
            "jwks_url": p.jwks_url,
            "groups_claim": p.groups_claim,
            "sub_claim": p.sub_claim,
            "trusted_cidrs": p.trusted_cidrs,
            "has_proxy_secret": bool(p.encrypted_proxy_secret),
            "created_at": p.created_at.isoformat(),
        }
        for p in rows
    ]


@router.post("/auth-providers", status_code=status.HTTP_201_CREATED)
async def create_auth_provider(
    body: AuthProviderCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if body.provider_type == "oidc" and not (body.issuer_url and body.issuer_url.strip()):
        raise HTTPException(status_code=422, detail="OIDC provider requires issuer_url.")
    cidrs = _validate_cidrs(body.trusted_cidrs)
    if body.provider_type == "trusted_proxy" and (not cidrs or not body.proxy_secret):
        raise HTTPException(
            status_code=422,
            detail="Trusted-proxy provider requires at least one valid CIDR and proxy_secret.",
        )

    settings = get_settings()
    master_key, _ = settings.resolve_secrets()
    encrypted_secret = (
        encrypt_secret(body.proxy_secret, master_key) if body.proxy_secret else None
    )

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
    await _commit_or_409(session, f"Auth provider '{provider.name}' already exists.")
    return {"id": provider.id, "name": provider.name, "provider_type": provider.provider_type}


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


@router.patch("/auth-providers/{provider_id}")
async def update_auth_provider(
    provider_id: str,
    body: AuthProviderUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
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
        provider.trusted_cidrs = _validate_cidrs(body.trusted_cidrs)
    if body.proxy_secret:
        master_key, _ = get_settings().resolve_secrets()
        provider.encrypted_proxy_secret = encrypt_secret(body.proxy_secret, master_key)

    await _commit_or_409(session, f"Auth provider '{provider.name}' already exists.")
    return {"id": provider.id, "name": provider.name, "is_enabled": provider.is_enabled}


# ---------------------------------------------------------------------------
# Group Mappings
# ---------------------------------------------------------------------------


class GroupMappingCreateRequest(BaseModel):
    provider_id: str | None = None
    external_group: str = Field(min_length=1, max_length=255)
    policy_role: str | None = Field(default=None, max_length=128)
    policy_id: str = Field(min_length=1, max_length=36)
    priority: int = 0


@router.get("/group-mappings")
async def list_group_mappings(
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = (
        select(GroupMapping)
        .where(GroupMapping.tenant_id == admin.tenant_id)
        .order_by(GroupMapping.priority.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": m.id,
            "provider_id": m.provider_id,
            "external_group": m.external_group,
            "policy_role": m.policy_role,
            "policy_id": m.policy_id,
            "priority": m.priority,
        }
        for m in rows
    ]


@router.post("/group-mappings", status_code=status.HTTP_201_CREATED)
async def create_group_mapping(
    body: GroupMappingCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _ensure_route_targets(
        session, tenant_id=admin.tenant_id, upstream_id=None, policy_id=body.policy_id
    )
    role_clean = body.policy_role.strip() if body.policy_role else None
    mapping = GroupMapping(
        tenant_id=admin.tenant_id,
        provider_id=body.provider_id,
        external_group=body.external_group.strip(),
        policy_role=role_clean or None,
        policy_id=body.policy_id,
        priority=body.priority,
    )
    session.add(mapping)
    await session.commit()
    return {
        "id": mapping.id,
        "external_group": mapping.external_group,
        "policy_role": mapping.policy_role,
        "policy_id": mapping.policy_id,
        "priority": mapping.priority,
    }


@router.delete("/group-mappings/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group_mapping(
    mapping_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(GroupMapping).where(
        GroupMapping.id == mapping_id,
        GroupMapping.tenant_id == admin.tenant_id,
    )
    mapping = (await session.execute(stmt)).scalars().first()
    if mapping is None:
        raise HTTPException(status_code=404, detail="Group mapping not found.")
    await session.delete(mapping)
    await session.commit()


class GroupMappingUpdateRequest(BaseModel):
    external_group: str | None = Field(default=None, min_length=1, max_length=255)
    policy_role: str | None = Field(default=None, max_length=128)
    policy_id: str | None = Field(default=None, min_length=1, max_length=36)
    priority: int | None = None


@router.patch("/group-mappings/{mapping_id}")
async def update_group_mapping(
    mapping_id: str,
    body: GroupMappingUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(GroupMapping).where(
        GroupMapping.id == mapping_id,
        GroupMapping.tenant_id == admin.tenant_id,
    )
    mapping = (await session.execute(stmt)).scalars().first()
    if mapping is None:
        raise HTTPException(status_code=404, detail="Group mapping not found.")

    if body.policy_id is not None:
        await _ensure_route_targets(
            session, tenant_id=admin.tenant_id, upstream_id=None, policy_id=body.policy_id
        )
        mapping.policy_id = body.policy_id
    if body.external_group is not None:
        mapping.external_group = body.external_group.strip()
    if body.policy_role is not None:
        mapping.policy_role = body.policy_role.strip() or None
    if body.priority is not None:
        mapping.priority = body.priority

    await session.commit()
    return {
        "id": mapping.id,
        "external_group": mapping.external_group,
        "policy_role": mapping.policy_role,
        "policy_id": mapping.policy_id,
        "priority": mapping.priority,
    }


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    groups: list[str] = Field(min_length=1)
    allowed_policy_ids: list[str] | None = None
    expires_at: datetime | None = None


@router.get("/api-keys")
async def list_api_keys(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = select(ApiKey).where(ApiKey.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "groups": k.groups,
            "allowed_policy_ids": k.allowed_policy_ids,
            "is_active": k.is_active,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        }
        for k in rows
    ]


@router.post("/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
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
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": key_prefix,
        "raw_key": raw_key,  # Shown only once at creation
        "groups": api_key.groups,
    }


@router.post("/api-keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == admin.tenant_id)
    api_key = (await session.execute(stmt)).scalars().first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    api_key.is_active = False
    await session.commit()
    return {"status": "revoked", "id": api_key.id}


class ApiKeyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    groups: list[str] | None = None
    is_active: bool | None = None


@router.patch("/api-keys/{key_id}")
async def update_api_key(
    key_id: str,
    body: ApiKeyUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.tenant_id == admin.tenant_id)
    api_key = (await session.execute(stmt)).scalars().first()
    if api_key is None:
        raise HTTPException(status_code=404, detail="API key not found.")
    if body.name is not None:
        api_key.name = body.name.strip()
    if body.groups is not None:
        api_key.groups = [g.strip() for g in body.groups if g.strip()]
    if body.is_active is not None:
        api_key.is_active = body.is_active
    await session.commit()
    return {
        "id": api_key.id,
        "name": api_key.name,
        "groups": api_key.groups,
        "is_active": api_key.is_active,
    }


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


# ---------------------------------------------------------------------------
# Upstreams & Proxy Routes
# ---------------------------------------------------------------------------


class UpstreamCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_url: str = Field(min_length=1, max_length=512)
    auth_type: str = Field(default="none", pattern="^(none|bearer|api_key_header|basic)$")
    auth_header_name: str | None = None
    credential: str | None = None
    timeout_seconds: float = Field(default=15.0, ge=0.5, le=120.0)


@router.get("/upstreams")
async def list_upstreams(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = select(Upstream).where(Upstream.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": u.id,
            "name": u.name,
            "base_url": u.base_url,
            "auth_type": u.auth_type,
            "auth_header_name": u.auth_header_name,
            "has_credential": bool(u.encrypted_credential),
            "timeout_seconds": u.timeout_seconds,
            "is_active": u.is_active,
        }
        for u in rows
    ]


@router.post("/upstreams", status_code=status.HTTP_201_CREATED)
async def create_upstream(
    body: UpstreamCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
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
    await _commit_or_409(session, f"Upstream '{upstream.name}' already exists.")
    return {"id": upstream.id, "name": upstream.name, "base_url": upstream.base_url}


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


class UpstreamUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    base_url: str | None = Field(default=None, min_length=1, max_length=512)
    auth_type: str | None = Field(default=None, pattern="^(none|bearer|api_key_header|basic)$")
    auth_header_name: str | None = None
    credential: str | None = None
    timeout_seconds: float | None = Field(default=None, ge=0.5, le=120.0)
    is_active: bool | None = None


@router.patch("/upstreams/{upstream_id}")
async def update_upstream(
    upstream_id: str,
    body: UpstreamUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
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

    await _commit_or_409(session, f"Upstream '{upstream.name}' already exists.")
    return {"id": upstream.id, "name": upstream.name, "base_url": upstream.base_url}


class ProxyRouteCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    route_prefix: str = Field(min_length=1, max_length=255)
    upstream_id: str
    policy_id: str
    strip_prefix: bool = True
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    blocked_subpaths: list[str] = Field(default_factory=list)
    allow_policy_override: bool = False
    on_unstructured: str = Field(default="fail_closed", pattern="^(fail_closed|passthrough)$")


@router.get("/routes")
async def list_routes(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = select(ProxyRoute).where(ProxyRoute.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "route_prefix": r.route_prefix,
            "upstream_id": r.upstream_id,
            "policy_id": r.policy_id,
            "strip_prefix": r.strip_prefix,
            "allowed_methods": r.allowed_methods,
            "blocked_subpaths": r.blocked_subpaths,
            "allow_policy_override": r.allow_policy_override,
            "on_unstructured": r.on_unstructured,
            "is_active": r.is_active,
        }
        for r in rows
    ]


@router.post("/routes", status_code=status.HTTP_201_CREATED)
async def create_route(
    body: ProxyRouteCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    await _ensure_route_targets(
        session,
        tenant_id=admin.tenant_id,
        upstream_id=body.upstream_id,
        policy_id=body.policy_id,
    )
    methods = [m.upper().strip() for m in body.allowed_methods if m.strip()]
    if not methods:
        raise HTTPException(status_code=422, detail="At least one allowed HTTP method is required.")
    prefix = "/" + body.route_prefix.strip().strip("/")
    route = ProxyRoute(
        tenant_id=admin.tenant_id,
        name=body.name.strip(),
        route_prefix=prefix,
        upstream_id=body.upstream_id,
        policy_id=body.policy_id,
        strip_prefix=body.strip_prefix,
        allowed_methods=methods,
        blocked_subpaths=[p.strip() for p in body.blocked_subpaths if p.strip()],
        allow_policy_override=body.allow_policy_override,
        on_unstructured=body.on_unstructured,
        is_active=True,
    )
    session.add(route)
    await _commit_or_409(session, f"Proxy route prefix '{prefix}' already exists.")
    return {"id": route.id, "name": route.name, "route_prefix": route.route_prefix}


@router.delete("/routes/{route_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_route(
    route_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    stmt = select(ProxyRoute).where(
        ProxyRoute.id == route_id,
        ProxyRoute.tenant_id == admin.tenant_id,
    )
    route = (await session.execute(stmt)).scalars().first()
    if route is None:
        raise HTTPException(status_code=404, detail="Proxy route not found.")
    await session.delete(route)
    await session.commit()


class ProxyRouteUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    route_prefix: str | None = Field(default=None, min_length=1, max_length=255)
    upstream_id: str | None = None
    policy_id: str | None = None
    strip_prefix: bool | None = None
    allowed_methods: list[str] | None = None
    blocked_subpaths: list[str] | None = None
    allow_policy_override: bool | None = None
    on_unstructured: str | None = Field(default=None, pattern="^(fail_closed|passthrough)$")
    is_active: bool | None = None


@router.patch("/routes/{route_id}")
async def update_route(
    route_id: str,
    body: ProxyRouteUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(ProxyRoute).where(
        ProxyRoute.id == route_id,
        ProxyRoute.tenant_id == admin.tenant_id,
    )
    route = (await session.execute(stmt)).scalars().first()
    if route is None:
        raise HTTPException(status_code=404, detail="Proxy route not found.")

    await _ensure_route_targets(
        session,
        tenant_id=admin.tenant_id,
        upstream_id=body.upstream_id,
        policy_id=body.policy_id,
    )
    if body.name is not None:
        route.name = body.name.strip()
    if body.route_prefix is not None:
        route.route_prefix = "/" + body.route_prefix.strip().strip("/")
    if body.upstream_id is not None:
        route.upstream_id = body.upstream_id
    if body.policy_id is not None:
        route.policy_id = body.policy_id
    if body.strip_prefix is not None:
        route.strip_prefix = body.strip_prefix
    if body.allowed_methods is not None:
        methods = [m.upper().strip() for m in body.allowed_methods if m.strip()]
        if not methods:
            raise HTTPException(
                status_code=422, detail="At least one allowed HTTP method is required."
            )
        route.allowed_methods = methods
    if body.blocked_subpaths is not None:
        route.blocked_subpaths = [p.strip() for p in body.blocked_subpaths if p.strip()]
    if body.allow_policy_override is not None:
        route.allow_policy_override = body.allow_policy_override
    if body.on_unstructured is not None:
        route.on_unstructured = body.on_unstructured
    if body.is_active is not None:
        route.is_active = body.is_active

    await _commit_or_409(session, f"Proxy route prefix '{route.route_prefix}' already exists.")
    return {"id": route.id, "name": route.name, "route_prefix": route.route_prefix}


# ---------------------------------------------------------------------------
# Admin Users & Audit Events
# ---------------------------------------------------------------------------


class AdminUserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="policy_author")


@router.get("/users")
async def list_admin_users(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = select(AdminUser).where(AdminUser.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in rows
    ]


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_admin_user(
    body: AdminUserCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    if body.role not in VALID_ADMIN_ROLES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid admin role '{body.role}'. Valid: {sorted(VALID_ADMIN_ROLES)}",
        )
    user = AdminUser(
        tenant_id=admin.tenant_id,
        email=body.email.strip().lower(),
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    session.add(user)
    await _commit_or_409(session, f"Admin user '{user.email}' already exists.")
    return {"id": user.id, "email": user.email, "role": user.role}


class AdminUserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


async def _count_active_platform_admins(session: AsyncSession, tenant_id: str) -> int:
    """Return count of active platform_admin accounts in *tenant_id*."""
    from sqlalchemy import func

    stmt = select(func.count(AdminUser.id)).where(
        AdminUser.tenant_id == tenant_id,
        AdminUser.role == "platform_admin",
        AdminUser.is_active.is_(True),
    )
    return int((await session.execute(stmt)).scalar_one() or 0)


@router.patch("/users/{user_id}")
async def update_admin_user(
    user_id: str,
    body: AdminUserUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(AdminUser).where(
        AdminUser.id == user_id,
        AdminUser.tenant_id == admin.tenant_id,
    )
    user = (await session.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Admin user not found.")

    was_active_platform_admin = user.role == "platform_admin" and user.is_active

    if body.role is not None:
        if body.role not in VALID_ADMIN_ROLES:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid admin role '{body.role}'. Valid: {sorted(VALID_ADMIN_ROLES)}",
            )
        if user.id == admin.admin_id and body.role != "platform_admin":
            raise HTTPException(status_code=400, detail="Cannot demote your own active account.")
        if was_active_platform_admin and body.role != "platform_admin":
            if await _count_active_platform_admins(session, admin.tenant_id) <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot demote the last active platform_admin."
                )
        user.role = body.role

    if body.is_active is not None:
        if user.id == admin.admin_id and not body.is_active:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account.")
        if was_active_platform_admin and not body.is_active:
            if await _count_active_platform_admins(session, admin.tenant_id) <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot deactivate the last active platform_admin."
                )
        user.is_active = body.is_active

    if body.password:
        user.password_hash = hash_password(body.password)

    await session.commit()
    return {"id": user.id, "email": user.email, "role": user.role, "is_active": user.is_active}


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_admin_user(
    user_id: str,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> None:
    if user_id == admin.admin_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account.")
    stmt = select(AdminUser).where(
        AdminUser.id == user_id,
        AdminUser.tenant_id == admin.tenant_id,
    )
    user = (await session.execute(stmt)).scalars().first()
    if user is None:
        raise HTTPException(status_code=404, detail="Admin user not found.")
    if user.role == "platform_admin" and user.is_active:
        if await _count_active_platform_admins(session, admin.tenant_id) <= 1:
            raise HTTPException(
                status_code=400, detail="Cannot delete the last active platform_admin."
            )
    await session.delete(user)
    await session.commit()


@router.get("/audit")
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "auditor")),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == admin.tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        {
            "id": e.id,
            "request_id": e.request_id,
            "caller_id": e.caller_id,
            "auth_method": e.auth_method,
            "route_id": e.route_id,
            "policy_id": e.policy_id,
            "policy_version": e.policy_version,
            "resolved_role": e.resolved_role,
            "format_name": e.format_name,
            "status_code": e.status_code,
            "duration_ms": e.duration_ms,
            "detail": e.detail,
            "created_at": e.created_at.isoformat(),
        }
        for e in rows
    ]
