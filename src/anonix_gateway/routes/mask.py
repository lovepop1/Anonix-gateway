"""Direct on-the-fly masking endpoint (POST /v1/mask)."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.audit.ledger import record_audit_event
from anonix_gateway.auth.caller import (
    CallerIdentity,
    authenticate_caller,
    resolve_group_mapping,
)
from anonix_gateway.cache.rate_limit import get_rate_limiter
from anonix_gateway.config import get_settings
from anonix_gateway.db.models import MaskingPolicy, PolicyVersion
from anonix_gateway.db.session import get_session
from anonix_gateway.masking.engine_cache import get_cached_engine

router = APIRouter(prefix="/v1", tags=["masking"])

_FORMAT_MEDIA_TYPES = {
    "json": "application/json",
    "xml": "application/xml",
    "yaml": "application/yaml",
    "csv": "text/csv",
}


def _detect_format(content_type: str | None, explicit_format: str | None) -> str:
    """Determine input payload format from explicit param or Content-Type."""
    if explicit_format:
        return explicit_format.strip().lower()
    if content_type:
        ct = content_type.lower()
        if "xml" in ct:
            return "xml"
        if "yaml" in ct or "yml" in ct:
            return "yaml"
        if "csv" in ct:
            return "csv"
    return "json"


async def _load_active_policy(
    session: AsyncSession,
    *,
    tenant_id: str,
    policy_ref: str,
) -> tuple[MaskingPolicy, PolicyVersion]:
    """Resolve a MaskingPolicy (by id or name) and its active PolicyVersion."""
    stmt = select(MaskingPolicy).where(
        MaskingPolicy.tenant_id == tenant_id,
        (MaskingPolicy.id == policy_ref) | (MaskingPolicy.name == policy_ref),
    )
    res = await session.execute(stmt)
    policy = res.scalars().first()
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Masking policy '{policy_ref}' not found.",
        )

    v_stmt = (
        select(PolicyVersion)
        .where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.status == "active",
        )
        .order_by(PolicyVersion.version_number.desc())
    )
    v_res = await session.execute(v_stmt)
    version = v_res.scalars().first()
    if version is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Masking policy '{policy.name}' has no active version.",
        )
    return policy, version


@router.post("/mask")
async def mask_payload(
    request: Request,
    identity: CallerIdentity = Depends(authenticate_caller),
    session: AsyncSession = Depends(get_session),
    x_anonix_policy: str | None = Header(default=None, alias="X-Anonix-Policy"),
    x_anonix_format: str | None = Header(default=None, alias="X-Anonix-Format"),
    content_type: str | None = Header(default=None),
) -> Response:
    """Mask an in-memory JSON, XML, YAML, or CSV payload according to caller role & policy.

    Accepts either:
    - Structured JSON envelope: ``{"policy": "<id_or_name>", "format": "json", "payload": ...}``
    - Raw payload body with ``X-Anonix-Policy`` header (or policy bound via GroupMapping/API key).
    """
    limiter = get_rate_limiter()
    if not await limiter.allow(f"{identity.tenant_id}:{identity.caller_id}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded.",
        )

    settings = get_settings()
    raw_bytes = await request.body()
    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty request payload.",
        )
    if len(raw_bytes) > settings.max_payload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Payload exceeds max_payload_bytes ({settings.max_payload_bytes}).",
        )

    requested_policy = x_anonix_policy.strip() if x_anonix_policy else None
    fmt = _detect_format(content_type, x_anonix_format)
    payload_bytes = raw_bytes

    # Support JSON envelope {"policy": ..., "payload": ..., "format": ...}
    if fmt == "json":
        try:
            parsed: Any = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON payload: {exc}",
            ) from exc
        if isinstance(parsed, dict) and "payload" in parsed and (
            "policy" in parsed or "policy_id" in parsed or requested_policy is None
        ):
            env_policy = parsed.get("policy") or parsed.get("policy_id")
            if env_policy:
                requested_policy = str(env_policy).strip()
            if parsed.get("format"):
                fmt = str(parsed["format"]).strip().lower()
            inner = parsed["payload"]
            if isinstance(inner, str):
                payload_bytes = inner.encode("utf-8")
            else:
                payload_bytes = json.dumps(inner, ensure_ascii=False).encode("utf-8")

    # Resolve policy and verify caller's GroupMapping authorizes that policy
    if requested_policy:
        policy, policy_version = await _load_active_policy(
            session,
            tenant_id=identity.tenant_id,
            policy_ref=requested_policy,
        )
        authz = await resolve_group_mapping(
            session,
            identity,
            target_policy_id=policy.id,
        )
    else:
        authz = await resolve_group_mapping(session, identity)
        policy, policy_version = await _load_active_policy(
            session,
            tenant_id=identity.tenant_id,
            policy_ref=authz.mapped_policy_id,
        )

    if identity.api_key_allowed_policy_ids is not None:
        if (
            policy.id not in identity.api_key_allowed_policy_ids
            and policy.name not in identity.api_key_allowed_policy_ids
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key is not authorized to use policy '{policy.name}'.",
            )

    master_key, _ = settings.resolve_secrets()
    engine = get_cached_engine(
        policy_id=policy.id,
        version_number=policy_version.version_number,
        yaml_content=policy_version.yaml_content,
        tenant_salt=f"{identity.tenant_id}:{master_key}",
    )

    req_id = str(uuid.uuid4())
    start_t = time.perf_counter()
    try:
        result = engine.mask(
            payload_bytes,
            format=fmt,
            role=authz.role,
            tenant_id=identity.tenant_id,
            request_id=req_id,
            max_input_bytes=settings.max_payload_bytes,
        )
    except Exception as exc:
        duration_ms = (time.perf_counter() - start_t) * 1000.0
        await record_audit_event(
            session,
            tenant_id=identity.tenant_id,
            request_id=req_id,
            caller_id=identity.caller_id,
            auth_method=identity.auth_method,
            policy_id=policy.id,
            policy_version=policy_version.version_number,
            resolved_role=authz.role,
            format_name=fmt,
            status_code=status.HTTP_400_BAD_REQUEST,
            duration_ms=duration_ms,
            detail={"error": "masking_execution_failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Masking execution error: {exc}",
        ) from exc

    duration_ms = (time.perf_counter() - start_t) * 1000.0
    await record_audit_event(
        session,
        tenant_id=identity.tenant_id,
        request_id=req_id,
        caller_id=identity.caller_id,
        auth_method=identity.auth_method,
        policy_id=policy.id,
        policy_version=policy_version.version_number,
        resolved_role=authz.role,
        format_name=result.format_name,
        status_code=status.HTTP_200_OK,
        duration_ms=duration_ms,
        detail={
            "uncovered_count": result.uncovered_count,
            "conflict_count": result.conflict_count,
            "k_achieved": result.k_achieved,
        },
    )

    media_type = _FORMAT_MEDIA_TYPES.get(result.format_name, "application/octet-stream")
    return Response(
        content=result.output_bytes,
        media_type=media_type,
        headers={
            "X-Anonix-Request-ID": req_id,
            "X-Anonix-Role": authz.role or "default",
            "X-Anonix-Policy": policy.name,
            "X-Anonix-Policy-Version": str(policy_version.version_number),
        },
    )
