"""Fail-closed reverse-proxy gateway routes (/proxy/{path})."""

from __future__ import annotations

import fnmatch
import time
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
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
from anonix_gateway.db.models import ProxyRoute, Upstream
from anonix_gateway.db.session import get_session
from anonix_gateway.masking.engine_cache import get_cached_engine
from anonix_gateway.proxy.ssrf import validate_upstream_url
from anonix_gateway.routes.mask import _load_active_policy
from anonix_gateway.security.crypto import decrypt_secret

router = APIRouter(tags=["reverse-proxy"])

_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "authorization",
        "x-api-key",
        "x-anonix-user",
        "x-anonix-groups",
        "x-anonix-proxy-secret",
    }
)


def _match_route(routes: list[ProxyRoute], full_path: str) -> ProxyRoute | None:
    """Match *full_path* using longest-prefix-wins."""
    normalized = "/" + full_path.lstrip("/")
    candidates = sorted(routes, key=lambda r: len(r.route_prefix), reverse=True)
    for route in candidates:
        prefix = route.route_prefix.rstrip("/")
        if normalized == prefix or normalized.startswith(prefix + "/"):
            return route
    return None


def _detect_response_format(content_type: str | None) -> str | None:
    """Map upstream Content-Type to an anonix format name, or None if unstructured."""
    if not content_type:
        return None
    ct = content_type.lower()
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "yaml" in ct or "yml" in ct:
        return "yaml"
    if "csv" in ct:
        return "csv"
    return None


@router.api_route(
    "/proxy/{proxy_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def reverse_proxy(
    proxy_path: str,
    request: Request,
    identity: CallerIdentity = Depends(authenticate_caller),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Authenticate caller, fetch upstream in RAM, mask via anonix, and fail closed."""
    limiter = get_rate_limiter()
    if not await limiter.allow(f"{identity.tenant_id}:{identity.caller_id}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded.",
        )

    r_stmt = select(ProxyRoute).where(
        ProxyRoute.tenant_id == identity.tenant_id,
        ProxyRoute.is_active.is_(True),
    )
    routes = list((await session.execute(r_stmt)).scalars().all())
    route = _match_route(routes, proxy_path)
    if route is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No matching proxy route."
        )

    if request.method.upper() not in {m.upper() for m in route.allowed_methods}:
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail=f"Method {request.method} is not allowed on route '{route.name}'.",
        )

    normalized_path = "/" + proxy_path.lstrip("/")
    subpath = normalized_path[len(route.route_prefix.rstrip("/")) :] or "/"
    for pattern in route.blocked_subpaths:
        if fnmatch.fnmatch(subpath, pattern):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Target subpath is blocked by route policy.",
            )

    if route.allow_policy_override:
        authz = await resolve_group_mapping(session, identity)
        target_policy_id = authz.mapped_policy_id
    else:
        authz = await resolve_group_mapping(
            session, identity, target_policy_id=route.policy_id
        )
        target_policy_id = route.policy_id

    policy, policy_version = await _load_active_policy(
        session, tenant_id=identity.tenant_id, policy_ref=target_policy_id
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

    u_stmt = select(Upstream).where(
        Upstream.id == route.upstream_id,
        Upstream.tenant_id == identity.tenant_id,
        Upstream.is_active.is_(True),
    )
    upstream = (await session.execute(u_stmt)).scalars().first()
    if upstream is None:
        raise HTTPException(status_code=502, detail="Configured upstream is inactive or missing.")

    settings = get_settings()
    try:
        clean_base = validate_upstream_url(
            upstream.base_url, allow_private=settings.allow_private_upstreams
        )
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream SSRF check failed: {exc}") from exc

    forward_path = subpath if route.strip_prefix else normalized_path
    target_url = clean_base + (forward_path if forward_path.startswith("/") else "/" + forward_path)
    if request.url.query:
        target_url += f"?{request.url.query}"

    outbound_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS
    }
    master_key, _ = settings.resolve_secrets()
    if upstream.auth_type != "none" and upstream.encrypted_credential:
        cred = decrypt_secret(upstream.encrypted_credential, master_key)
        if upstream.auth_type == "bearer":
            outbound_headers["Authorization"] = f"Bearer {cred}"
        elif upstream.auth_type == "basic":
            outbound_headers["Authorization"] = f"Basic {cred}"
        elif upstream.auth_type == "api_key_header":
            hdr = upstream.auth_header_name or "X-API-Key"
            outbound_headers[hdr] = cred

    req_body = await request.body()
    req_id = str(uuid.uuid4())
    start_t = time.perf_counter()

    try:
        async with httpx.AsyncClient(timeout=upstream.timeout_seconds) as client:
            up_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=outbound_headers,
                content=req_body if req_body else None,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail=f"Upstream timeout: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream connection error: {exc}") from exc

    raw_resp_bytes = up_resp.content
    duration_ms = (time.perf_counter() - start_t) * 1000.0

    if up_resp.status_code == 204 or not raw_resp_bytes:
        await record_audit_event(
            session,
            tenant_id=identity.tenant_id,
            request_id=req_id,
            caller_id=identity.caller_id,
            auth_method=identity.auth_method,
            route_id=route.id,
            policy_id=policy.id,
            policy_version=policy_version.version_number,
            resolved_role=authz.role,
            format_name=None,
            status_code=up_resp.status_code,
            duration_ms=duration_ms,
        )
        return Response(status_code=up_resp.status_code)

    fmt = _detect_response_format(up_resp.headers.get("content-type"))
    if fmt is None:
        if route.on_unstructured == "passthrough":
            await record_audit_event(
                session,
                tenant_id=identity.tenant_id,
                request_id=req_id,
                caller_id=identity.caller_id,
                auth_method=identity.auth_method,
                route_id=route.id,
                policy_id=policy.id,
                policy_version=policy_version.version_number,
                resolved_role=authz.role,
                format_name="unstructured_passthrough",
                status_code=up_resp.status_code,
                duration_ms=duration_ms,
            )
            return Response(
                content=raw_resp_bytes,
                status_code=up_resp.status_code,
                media_type=up_resp.headers.get("content-type"),
            )
        # Fail closed: never leak unmasked HTML/text/unknown payloads
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream returned unstructured/unsupported content type (fail-closed).",
        )

    engine = get_cached_engine(
        policy_id=policy.id,
        version_number=policy_version.version_number,
        yaml_content=policy_version.yaml_content,
        tenant_salt=f"{identity.tenant_id}:{master_key}",
    )

    try:
        masked = engine.mask(
            raw_resp_bytes,
            format=fmt,
            role=authz.role,
            tenant_id=identity.tenant_id,
            request_id=req_id,
            max_input_bytes=settings.max_payload_bytes,
        )
    except Exception as exc:
        # Fail closed: drop raw upstream payload immediately
        await record_audit_event(
            session,
            tenant_id=identity.tenant_id,
            request_id=req_id,
            caller_id=identity.caller_id,
            auth_method=identity.auth_method,
            route_id=route.id,
            policy_id=policy.id,
            policy_version=policy_version.version_number,
            resolved_role=authz.role,
            format_name=fmt,
            status_code=status.HTTP_502_BAD_GATEWAY,
            duration_ms=(time.perf_counter() - start_t) * 1000.0,
            detail={"error": "proxy_masking_failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to mask upstream response (fail-closed): {exc}",
        ) from exc

    total_ms = (time.perf_counter() - start_t) * 1000.0
    await record_audit_event(
        session,
        tenant_id=identity.tenant_id,
        request_id=req_id,
        caller_id=identity.caller_id,
        auth_method=identity.auth_method,
        route_id=route.id,
        policy_id=policy.id,
        policy_version=policy_version.version_number,
        resolved_role=authz.role,
        format_name=masked.format_name,
        status_code=up_resp.status_code,
        duration_ms=total_ms,
        detail={
            "uncovered_count": masked.uncovered_count,
            "conflict_count": masked.conflict_count,
            "k_achieved": masked.k_achieved,
        },
    )

    return Response(
        content=masked.output_bytes,
        status_code=up_resp.status_code,
        media_type=up_resp.headers.get("content-type"),
        headers={
            "X-Anonix-Request-ID": req_id,
            "X-Anonix-Role": authz.role or "default",
            "X-Anonix-Policy": policy.name,
            "X-Anonix-Policy-Version": str(policy_version.version_number),
        },
    )
