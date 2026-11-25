"""Zero-PII compliance audit event persistence."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.db.models import AuditEvent


async def record_audit_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    request_id: str,
    caller_id: str,
    auth_method: str,
    status_code: int,
    duration_ms: float,
    route_id: str | None = None,
    policy_id: str | None = None,
    policy_version: int | None = None,
    resolved_role: str | None = None,
    format_name: str | None = None,
    fields_masked_count: int = 0,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    """Persist a metadata-only ``AuditEvent`` (never stores raw or masked data)."""
    event = AuditEvent(
        tenant_id=tenant_id,
        request_id=request_id,
        caller_id=caller_id,
        auth_method=auth_method,
        route_id=route_id,
        policy_id=policy_id,
        policy_version=policy_version,
        resolved_role=resolved_role,
        format_name=format_name,
        fields_masked_count=fields_masked_count,
        status_code=status_code,
        duration_ms=round(duration_ms, 3),
        detail=detail or {},
    )
    session.add(event)
    await session.commit()
    return event
