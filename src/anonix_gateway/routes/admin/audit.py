"""Control-plane Zero-PII AuditEvent query routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.db.models import AuditEvent
from anonix_gateway.db.session import get_session
from anonix_gateway.schemas.admin import AuditEventOut

router = APIRouter()


@router.get("/audit", response_model=list[AuditEventOut])
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "auditor")),
    session: AsyncSession = Depends(get_session),
) -> list[AuditEventOut]:
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.tenant_id == admin.tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        AuditEventOut(
            id=e.id,
            request_id=e.request_id,
            caller_id=e.caller_id,
            auth_method=e.auth_method,
            route_id=e.route_id,
            policy_id=e.policy_id,
            policy_version=e.policy_version,
            resolved_role=e.resolved_role,
            format_name=e.format_name,
            status_code=e.status_code,
            duration_ms=e.duration_ms,
            detail=e.detail,
            created_at=e.created_at,
        )
        for e in rows
    ]
