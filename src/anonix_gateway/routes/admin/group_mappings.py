"""Control-plane GroupMapping CRUD routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.db.models import GroupMapping
from anonix_gateway.db.session import get_session
from anonix_gateway.routes.admin.helpers import ensure_targets_exist
from anonix_gateway.schemas.admin import GroupMappingOut

router = APIRouter()


class GroupMappingCreateRequest(BaseModel):
    provider_id: str | None = None
    external_group: str = Field(min_length=1, max_length=255)
    policy_role: str | None = Field(default=None, max_length=128)
    policy_id: str = Field(min_length=1, max_length=36)
    priority: int = 0


class GroupMappingUpdateRequest(BaseModel):
    external_group: str | None = Field(default=None, min_length=1, max_length=255)
    policy_role: str | None = Field(default=None, max_length=128)
    policy_id: str | None = Field(default=None, min_length=1, max_length=36)
    priority: int | None = None


@router.get("/group-mappings", response_model=list[GroupMappingOut])
async def list_group_mappings(
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> list[GroupMappingOut]:
    stmt = (
        select(GroupMapping)
        .where(GroupMapping.tenant_id == admin.tenant_id)
        .order_by(GroupMapping.priority.desc())
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [
        GroupMappingOut(
            id=m.id,
            provider_id=m.provider_id,
            external_group=m.external_group,
            policy_role=m.policy_role,
            policy_id=m.policy_id,
            priority=m.priority,
        )
        for m in rows
    ]


@router.post(
    "/group-mappings",
    response_model=GroupMappingOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_group_mapping(
    body: GroupMappingCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> GroupMappingOut:
    await ensure_targets_exist(session, tenant_id=admin.tenant_id, policy_id=body.policy_id)
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
    return GroupMappingOut(
        id=mapping.id,
        provider_id=mapping.provider_id,
        external_group=mapping.external_group,
        policy_role=mapping.policy_role,
        policy_id=mapping.policy_id,
        priority=mapping.priority,
    )


@router.patch("/group-mappings/{mapping_id}", response_model=GroupMappingOut)
async def update_group_mapping(
    mapping_id: str,
    body: GroupMappingUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> GroupMappingOut:
    stmt = select(GroupMapping).where(
        GroupMapping.id == mapping_id,
        GroupMapping.tenant_id == admin.tenant_id,
    )
    mapping = (await session.execute(stmt)).scalars().first()
    if mapping is None:
        raise HTTPException(status_code=404, detail="Group mapping not found.")

    if body.policy_id is not None:
        await ensure_targets_exist(session, tenant_id=admin.tenant_id, policy_id=body.policy_id)
        mapping.policy_id = body.policy_id
    if body.external_group is not None:
        mapping.external_group = body.external_group.strip()
    if body.policy_role is not None:
        mapping.policy_role = body.policy_role.strip() or None
    if body.priority is not None:
        mapping.priority = body.priority

    await session.commit()
    return GroupMappingOut(
        id=mapping.id,
        provider_id=mapping.provider_id,
        external_group=mapping.external_group,
        policy_role=mapping.policy_role,
        policy_id=mapping.policy_id,
        priority=mapping.priority,
    )


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
