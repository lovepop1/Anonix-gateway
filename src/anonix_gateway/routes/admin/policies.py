"""Control-plane MaskingPolicy CRUD, versioning, and live playground routes."""

from __future__ import annotations

from anonix.engine import MaskingEngine
from anonix.exceptions import PolicyValidationError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.db.models import MaskingPolicy, PolicyVersion
from anonix_gateway.db.session import get_session
from anonix_gateway.masking.engine_cache import validate_policy_yaml
from anonix_gateway.schemas.admin import (
    PlaygroundOut,
    PolicyActivateOut,
    PolicyCreateOut,
    PolicyOut,
    PolicyVersionCreateOut,
    PolicyVersionOut,
)

router = APIRouter()


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


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(
    admin: AdminContext = Depends(
        require_admin_roles("platform_admin", "policy_author", "auditor")
    ),
    session: AsyncSession = Depends(get_session),
) -> list[PolicyOut]:
    stmt = (
        select(MaskingPolicy)
        .where(MaskingPolicy.tenant_id == admin.tenant_id)
        .options(selectinload(MaskingPolicy.versions))
        .order_by(MaskingPolicy.name.asc())
    )
    policies = (await session.execute(stmt)).scalars().all()
    return [
        PolicyOut(
            id=p.id,
            name=p.name,
            description=p.description,
            created_at=p.created_at,
            versions=[
                PolicyVersionOut(
                    id=v.id,
                    version_number=v.version_number,
                    status=v.status,
                    yaml_content=v.yaml_content,
                    created_by=v.created_by,
                    created_at=v.created_at,
                )
                for v in p.versions
            ],
        )
        for p in policies
    ]


@router.post("/policies", response_model=PolicyCreateOut, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> PolicyCreateOut:
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
    return PolicyCreateOut(id=policy.id, name=policy.name, version_number=1, status="active")


@router.post(
    "/policies/{policy_id}/versions",
    response_model=PolicyVersionCreateOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_policy_version(
    policy_id: str,
    body: PolicyVersionCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> PolicyVersionCreateOut:
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
    return PolicyVersionCreateOut(
        policy_id=policy.id,
        version_number=next_num,
        status=new_ver.status,
    )


@router.post(
    "/policies/{policy_id}/versions/{version_number}/activate",
    response_model=PolicyActivateOut,
)
async def activate_policy_version(
    policy_id: str,
    version_number: int,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
    session: AsyncSession = Depends(get_session),
) -> PolicyActivateOut:
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
    return PolicyActivateOut(policy_id=policy.id, active_version=version_number)


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


@router.post("/policies/playground", response_model=PlaygroundOut)
async def policy_playground(
    body: PlaygroundRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin", "policy_author")),
) -> PlaygroundOut:
    """Dry-run a policy YAML against sample data in memory (zero persistence)."""
    try:
        policy = validate_policy_yaml(body.yaml_content)
        engine = MaskingEngine(policy, salt=f"playground:{admin.tenant_id}")
        result = engine.mask(body.payload, format=body.format, role=body.role)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return PlaygroundOut(
        format=result.format_name,
        role=body.role,
        output=result.output_text,
        k_achieved=result.k_achieved,
        conflict_count=result.conflict_count,
        uncovered_count=result.uncovered_count,
    )
