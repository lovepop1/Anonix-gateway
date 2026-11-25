"""Control-plane AdminUser CRUD routes with self-lockout protection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import VALID_ADMIN_ROLES, AdminContext, require_admin_roles
from anonix_gateway.db.models import AdminUser
from anonix_gateway.db.session import get_session
from anonix_gateway.routes.admin.helpers import commit_or_409, count_active_platform_admins
from anonix_gateway.schemas.admin import AdminUserOut, AdminUserRefOut
from anonix_gateway.security.crypto import hash_password

router = APIRouter()


class AdminUserCreateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="policy_author")


class AdminUserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=256)


@router.get("/users", response_model=list[AdminUserOut])
async def list_admin_users(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[AdminUserOut]:
    stmt = select(AdminUser).where(AdminUser.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        AdminUserOut(
            id=u.id,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
        )
        for u in rows
    ]


@router.post(
    "/users",
    response_model=AdminUserRefOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_admin_user(
    body: AdminUserCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> AdminUserRefOut:
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
    await commit_or_409(session, f"Admin user '{user.email}' already exists.")
    return AdminUserRefOut(id=user.id, email=user.email, role=user.role)


@router.patch("/users/{user_id}", response_model=AdminUserRefOut)
async def update_admin_user(
    user_id: str,
    body: AdminUserUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> AdminUserRefOut:
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
            if await count_active_platform_admins(session, admin.tenant_id) <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot demote the last active platform_admin."
                )
        user.role = body.role

    if body.is_active is not None:
        if user.id == admin.admin_id and not body.is_active:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account.")
        if was_active_platform_admin and not body.is_active:
            if await count_active_platform_admins(session, admin.tenant_id) <= 1:
                raise HTTPException(
                    status_code=400, detail="Cannot deactivate the last active platform_admin."
                )
        user.is_active = body.is_active

    if body.password:
        user.password_hash = hash_password(body.password)

    await session.commit()
    return AdminUserRefOut(id=user.id, email=user.email, role=user.role, is_active=user.is_active)


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
        if await count_active_platform_admins(session, admin.tenant_id) <= 1:
            raise HTTPException(
                status_code=400, detail="Cannot delete the last active platform_admin."
            )
    await session.delete(user)
    await session.commit()
