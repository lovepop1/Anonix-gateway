"""Control-plane ProxyRoute CRUD routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.auth.admin import AdminContext, require_admin_roles
from anonix_gateway.db.models import ProxyRoute
from anonix_gateway.db.session import get_session
from anonix_gateway.routes.admin.helpers import commit_or_409, ensure_targets_exist
from anonix_gateway.schemas.admin import ProxyRouteOut, ProxyRouteRefOut

router = APIRouter()


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


@router.get("/routes", response_model=list[ProxyRouteOut])
async def list_routes(
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> list[ProxyRouteOut]:
    stmt = select(ProxyRoute).where(ProxyRoute.tenant_id == admin.tenant_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [
        ProxyRouteOut(
            id=r.id,
            name=r.name,
            route_prefix=r.route_prefix,
            upstream_id=r.upstream_id,
            policy_id=r.policy_id,
            strip_prefix=r.strip_prefix,
            allowed_methods=r.allowed_methods,
            blocked_subpaths=r.blocked_subpaths,
            allow_policy_override=r.allow_policy_override,
            on_unstructured=r.on_unstructured,
            is_active=r.is_active,
        )
        for r in rows
    ]


@router.post(
    "/routes",
    response_model=ProxyRouteRefOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_route(
    body: ProxyRouteCreateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> ProxyRouteRefOut:
    await ensure_targets_exist(
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
    await commit_or_409(session, f"Proxy route prefix '{prefix}' already exists.")
    return ProxyRouteRefOut(id=route.id, name=route.name, route_prefix=route.route_prefix)


@router.patch("/routes/{route_id}", response_model=ProxyRouteRefOut)
async def update_route(
    route_id: str,
    body: ProxyRouteUpdateRequest,
    admin: AdminContext = Depends(require_admin_roles("platform_admin")),
    session: AsyncSession = Depends(get_session),
) -> ProxyRouteRefOut:
    stmt = select(ProxyRoute).where(
        ProxyRoute.id == route_id,
        ProxyRoute.tenant_id == admin.tenant_id,
    )
    route = (await session.execute(stmt)).scalars().first()
    if route is None:
        raise HTTPException(status_code=404, detail="Proxy route not found.")

    await ensure_targets_exist(
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

    await commit_or_409(session, f"Proxy route prefix '{route.route_prefix}' already exists.")
    return ProxyRouteRefOut(id=route.id, name=route.name, route_prefix=route.route_prefix)


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
