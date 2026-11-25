"""Aggregated control-plane admin router."""

from __future__ import annotations

from fastapi import APIRouter

from anonix_gateway.routes.admin import (
    api_keys,
    audit,
    auth_providers,
    group_mappings,
    policies,
    proxy_routes,
    upstreams,
    users,
)

router = APIRouter(prefix="/api/admin", tags=["admin"])
router.include_router(policies.router)
router.include_router(auth_providers.router)
router.include_router(group_mappings.router)
router.include_router(api_keys.router)
router.include_router(upstreams.router)
router.include_router(proxy_routes.router)
router.include_router(users.router)
router.include_router(audit.router)
