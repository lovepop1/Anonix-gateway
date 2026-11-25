"""Typed Pydantic request and response schemas for the Control Plane."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PolicyVersionOut(BaseModel):
    id: str
    version_number: int
    status: str
    yaml_content: str
    created_by: str
    created_at: datetime


class PolicyOut(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    versions: list[PolicyVersionOut]


class PolicyCreateOut(BaseModel):
    id: str
    name: str
    version_number: int
    status: str


class PolicyVersionCreateOut(BaseModel):
    policy_id: str
    version_number: int
    status: str


class PolicyActivateOut(BaseModel):
    policy_id: str
    active_version: int


class PlaygroundOut(BaseModel):
    format: str
    role: str | None
    output: str
    k_achieved: bool
    conflict_count: int
    uncovered_count: int


class AuthProviderOut(BaseModel):
    id: str
    name: str
    provider_type: str
    is_enabled: bool
    issuer_url: str | None
    audience: str | None
    jwks_url: str | None
    groups_claim: str
    sub_claim: str
    trusted_cidrs: list[str]
    has_proxy_secret: bool
    created_at: datetime


class AuthProviderRefOut(BaseModel):
    id: str
    name: str
    provider_type: str
    is_enabled: bool


class GroupMappingOut(BaseModel):
    id: str
    provider_id: str | None
    external_group: str
    policy_role: str | None
    policy_id: str
    priority: int


class ApiKeyOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    groups: list[str]
    allowed_policy_ids: list[str] | None
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None


class ApiKeyCreateOut(BaseModel):
    id: str
    name: str
    key_prefix: str
    raw_key: str
    groups: list[str]


class ApiKeyUpdateOut(BaseModel):
    id: str
    name: str
    groups: list[str]
    is_active: bool


class ApiKeyRevokeOut(BaseModel):
    status: str
    id: str


class UpstreamOut(BaseModel):
    id: str
    name: str
    base_url: str
    auth_type: str
    auth_header_name: str | None
    has_credential: bool
    timeout_seconds: float
    is_active: bool


class UpstreamRefOut(BaseModel):
    id: str
    name: str
    base_url: str


class ProxyRouteOut(BaseModel):
    id: str
    name: str
    route_prefix: str
    upstream_id: str
    policy_id: str
    strip_prefix: bool
    allowed_methods: list[str]
    blocked_subpaths: list[str]
    allow_policy_override: bool
    on_unstructured: str
    is_active: bool


class ProxyRouteRefOut(BaseModel):
    id: str
    name: str
    route_prefix: str


class AdminUserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class AdminUserRefOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool = True


class AuditEventOut(BaseModel):
    id: str
    request_id: str
    caller_id: str
    auth_method: str
    route_id: str | None
    policy_id: str | None
    policy_version: int | None
    resolved_role: str | None
    format_name: str | None
    status_code: int
    duration_ms: float
    detail: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
