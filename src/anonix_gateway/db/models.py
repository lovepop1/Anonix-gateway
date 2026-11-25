"""ORM models for Anonix Gateway (PostgreSQL and SQLite compatible)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from anonix_gateway.db.base import Base, generate_uuid, utc_now


class Tenant(Base):
    """Organization boundary (single_org uses 'default'; multi_tenant supports many)."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class AdminUser(Base):
    """Local control-plane administrator account."""

    __tablename__ = "admin_users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_admin_tenant_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="platform_admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthProvider(Base):
    """Configured inbound authentication provider (OIDC/JWT or Trusted-Proxy)."""

    __tablename__ = "auth_providers"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_auth_provider_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(32), nullable=False)  # oidc | trusted_proxy
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # OIDC fields
    issuer_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    audience: Mapped[str | None] = mapped_column(String(255), nullable=True)
    jwks_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    groups_claim: Mapped[str] = mapped_column(String(128), default="groups", nullable=False)
    sub_claim: Mapped[str] = mapped_column(String(128), default="sub", nullable=False)

    # Trusted-proxy fields
    trusted_cidrs: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    encrypted_proxy_secret: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class MaskingPolicy(Base):
    """Named masking policy container with versioned YAML definitions."""

    __tablename__ = "masking_policies"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_policy_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="PolicyVersion.version_number.desc()",
    )


class PolicyVersion(Base):
    """Immutable versioned YAML snapshot of a :class:`MaskingPolicy`."""

    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint("policy_id", "version_number", name="uq_policy_version_num"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    policy_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("masking_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    policy: Mapped[MaskingPolicy] = relationship(back_populates="versions")


class GroupMapping(Base):
    """Maps an external group claim to a policy role and optional policy override."""

    __tablename__ = "group_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("auth_providers.id", ondelete="CASCADE"), nullable=True, index=True
    )
    external_group: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("masking_policies.id", ondelete="CASCADE"), nullable=False
    )
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class ApiKey(Base):
    """Service/pipeline API key carrying assigned groups and optional policy scope."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    groups: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allowed_policy_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Upstream(Base):
    """Registered enterprise backend API target for reverse-proxy masking."""

    __tablename__ = "upstreams"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_upstream_tenant_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_type: Mapped[str] = mapped_column(
        String(32), default="none", nullable=False
    )  # none | bearer | api_key_header | basic
    auth_header_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    encrypted_credential: Mapped[str | None] = mapped_column(Text, nullable=True)
    timeout_seconds: Mapped[float] = mapped_column(Float, default=15.0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class ProxyRoute(Base):
    """Maps a public ``/proxy/{prefix}`` path to an Upstream and MaskingPolicy."""

    __tablename__ = "proxy_routes"
    __table_args__ = (UniqueConstraint("tenant_id", "route_prefix", name="uq_route_tenant_prefix"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    route_prefix: Mapped[str] = mapped_column(String(255), nullable=False)
    upstream_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("upstreams.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("masking_policies.id", ondelete="RESTRICT"), nullable=False
    )
    strip_prefix: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allowed_methods: Mapped[list[str]] = mapped_column(
        JSON, default=lambda: ["GET", "POST"], nullable=False
    )
    blocked_subpaths: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    allow_policy_override: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    on_unstructured: Mapped[str] = mapped_column(String(32), default="fail_closed", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class AuditEvent(Base):
    """Zero-PII compliance audit ledger (never stores raw or masked field values)."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    caller_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    route_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    format_name: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fields_masked_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
