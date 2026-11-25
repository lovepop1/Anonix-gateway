"""Initial Anonix Gateway schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("slug", sa.String(length=128), nullable=False, unique=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)

    op.create_table(
        "admin_users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "email", name="uq_admin_tenant_email"),
    )
    op.create_index("ix_admin_users_tenant_id", "admin_users", ["tenant_id"])

    op.create_table(
        "auth_providers",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider_type", sa.String(length=32), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("issuer_url", sa.String(length=512), nullable=True),
        sa.Column("audience", sa.String(length=255), nullable=True),
        sa.Column("jwks_url", sa.String(length=512), nullable=True),
        sa.Column("groups_claim", sa.String(length=128), nullable=False),
        sa.Column("sub_claim", sa.String(length=128), nullable=False),
        sa.Column("trusted_cidrs", sa.JSON(), nullable=False),
        sa.Column("encrypted_proxy_secret", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_auth_provider_tenant_name"),
    )
    op.create_index("ix_auth_providers_tenant_id", "auth_providers", ["tenant_id"])

    op.create_table(
        "masking_policies",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_policy_tenant_name"),
    )
    op.create_index("ix_masking_policies_tenant_id", "masking_policies", ["tenant_id"])

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "policy_id",
            sa.String(length=36),
            sa.ForeignKey("masking_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("yaml_content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "version_number", name="uq_policy_version_num"),
    )
    op.create_index("ix_policy_versions_policy_id", "policy_versions", ["policy_id"])

    op.create_table(
        "group_mappings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "provider_id",
            sa.String(length=36),
            sa.ForeignKey("auth_providers.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("external_group", sa.String(length=255), nullable=False),
        sa.Column("policy_role", sa.String(length=128), nullable=True),
        sa.Column(
            "policy_id",
            sa.String(length=36),
            sa.ForeignKey("masking_policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_group_mappings_tenant_id", "group_mappings", ["tenant_id"])
    op.create_index("ix_group_mappings_external_group", "group_mappings", ["external_group"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_prefix", sa.String(length=24), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("groups", sa.JSON(), nullable=False),
        sa.Column("allowed_policy_ids", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)

    op.create_table(
        "upstreams",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("auth_type", sa.String(length=32), nullable=False),
        sa.Column("auth_header_name", sa.String(length=128), nullable=True),
        sa.Column("encrypted_credential", sa.Text(), nullable=True),
        sa.Column("timeout_seconds", sa.Float(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_upstream_tenant_name"),
    )
    op.create_index("ix_upstreams_tenant_id", "upstreams", ["tenant_id"])

    op.create_table(
        "proxy_routes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("route_prefix", sa.String(length=255), nullable=False),
        sa.Column(
            "upstream_id",
            sa.String(length=36),
            sa.ForeignKey("upstreams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "policy_id",
            sa.String(length=36),
            sa.ForeignKey("masking_policies.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("strip_prefix", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allowed_methods", sa.JSON(), nullable=False),
        sa.Column("blocked_subpaths", sa.JSON(), nullable=False),
        sa.Column("allow_policy_override", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("on_unstructured", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "route_prefix", name="uq_route_tenant_prefix"),
    )
    op.create_index("ix_proxy_routes_tenant_id", "proxy_routes", ["tenant_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("caller_id", sa.String(length=255), nullable=False),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("route_id", sa.String(length=36), nullable=True),
        sa.Column("policy_id", sa.String(length=36), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("resolved_role", sa.String(length=128), nullable=True),
        sa.Column("format_name", sa.String(length=32), nullable=True),
        sa.Column("fields_masked_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("proxy_routes")
    op.drop_table("upstreams")
    op.drop_table("api_keys")
    op.drop_table("group_mappings")
    op.drop_table("policy_versions")
    op.drop_table("masking_policies")
    op.drop_table("auth_providers")
    op.drop_table("admin_users")
    op.drop_table("tenants")
