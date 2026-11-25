"""First-run tenant and administrator bootstrap helpers."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.db.models import AdminUser, Tenant
from anonix_gateway.security.crypto import hash_password

DEFAULT_TENANT_SLUG = "default"


async def get_or_create_default_tenant(
    session: AsyncSession,
    *,
    org_name: str = "Default Organization",
) -> Tenant:
    """Return the default tenant, creating it if it does not yet exist."""
    stmt = select(Tenant).where(Tenant.slug == DEFAULT_TENANT_SLUG)
    res = await session.execute(stmt)
    tenant = res.scalars().first()
    if tenant is not None:
        return tenant

    tenant = Tenant(slug=DEFAULT_TENANT_SLUG, name=org_name, is_active=True)
    session.add(tenant)
    await session.flush()
    return tenant


async def is_bootstrapped(session: AsyncSession) -> bool:
    """Return True if at least one active AdminUser exists."""
    stmt = select(func.count(AdminUser.id))
    res = await session.execute(stmt)
    count = int(res.scalar_one() or 0)
    return count > 0


async def bootstrap_instance(
    session: AsyncSession,
    *,
    admin_email: str,
    admin_password: str,
    org_name: str = "Default Organization",
) -> tuple[Tenant, AdminUser]:
    """Bootstrap the initial tenant and platform_admin user.

    Raises:
        RuntimeError: If an admin user already exists.
    """
    if await is_bootstrapped(session):
        raise RuntimeError("Anonix Gateway is already bootstrapped.")

    tenant = await get_or_create_default_tenant(session, org_name=org_name)
    if tenant.name != org_name and org_name.strip():
        tenant.name = org_name.strip()

    admin = AdminUser(
        tenant_id=tenant.id,
        email=admin_email.strip().lower(),
        password_hash=hash_password(admin_password),
        role="platform_admin",
        is_active=True,
    )
    session.add(admin)
    await session.commit()
    await session.refresh(tenant)
    await session.refresh(admin)
    return tenant, admin
