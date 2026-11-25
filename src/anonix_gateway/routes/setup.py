"""First-run setup wizard and administrator authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway.config import get_settings
from anonix_gateway.db.base import utc_now
from anonix_gateway.db.bootstrap import bootstrap_instance, is_bootstrapped
from anonix_gateway.db.models import AdminUser
from anonix_gateway.db.session import get_session
from anonix_gateway.security.crypto import verify_password
from anonix_gateway.security.tokens import create_admin_token

router = APIRouter(prefix="/api", tags=["setup-auth"])


class SetupStatusResponse(BaseModel):
    """Indicates whether the instance has completed initial admin bootstrap."""

    bootstrapped: bool
    tenancy_mode: str


class BootstrapRequest(BaseModel):
    """First-run administrator creation payload."""

    org_name: str = Field(default="Default Organization", min_length=1, max_length=255)
    admin_email: str = Field(min_length=3, max_length=255)
    admin_password: str = Field(min_length=8, max_length=256)


class AdminLoginRequest(BaseModel):
    """Local administrator login credentials."""

    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class AdminTokenResponse(BaseModel):
    """Signed admin session JWT response."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105
    role: str
    email: str


@router.get("/setup/status", response_model=SetupStatusResponse)
async def setup_status(session: AsyncSession = Depends(get_session)) -> SetupStatusResponse:
    """Return whether initial bootstrap has been completed."""
    settings = get_settings()
    return SetupStatusResponse(
        bootstrapped=await is_bootstrapped(session),
        tenancy_mode=settings.tenancy_mode,
    )


@router.post(
    "/setup/bootstrap",
    response_model=AdminTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def setup_bootstrap(
    body: BootstrapRequest,
    session: AsyncSession = Depends(get_session),
) -> AdminTokenResponse:
    """Create the initial organization and platform_admin user (one-time only)."""
    try:
        tenant, admin = await bootstrap_instance(
            session,
            admin_email=body.admin_email,
            admin_password=body.admin_password,
            org_name=body.org_name,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    settings = get_settings()
    _, jwt_secret = settings.resolve_secrets()
    token = create_admin_token(
        admin_id=admin.id,
        email=admin.email,
        role=admin.role,
        tenant_id=tenant.id,
        secret=jwt_secret,
        ttl_minutes=settings.admin_token_ttl_minutes,
    )
    return AdminTokenResponse(access_token=token, role=admin.role, email=admin.email)


@router.post("/admin/login", response_model=AdminTokenResponse)
async def admin_login(
    body: AdminLoginRequest,
    session: AsyncSession = Depends(get_session),
) -> AdminTokenResponse:
    """Authenticate a local admin user and return a signed JWT."""
    email_norm = body.email.strip().lower()
    stmt = select(AdminUser).where(
        AdminUser.email == email_norm,
        AdminUser.is_active.is_(True),
    )
    res = await session.execute(stmt)
    admin = res.scalars().first()
    if admin is None or not verify_password(body.password, admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin email or password.",
        )

    admin.last_login_at = utc_now()
    await session.commit()

    settings = get_settings()
    _, jwt_secret = settings.resolve_secrets()
    token = create_admin_token(
        admin_id=admin.id,
        email=admin.email,
        role=admin.role,
        tenant_id=admin.tenant_id,
        secret=jwt_secret,
        ttl_minutes=settings.admin_token_ttl_minutes,
    )
    return AdminTokenResponse(access_token=token, role=admin.role, email=admin.email)
