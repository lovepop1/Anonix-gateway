"""Health and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from anonix_gateway import __version__
from anonix_gateway.db.session import get_session

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
async def readyz(session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    """Readiness probe verifying database connectivity."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unavailable: {exc}",
        ) from exc
    return {"status": "ready", "version": __version__}
