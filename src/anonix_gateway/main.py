"""FastAPI application factory and lifespan management."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint

from anonix_gateway import __version__
from anonix_gateway.cache.rate_limit import reset_rate_limiter
from anonix_gateway.config import get_settings
from anonix_gateway.db.bootstrap import bootstrap_instance, is_bootstrapped
from anonix_gateway.db.session import dispose_engine, get_session_factory, init_db_schema
from anonix_gateway.routes import admin, health, mask, proxy, setup


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize secrets, database schema, and optional env-var bootstrap."""
    settings = get_settings()
    settings.resolve_secrets()
    await init_db_schema()

    if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
        factory = get_session_factory()
        async with factory() as session:
            if not await is_bootstrapped(session):
                await bootstrap_instance(
                    session,
                    admin_email=settings.bootstrap_admin_email,
                    admin_password=settings.bootstrap_admin_password,
                    org_name=settings.bootstrap_org_name,
                )

    yield

    await reset_rate_limiter()
    await dispose_engine()


def create_app() -> FastAPI:
    """Create and configure the :class:`FastAPI` application."""
    settings = get_settings()
    app = FastAPI(
        title="Anonix Gateway",
        version=__version__,
        description="Self-hosted on-the-fly data masking reverse proxy and API gateway.",
        lifespan=_lifespan,
    )

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def security_headers_middleware(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        path = request.url.path
        if path.startswith(("/v1/", "/proxy/", "/api/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.include_router(health.router)
    app.include_router(setup.router)
    app.include_router(admin.router)
    app.include_router(mask.router)
    app.include_router(proxy.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir() and (static_dir / "index.html").is_file():
        assets_dir = static_dir / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="console-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str) -> FileResponse:
            candidate = static_dir / full_path
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(static_dir / "index.html")

    return app


app = create_app()
