"""Shared pytest fixtures for Anonix Gateway tests."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet

from anonix_gateway.auth.oidc import clear_jwks_cache
from anonix_gateway.cache.rate_limit import reset_rate_limiter
from anonix_gateway.config import clear_settings_cache
from anonix_gateway.db.session import dispose_engine, init_db_schema
from anonix_gateway.main import create_app
from anonix_gateway.masking.engine_cache import clear_engine_cache


@pytest.fixture()
async def gateway_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield an isolated AsyncClient backed by a fresh SQLite DB and settings."""
    master_key = Fernet.generate_key().decode("ascii")
    db_url = f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    monkeypatch.setenv("ANONIX_ENV", "development")
    monkeypatch.setenv("ANONIX_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ANONIX_DATABASE_URL", db_url)
    monkeypatch.setenv("ANONIX_MASTER_KEY", master_key)
    monkeypatch.setenv("ANONIX_ADMIN_JWT_SECRET", "test-admin-jwt-secret-key-at-least-32-bytes")
    monkeypatch.setenv("ANONIX_ALLOW_PRIVATE_UPSTREAMS", "true")
    monkeypatch.delenv("ANONIX_REDIS_URL", raising=False)
    monkeypatch.delenv("ANONIX_BOOTSTRAP_ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ANONIX_BOOTSTRAP_ADMIN_PASSWORD", raising=False)

    clear_settings_cache()
    clear_engine_cache()
    clear_jwks_cache()
    await reset_rate_limiter()
    await dispose_engine()

    app = create_app()
    await init_db_schema()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    await reset_rate_limiter()
    await dispose_engine()
    clear_settings_cache()
    clear_engine_cache()
    clear_jwks_cache()


async def bootstrap_admin(
    client: httpx.AsyncClient,
    *,
    email: str = "admin@acme.org",
    password: str = "StrongPass123!",
    org_name: str = "Acme Corp",
) -> dict[str, str]:
    """Bootstrap an isolated test instance and return Bearer auth headers."""
    resp = await client.post(
        "/api/setup/bootstrap",
        json={
            "org_name": org_name,
            "admin_email": email,
            "admin_password": password,
        },
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
