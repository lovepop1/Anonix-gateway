"""Command-line interface for Anonix Gateway (keygen, init, migrate, serve)."""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

import typer
import uvicorn
from cryptography.fernet import Fernet

from anonix_gateway.config import get_settings
from anonix_gateway.db.bootstrap import bootstrap_instance, is_bootstrapped
from anonix_gateway.db.session import dispose_engine, get_session_factory, init_db_schema

app = typer.Typer(
    name="anonix-gateway",
    help="Self-hosted on-the-fly data masking reverse proxy and API gateway.",
    no_args_is_help=True,
)


@app.command()
def keygen() -> None:
    """Generate fresh ANONIX_MASTER_KEY and ANONIX_ADMIN_JWT_SECRET values."""
    master_key = Fernet.generate_key().decode("ascii")
    jwt_secret = secrets.token_urlsafe(48)
    typer.echo(f"ANONIX_MASTER_KEY={master_key}")
    typer.echo(f"ANONIX_ADMIN_JWT_SECRET={jwt_secret}")


@app.command()
def init(
    org_name: str = typer.Option("Default Organization", prompt="Organization name"),
    admin_email: str = typer.Option(..., prompt="Initial platform_admin email"),
    admin_password: str = typer.Option(
        ...,
        prompt="Initial platform_admin password (min 8 chars)",
        hide_input=True,
        confirmation_prompt=True,
    ),
    write_env: bool = typer.Option(
        True,
        help="Write generated secrets to .env if it does not already exist.",
    ),
) -> None:
    """Initialize database schema, cryptographic secrets, and first platform_admin."""
    env_path = Path(".env")
    if write_env and not env_path.exists():
        master_key = Fernet.generate_key().decode("ascii")
        jwt_secret = secrets.token_urlsafe(48)
        env_path.write_text(
            f"ANONIX_ENV=development\n"
            f"ANONIX_MASTER_KEY={master_key}\n"
            f"ANONIX_ADMIN_JWT_SECRET={jwt_secret}\n",
            encoding="utf-8",
        )
        typer.echo("Created .env with fresh cryptographic keys.")

    async def _run() -> None:
        get_settings().resolve_secrets()
        await init_db_schema()
        factory = get_session_factory()
        async with factory() as session:
            if await is_bootstrapped(session):
                typer.echo("Instance is already bootstrapped.")
            else:
                tenant, admin = await bootstrap_instance(
                    session,
                    admin_email=admin_email,
                    admin_password=admin_password,
                    org_name=org_name,
                )
                typer.echo(
                    f"Bootstrapped organization '{tenant.name}' with admin '{admin.email}'."
                )
        await dispose_engine()

    asyncio.run(_run())


@app.command()
def migrate() -> None:
    """Ensure database tables are created/migrated."""

    async def _run() -> None:
        await init_db_schema()
        await dispose_engine()

    asyncio.run(_run())
    typer.echo("Database schema is up to date.")


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Bind host override"),
    port: int | None = typer.Option(None, help="Bind port override"),
) -> None:
    """Start the Anonix Gateway HTTP server."""
    settings = get_settings()
    uvicorn.run(
        "anonix_gateway.main:app",
        host=host or settings.host,
        port=port or settings.port,
        log_level=settings.log_level.lower(),
    )
