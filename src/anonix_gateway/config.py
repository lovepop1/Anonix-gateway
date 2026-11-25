"""Application configuration and fail-closed secret resolution."""

from __future__ import annotations

import json
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and optional ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="ANONIX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "production"] = "development"
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8000
    log_level: str = "INFO"
    tenancy_mode: Literal["single_org", "multi_tenant"] = "single_org"

    database_url: str | None = None
    redis_url: str | None = None
    master_key: str | None = None
    admin_jwt_secret: str | None = None

    data_dir: Path = Field(default=Path("./data"))
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_org_name: str = "Default Organization"

    cors_origins: str = ""
    allow_private_upstreams: bool = False
    admin_token_ttl_minutes: int = 480
    rate_limit_per_minute: int = 120
    max_payload_bytes: int = 10 * 1024 * 1024  # 10 MiB

    @property
    def resolved_database_url(self) -> str:
        """Return configured DB URL or auto-create a local SQLite path."""
        if self.database_url and self.database_url.strip():
            url = self.database_url.strip()
            if url.startswith("postgresql://"):
                return url.replace("postgresql://", "postgresql+asyncpg://", 1)
            if url.startswith("postgres://"):
                return url.replace("postgres://", "postgresql+asyncpg://", 1)
            return url

        self.data_dir.mkdir(parents=True, exist_ok=True)
        db_path = (self.data_dir / "anonix.db").resolve()
        return f"sqlite+aiosqlite:///{db_path.as_posix()}"

    @property
    def is_sqlite(self) -> bool:
        """Return True when the resolved database backend is SQLite."""
        return self.resolved_database_url.startswith("sqlite")

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse comma-separated CORS origins."""
        if not self.cors_origins.strip():
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolve_secrets(self) -> tuple[str, str]:
        """Return ``(master_key, admin_jwt_secret)`` failing closed in production."""
        mk = (self.master_key or "").strip()
        jwt_sec = (self.admin_jwt_secret or "").strip()
        if mk and jwt_sec:
            return mk, jwt_sec

        if self.env == "production":
            raise RuntimeError(
                "ANONIX_MASTER_KEY and ANONIX_ADMIN_JWT_SECRET must be set when "
                "ANONIX_ENV=production. Generate them with `anonix-gateway keygen`."
            )

        self.data_dir.mkdir(parents=True, exist_ok=True)
        secrets_file = self.data_dir / ".anonix_secrets.json"
        if secrets_file.exists():
            data = json.loads(secrets_file.read_text(encoding="utf-8"))
            mk = mk or str(data.get("master_key", ""))
            jwt_sec = jwt_sec or str(data.get("admin_jwt_secret", ""))

        changed = False
        if not mk:
            mk = Fernet.generate_key().decode("ascii")
            changed = True
        if not jwt_sec:
            jwt_sec = secrets.token_urlsafe(48)
            changed = True

        if changed or not secrets_file.exists():
            secrets_file.write_text(
                json.dumps({"master_key": mk, "admin_jwt_secret": jwt_sec}, indent=2),
                encoding="utf-8",
            )
            try:
                os.chmod(secrets_file, 0o600)
            except OSError:
                pass

        return mk, jwt_sec


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached :class:`Settings` instance."""
    return Settings()


def clear_settings_cache() -> None:
    """Clear the cached settings (intended for tests)."""
    get_settings.cache_clear()
