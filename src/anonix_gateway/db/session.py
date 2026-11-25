"""Async SQLAlchemy engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from anonix_gateway.config import get_settings
from anonix_gateway.db.base import Base

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return (and lazily initialize) the shared async SQLAlchemy engine."""
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        url = settings.resolved_database_url
        connect_args = {"check_same_thread": False} if settings.is_sqlite else {}
        _engine = create_async_engine(
            url,
            echo=False,
            pool_pre_ping=not settings.is_sqlite,
            connect_args=connect_args,
        )
        _session_factory = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the async session factory."""
    if _session_factory is None:
        get_engine()
    assert _session_factory is not None
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a scoped async database session."""
    factory = get_session_factory()
    async with factory() as session:
        yield session


async def init_db_schema() -> None:
    """Create tables if they do not exist (for local/dev/test convenience)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose the engine and reset module singletons (for shutdown & tests)."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
