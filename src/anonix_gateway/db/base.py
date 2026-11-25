"""SQLAlchemy declarative base and shared model helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import DeclarativeBase


def generate_uuid() -> str:
    """Return a new UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all Anonix Gateway ORM models."""
