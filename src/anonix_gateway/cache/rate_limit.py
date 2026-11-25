"""Rate limiter supporting Redis (multi-replica) with automatic in-memory fallback."""

from __future__ import annotations

import logging
import time
from collections import defaultdict

import redis.asyncio as aioredis

from anonix_gateway.config import get_settings

logger = logging.getLogger(__name__)


class RateLimiter:
    """Fixed-window per-minute rate limiter with Redis or in-memory backend."""

    def __init__(self, redis_url: str | None = None, limit_per_minute: int = 120) -> None:
        self._limit = limit_per_minute
        self._redis: aioredis.Redis | None = None
        if redis_url and redis_url.strip():
            self._redis = aioredis.Redis.from_url(redis_url.strip(), decode_responses=True)
        self._memory_windows: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))

    async def allow(self, key: str) -> bool:
        """Return True if *key* is within its per-minute quota."""
        if self._limit <= 0:
            return True

        window = int(time.time() // 60)
        if self._redis is not None:
            try:
                redis_key = f"anonix:rl:{key}:{window}"
                count = await self._redis.incr(redis_key)
                if count == 1:
                    await self._redis.expire(redis_key, 70)
                return int(count) <= self._limit
            except Exception as exc:
                # Fall back to in-memory limiter if Redis is momentarily unavailable
                logger.debug("Redis rate limiter fallback to memory: %s", exc)

        prev_window, prev_count = self._memory_windows[key]
        if prev_window != window:
            self._memory_windows[key] = (window, 1)
            return True
        new_count = prev_count + 1
        self._memory_windows[key] = (window, new_count)
        return new_count <= self._limit

    async def close(self) -> None:
        """Close the Redis connection pool if initialized."""
        if self._redis is not None:
            await self._redis.aclose()


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the shared :class:`RateLimiter` singleton."""
    global _limiter
    if _limiter is None:
        settings = get_settings()
        _limiter = RateLimiter(
            redis_url=settings.redis_url,
            limit_per_minute=settings.rate_limit_per_minute,
        )
    return _limiter


async def reset_rate_limiter() -> None:
    """Reset the rate limiter singleton (for tests & shutdown)."""
    global _limiter
    if _limiter is not None:
        await _limiter.close()
    _limiter = None
