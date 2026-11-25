"""Thread-safe in-memory cache for compiled ``anonix.MaskingEngine`` instances."""

from __future__ import annotations

import hashlib
from collections import OrderedDict

from anonix.engine import MaskingEngine
from anonix.policy.loader import load_policy_from_yaml
from anonix.policy.models import MaskingPolicy

_MAX_ENGINES = 256
_ENGINE_CACHE: OrderedDict[tuple[str, int, str], MaskingEngine] = OrderedDict()


def validate_policy_yaml(yaml_content: str) -> MaskingPolicy:
    """Parse and validate a policy YAML string via ``anonix``."""
    return load_policy_from_yaml(yaml_content)


def get_cached_engine(
    *,
    policy_id: str,
    version_number: int,
    yaml_content: str,
    tenant_salt: str,
) -> MaskingEngine:
    """Return a cached :class:`MaskingEngine` for ``(policy_id, version_number)``."""
    salt_digest = hashlib.sha256(tenant_salt.encode("utf-8")).hexdigest()[:16]
    cache_key = (policy_id, version_number, salt_digest)

    engine = _ENGINE_CACHE.get(cache_key)
    if engine is not None:
        _ENGINE_CACHE.move_to_end(cache_key)
        return engine

    policy = load_policy_from_yaml(yaml_content)
    engine = MaskingEngine(policy, salt=tenant_salt)
    _ENGINE_CACHE[cache_key] = engine
    if len(_ENGINE_CACHE) > _MAX_ENGINES:
        _ENGINE_CACHE.popitem(last=False)
    return engine


def clear_engine_cache() -> None:
    """Clear all cached ``MaskingEngine`` instances (for tests)."""
    _ENGINE_CACHE.clear()
