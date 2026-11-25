"""OIDC discovery, JWKS caching, and JWT validation."""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from anonix_gateway.db.models import AuthProvider

_JWKS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_JWKS_TTL_SECONDS = 300.0


def clear_jwks_cache() -> None:
    """Clear the in-memory JWKS cache (for tests)."""
    _JWKS_CACHE.clear()


async def _fetch_jwks_uri(issuer_url: str) -> str:
    """Discover ``jwks_uri`` from an OIDC provider's well-known metadata."""
    discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        data = resp.json()
    jwks_uri = data.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise ValueError(f"OIDC discovery at {discovery_url} did not return a valid jwks_uri.")
    return jwks_uri


async def _get_jwks(jwks_url: str) -> dict[str, Any]:
    """Return cached JWKS document, refreshing when expired."""
    now = time.monotonic()
    cached = _JWKS_CACHE.get(jwks_url)
    if cached is not None and (now - cached[0]) < _JWKS_TTL_SECONDS:
        return cached[1]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(jwks_url)
        resp.raise_for_status()
        jwks: dict[str, Any] = resp.json()
    _JWKS_CACHE[jwks_url] = (now, jwks)
    return jwks


def _select_signing_key(jwks: dict[str, Any], kid: str | None) -> Any:
    """Pick the matching JWK from *jwks* by ``kid`` (or the sole key if unambiguous)."""
    keys = jwks.get("keys", [])
    if not isinstance(keys, list) or not keys:
        raise ValueError("JWKS document contains no keys.")

    if kid is not None:
        for key_dict in keys:
            if key_dict.get("kid") == kid:
                return PyJWK.from_dict(key_dict).key
        raise ValueError(f"Signing key id '{kid}' not found in JWKS.")

    if len(keys) == 1:
        return PyJWK.from_dict(keys[0]).key
    raise ValueError("JWT header missing 'kid' and JWKS has multiple keys.")


async def validate_oidc_jwt(token: str, provider: AuthProvider) -> dict[str, Any]:
    """Validate an incoming Bearer JWT against *provider* and return its claims."""
    if not provider.issuer_url:
        raise ValueError(f"OIDC provider '{provider.name}' is missing issuer_url.")

    jwks_url = provider.jwks_url or await _fetch_jwks_uri(provider.issuer_url)
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    jwks = await _get_jwks(jwks_url)
    try:
        signing_key = _select_signing_key(jwks, kid)
    except ValueError:
        # Key rotation fallback: invalidate cache once and retry
        _JWKS_CACHE.pop(jwks_url, None)
        jwks = await _get_jwks(jwks_url)
        signing_key = _select_signing_key(jwks, kid)

    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        "issuer": provider.issuer_url,
    }
    if provider.audience:
        decode_kwargs["audience"] = provider.audience
    else:
        decode_kwargs["options"] = {"verify_aud": False}

    claims: dict[str, Any] = jwt.decode(token, signing_key, **decode_kwargs)
    return claims


def extract_claim_values(claims: dict[str, Any], claim_name: str) -> list[str]:
    """Extract normalized string values from a JWT claim (list or single string)."""
    raw = claims.get(claim_name)
    if raw is None:
        return []
    if isinstance(raw, str):
        stripped = raw.strip()
        return [stripped] if stripped else []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []
