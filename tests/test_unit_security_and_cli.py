"""Unit tests for cryptography, tokens, rate limiter, and CLI commands."""

from __future__ import annotations

from pathlib import Path

import jwt
import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from anonix_gateway.cache.rate_limit import RateLimiter
from anonix_gateway.cli import app as cli_app
from anonix_gateway.security.crypto import (
    decrypt_secret,
    encrypt_secret,
    generate_api_key,
    hash_password,
    verify_api_key,
    verify_password,
)
from anonix_gateway.security.tokens import create_admin_token, decode_admin_token


def test_password_hashing_and_validation() -> None:
    hashed = hash_password("SecurePass123!")
    assert verify_password("SecurePass123!", hashed) is True
    assert verify_password("WrongPass", hashed) is False
    with pytest.raises(ValueError, match="8 characters"):
        hash_password("short")


def test_api_key_generation_and_constant_time_verify() -> None:
    raw, prefix, digest = generate_api_key()
    assert raw.startswith("axk_")
    assert raw.startswith(prefix)
    assert verify_api_key(raw, digest) is True
    assert verify_api_key("axk_wrong", digest) is False


def test_secret_encryption_roundtrip() -> None:
    key = Fernet.generate_key().decode("ascii")
    other_key = Fernet.generate_key().decode("ascii")
    ciphertext = encrypt_secret("upstream-bearer-secret", key)
    assert ciphertext != "upstream-bearer-secret"
    assert decrypt_secret(ciphertext, key) == "upstream-bearer-secret"
    with pytest.raises(ValueError, match="Failed to decrypt"):
        decrypt_secret(ciphertext, other_key)


def test_admin_jwt_roundtrip_and_type_check() -> None:
    secret = "test-jwt-secret-with-plenty-of-entropy-bytes"
    tok = create_admin_token(
        admin_id="adm-1",
        email="admin@example.com",
        role="platform_admin",
        tenant_id="t-1",
        secret=secret,
        ttl_minutes=5,
    )
    claims = decode_admin_token(tok, secret)
    assert claims["sub"] == "adm-1"
    assert claims["role"] == "platform_admin"

    wrong_type = jwt.encode(
        {
            "sub": "adm-1",
            "role": "platform_admin",
            "tenant_id": "t-1",
            "exp": 9999999999,
            "typ": "other",
        },
        secret,
        algorithm="HS256",
    )
    with pytest.raises(jwt.InvalidTokenError):
        decode_admin_token(wrong_type, secret)


async def test_in_memory_rate_limiter_enforces_quota() -> None:
    limiter = RateLimiter(redis_url=None, limit_per_minute=2)
    assert await limiter.allow("caller-1") is True
    assert await limiter.allow("caller-1") is True
    assert await limiter.allow("caller-1") is False
    assert await limiter.allow("caller-2") is True


def test_cli_keygen_and_serve_ssl_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    res = runner.invoke(cli_app, ["keygen"])
    assert res.exit_code == 0
    assert "ANONIX_MASTER_KEY=" in res.stdout
    assert "ANONIX_ADMIN_JWT_SECRET=" in res.stdout

    monkeypatch.chdir(tmp_path)
    bad_ssl = runner.invoke(cli_app, ["serve", "--ssl-certfile", "cert.pem"])
    assert bad_ssl.exit_code != 0
