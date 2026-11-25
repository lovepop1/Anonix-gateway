"""Password hashing, symmetric secret encryption, and API key utilities."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

_PASSWORD_HASHER = PasswordHasher()
_API_KEY_PREFIX = "axk_"


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def generate_api_key() -> tuple[str, str, str]:
    """Generate ``(raw_key, key_prefix, sha256_hash)`` for a new API key."""
    token = secrets.token_urlsafe(32)
    raw_key = f"{_API_KEY_PREFIX}{token}"
    key_prefix = raw_key[:12]
    key_hash = hash_api_key(raw_key)
    return raw_key, key_prefix, key_hash


def hash_api_key(raw_key: str) -> str:
    """Return hex-encoded SHA-256 digest of a raw API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str, expected_hash: str) -> bool:
    """Constant-time comparison of an API key against its stored SHA-256 hash."""
    actual_hash = hash_api_key(raw_key)
    return hmac.compare_digest(actual_hash, expected_hash)


def encrypt_secret(plaintext: str, master_key: str) -> str:
    """Encrypt a sensitive credential at rest using Fernet."""
    fernet = Fernet(master_key.encode("ascii"))
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str, master_key: str) -> str:
    """Decrypt a stored Fernet ciphertext; raises ValueError on invalid key/token."""
    fernet = Fernet(master_key.encode("ascii"))
    try:
        return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt stored secret with configured master key.") from exc
