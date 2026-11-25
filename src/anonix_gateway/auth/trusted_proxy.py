"""Trusted-proxy header authentication (CIDR allowlist + shared secret)."""

from __future__ import annotations

import hmac
import ipaddress

from fastapi import Request

from anonix_gateway.db.models import AuthProvider
from anonix_gateway.security.crypto import decrypt_secret


def _ip_in_cidrs(client_ip: str, cidrs: list[str]) -> bool:
    """Return True if *client_ip* falls within any CIDR in *cidrs*."""
    if not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


def authenticate_trusted_proxy(
    request: Request,
    providers: list[AuthProvider],
    master_key: str,
) -> tuple[str, list[str], str] | None:
    """Verify trusted-proxy headers against enabled ``trusted_proxy`` providers.

    Returns ``(caller_id, groups, provider_id)`` when verified, or ``None`` if
    no trusted-proxy headers were supplied. Raises ``ValueError`` when headers
    are present but fail CIDR or secret validation.
    """
    proxy_user = request.headers.get("X-Anonix-User")
    proxy_secret = request.headers.get("X-Anonix-Proxy-Secret")
    proxy_groups_raw = request.headers.get("X-Anonix-Groups", "")

    if not proxy_user and not proxy_secret:
        return None

    enabled = [p for p in providers if p.provider_type == "trusted_proxy" and p.is_enabled]
    if not enabled:
        raise ValueError("Trusted-proxy authentication is not enabled.")

    client_host = request.client.host if request.client else ""
    for provider in enabled:
        if not _ip_in_cidrs(client_host, provider.trusted_cidrs):
            continue
        if not provider.encrypted_proxy_secret:
            continue
        expected_secret = decrypt_secret(provider.encrypted_proxy_secret, master_key)
        if proxy_secret and hmac.compare_digest(proxy_secret, expected_secret):
            caller_id = (proxy_user or "").strip()
            if not caller_id:
                raise ValueError("Missing X-Anonix-User header from trusted proxy.")
            groups = [g.strip() for g in proxy_groups_raw.split(",") if g.strip()]
            return caller_id, groups, provider.id

    raise ValueError("Trusted-proxy source IP or shared secret verification failed.")
