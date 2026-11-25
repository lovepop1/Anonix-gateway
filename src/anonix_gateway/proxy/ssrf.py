"""SSRF protection for upstream URL validation."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def _is_disallowed_ip(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool
) -> bool:
    """Return True if *ip_obj* is a metadata/link-local or disallowed private address."""
    # Always block cloud metadata / link-local / unspecified / multicast
    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True
    if not allow_private and (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved):
        return True
    return False


def validate_upstream_url(url: str, *, allow_private: bool = False) -> str:
    """Validate an upstream base URL against scheme and SSRF network rules.

    Raises:
        ValueError: If the scheme, host, or resolved IP is disallowed.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Upstream base_url must use http or https.")
    if not parsed.hostname:
        raise ValueError("Upstream base_url must include a valid hostname.")

    host = parsed.hostname.strip().lower()
    # Explicitly block common cloud metadata hostnames
    if host in {"metadata.google.internal", "169.254.169.254"}:
        raise ValueError(f"Upstream host '{host}' is blocked by SSRF policy.")

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if _is_disallowed_ip(ip_literal, allow_private):
            raise ValueError(
                f"Upstream IP '{ip_literal}' is blocked by SSRF policy "
                "(set ANONIX_ALLOW_PRIVATE_UPSTREAMS=true for internal VPC targets)."
            )
        return url.strip().rstrip("/")

    # Best-effort DNS resolution check when hostname is resolvable
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        # Allow unresolved internal service names when allow_private is enabled or in tests
        if not allow_private and host in {"localhost", "localhost.localdomain"}:
            raise ValueError("Loopback hostname is blocked by SSRF policy.") from None
        return url.strip().rstrip("/")

    for info in infos:
        addr_str = str(info[4][0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if _is_disallowed_ip(addr, allow_private):
            raise ValueError(
                f"Upstream '{host}' resolves to blocked IP '{addr}' "
                "(set ANONIX_ALLOW_PRIVATE_UPSTREAMS=true for internal VPC targets)."
            )

    return url.strip().rstrip("/")
