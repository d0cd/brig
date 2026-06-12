"""
Domain and IP validation for network policies.

Checks for suspicious domains (DNS rebinding risk) and overly permissive
patterns (broad TLD wildcards).
"""

from __future__ import annotations

import ipaddress
import socket

from brig.config import SUSPICIOUS_DOMAIN_PATTERNS


def _is_ip_literal(host: str) -> bool:
    """True if host denotes an IP address in any encoding (canonical or not).

    Egress targets must be domain names; literal IPs are blocked at the proxy.
    Catches the alternate IPv4 encodings (integer/hex/octal/short-dotted) that
    a plain ipaddress parse misses, so they can't slip into an allow or
    tls_passthrough list and reach an internal address.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        socket.inet_aton(host)
        return True
    except (OSError, UnicodeError):
        return False


def is_suspicious_domain(domain: str) -> str:
    """Check if domain pattern is suspicious for DNS rebinding.

    Returns reason string if suspicious, empty string if safe.
    """
    domain_lower = domain.lower()

    base = domain_lower[2:] if domain_lower.startswith("*.") else domain_lower
    if _is_ip_literal(base):
        return f"'{domain}' is an IP literal; egress targets must be domain names"

    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if domain_lower == pattern:
            return f"'{domain}' is too broad and could allow DNS rebinding"

    # Wildcard on bare TLD (e.g. "*.com") with only one dot means no subdomain.
    if domain_lower.startswith("*.") and domain_lower.count(".") == 1:
        return f"'{domain}' wildcard on TLD is too broad"

    # Pure wildcard.
    if domain_lower == "*":
        return "Wildcard '*' matches everything"

    return ""
