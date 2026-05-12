"""
Domain and IP validation for network policies.

Checks for suspicious domains (DNS rebinding risk) and overly permissive
patterns (broad TLD wildcards).
"""

from __future__ import annotations

from brig.config import SUSPICIOUS_DOMAIN_PATTERNS

# Overly permissive TLD patterns that effectively allow most of the internet.
OVERLY_PERMISSIVE_PATTERNS = [
    "*.com", "*.net", "*.org", "*.io", "*.co", "*.dev", "*.app",
    "*.me", "*.us", "*.uk", "*.de", "*.cn", "*.ru", "*.xyz",
    "*.info", "*.biz",
]


def is_suspicious_domain(domain: str) -> str:
    """Check if domain pattern is suspicious for DNS rebinding.

    Returns reason string if suspicious, empty string if safe.
    """
    domain_lower = domain.lower()

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


def is_overly_permissive_domain(domain: str) -> str:
    """Check if domain pattern is overly permissive.

    Returns warning string if permissive, empty string if fine.
    Unlike suspicious patterns, these are allowed but generate warnings.
    """
    domain_lower = domain.lower()

    for pattern in OVERLY_PERMISSIVE_PATTERNS:
        if domain_lower == pattern:
            tld = pattern[2:]
            return f"'{domain}' matches all .{tld} domains - consider using more specific patterns"

    # Wildcard directly under short TLD.
    if domain_lower.startswith("*.") and domain_lower.count(".") == 1:
        tld = domain_lower[2:]
        if len(tld) <= 4:
            return f"'{domain}' wildcard on .{tld} TLD allows many domains"

    return ""
