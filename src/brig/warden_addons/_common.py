"""
Shared helpers for warden addons.

Mounted alongside enforce.py / logger.py / notifier.py inside the warden
container. Addons import via `from _common import ...`.

Contents:
  - BLOCKED_NETWORKS: SSRF blocklist (RFC1918, localhost, CGNAT, link-local,
    benchmarking, multicast, IPv4-mapped-IPv6, etc.). Single source of truth.
  - SubnetResolver: subnet-map.json loader + cached IP -> cell resolver.
  - atomic_write_json: tempfile + fsync + rename helper.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import math
import os
import re
import socket
import tempfile
from pathlib import Path
from typing import Optional


# Networks that an egress request must never resolve to. This is the single
# source of truth for the SSRF blocklist — the host side imports nothing
# equivalent (brig/network/validation.py only does domain-suspicion checks),
# and the constant-mirror test asserts the addons don't diverge from it.
BLOCKED_NETWORKS = [
    # IPv4 private + reserved.
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    # IPv4 counterparts to the IPv6 tunnel/relay prefixes below, for symmetry:
    #   - 192.88.99.0/24  RFC3068 6to4 relay anycast
    #   - 192.0.0.0/24    RFC6890 IETF protocol assignments (incl. 192.0.0.170
    #                     NAT64 well-known address and the DS-Lite range)
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.0.0.0/24"),
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    # Unspecified address — the IPv6 analog of 0.0.0.0; connect() to it routes
    # to loopback on Linux, so it must be blocked like its v4 counterpart.
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # IPv4-mapped IPv6 (covers all IPv4 ranges above when expressed as ::ffff:a.b.c.d).
    ipaddress.ip_network("::ffff:0:0/96"),
    # IPv4-compatible IPv6 (deprecated RFC4291 ::a.b.c.d form) — the asymmetric
    # twin of the mapped range above; without it ::127.0.0.1 / ::169.254.169.254
    # would slip past the literal-IP block.
    ipaddress.ip_network("::/96"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("ff00::/8"),
    # Additional IPv6 ranges that can encapsulate or route to private
    # address space and let an attacker tunnel around the basic RFC1918
    # blocklist.
    #   - 64:ff9b::/96  RFC6052 well-known NAT64 prefix (can map to v4)
    #   - 100::/64      RFC6666 discard-only address block
    #   - 2002::/16     RFC3056 6to4, can encapsulate RFC1918 v4
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2002::/16"),
]


def stat_signature(path: Path) -> tuple[int, int]:
    """Return (st_mtime_ns, st_size) — a change fingerprint resilient to
    coarse filesystem mtime resolution. Same-second rewrites can collide on
    float-precision mtime but rarely on size, so the tuple catches edits a
    `!=` on st_mtime would silently drop. Raises OSError if the path is gone.
    """
    st = path.stat()
    return (st.st_mtime_ns, st.st_size)


# ---------------------------------------------------------------------------
# Path redaction / templating — the SINGLE source for every sink (logger,
# notifier, otel). Splitting these per-sink let secret-hygiene drift: a
# credential masked in one channel leaked verbatim in another. One classifier,
# composed two ways: mask secrets in logs; collapse ids+secrets in templates.
# ---------------------------------------------------------------------------

# High-cardinality path segments. Numeric/uuid are IDs (high-cardinality but not
# secret — kept in logs for audit, collapsed in templates). The rest are
# secret-shaped (masked in logs AND collapsed in templates).
_UUID_SEG = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_NUM_SEG = re.compile(r"\A[0-9]+\Z")
_HEX_SEG = re.compile(r"\A[0-9a-fA-F]{8,}\Z")
_TOKEN_SEG = re.compile(r"\A[A-Za-z0-9_\-]{20,}\Z")          # base64url/JWT-ish.
# Colon-joined credential, e.g. an `<id>:<secret>`-shaped API token in the path —
# the colon breaks _TOKEN_SEG, so without this it leaks verbatim.
_COLON_TOKEN = re.compile(r"\A[A-Za-z0-9._\-]+:[A-Za-z0-9._\-]{8,}\Z")

# Entropy fallback (detect-secrets-style recall net for unenumerated formats —
# short base64 w/ +/=, etc.). Length floor avoids masking short meaningful
# slugs; ~4 bits/char keeps English/structured names while catching random
# tokens. Tuned against brig's real flow logs.
_ENTROPY_MIN_LEN = 16
_ENTROPY_MIN_BITS = 4.0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n)
                for c in collections.Counter(s).values())


def _high_entropy_segment(seg: str) -> bool:
    return len(seg) >= _ENTROPY_MIN_LEN and _shannon_entropy(seg) >= _ENTROPY_MIN_BITS


def is_secret_segment(seg: str) -> bool:
    """A path segment that looks like a credential/secret (long hex, base64-ish
    token, colon-joined token, or high-entropy). Masked in logs, collapsed in
    templates. Excludes plain numeric/uuid ids — those are audit-useful."""
    return bool(_HEX_SEG.match(seg) or _TOKEN_SEG.match(seg)
                or _COLON_TOKEN.match(seg)) or _high_entropy_segment(seg)


def is_id_segment(seg: str) -> bool:
    """A high-cardinality but non-secret id (numeric / uuid)."""
    return bool(_NUM_SEG.match(seg) or _UUID_SEG.match(seg))


# Sensitive query-param names whose VALUE must be scrubbed from logged paths.
_SECRET_PARAM_RE = re.compile(
    r'([?&])'
    r'(key|api_key|apikey|token|access_token|refresh_token|id_token|secret|password|'
    r'auth|authorization|client_secret|private_key|signing_key|bearer|session|sig|'
    r'signature|code|sas)'
    r'=([^&]*)',
    re.IGNORECASE,
)

# Any query param (regardless of name) whose VALUE classifies as a secret
# segment (token-shaped / high-entropy) is scrubbed too, so a credential under
# an unenumerated parameter name doesn't leak.
_ANY_PARAM_RE = re.compile(r'([?&])([^=&]+)=([^&]*)')


def _scrub_secret_value(match: "re.Match[str]") -> str:
    sep, name, value = match.group(1), match.group(2), match.group(3)
    if is_secret_segment(value):
        return f"{sep}{name}=REDACTED"
    return match.group(0)


def redact_query_secrets(path: str) -> str:
    """Scrub sensitive query-param values. URL-decodes in a loop (max 5) so a
    double-encoded `%2561pi%255Fkey=secret` can't slip past. Redacts values for
    known-sensitive param names AND any value that classifies as a secret
    segment, so a credential under an unlisted name is still masked."""
    from urllib.parse import unquote
    decoded = path
    for _ in range(5):
        prev = decoded
        decoded = unquote(decoded)
        if decoded == prev:
            break
    named = _SECRET_PARAM_RE.sub(r'\1\2=REDACTED', decoded)
    return _ANY_PARAM_RE.sub(_scrub_secret_value, named)


def redact_path(path: str) -> str:
    """Log-safe path: scrub sensitive query-param values AND mask secret path
    segments (keeping non-secret ids + endpoint structure for audit). The one
    redactor every sink uses, so a secret can't be masked in one log and leak
    in another."""
    scrubbed = redact_query_secrets(path)
    base, sep, query = scrubbed.partition("?")
    base = "/".join("[REDACTED]" if seg and is_secret_segment(seg) else seg
                    for seg in base.split("/"))
    return base + sep + query


def collapse_path_template(path: str) -> str:
    """Stable template for novelty keys: drop query/fragment, collapse every
    high-cardinality segment (id OR secret) to {id}."""
    base = path.split("?", 1)[0].split("#", 1)[0]
    return "/".join("{id}" if seg and (is_id_segment(seg) or is_secret_segment(seg))
                    else seg for seg in base.split("/"))


def canonical_ip(host: str) -> Optional["ipaddress.IPv4Address | ipaddress.IPv6Address"]:
    """Return the IP a host string denotes as a literal, or None for a domain.

    Recognizes canonical IPv4/IPv6 plus the non-canonical IPv4 forms the libc
    resolver still accepts but ipaddress.ip_address rejects: integer
    ("2130706433"), hex ("0x7f000001"), octal ("0177.0.0.1"), and short-dotted
    ("127.1") — all of which mean 127.0.0.1. Without this, such forms slip past
    the IP blocklist and are treated as domain names. Domain names return None.
    """
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # IPv4 alternate encodings (integer/hex/octal/short-dotted) that the libc
    # resolver expands but ipaddress rejects. inet_aton raises on real domains.
    try:
        packed = socket.inet_aton(h)
    except (OSError, UnicodeError):
        return None
    return ipaddress.IPv4Address(packed)


def is_blocked_ip(ip_str: str) -> bool:
    """Return True if ip_str denotes an IP inside BLOCKED_NETWORKS.

    Returns False (not blocked) for domain names / unparseable input so callers
    can apply their own fail-closed policy at the call site.
    """
    ip = canonical_ip(ip_str)
    if ip is None:
        return False
    return any(ip in net for net in BLOCKED_NETWORKS)


class SubnetResolver:
    """Loads subnet-map.json and resolves client IPs to cell names.

    Single instance per addon. Caches mtime so repeated calls without file
    changes are cheap. Builds an O(1) index keyed by the top 24 bits of the
    network address for /24 IPv4 subnets (the common case); falls back to a
    linear scan for non-/24 or IPv6 entries.
    """

    def __init__(self, subnet_map_file: Path):
        self.subnet_map_file = subnet_map_file
        self.subnet_map: dict[str, str] = {}
        self._index: dict[int, str] = {}
        # (st_mtime_ns, st_size) rather than a float mtime: coarse-resolution
        # filesystems (HFS+, some CI tmpfs) can give two same-second writes an
        # identical float mtime, which would hide a subnet-map rewrite and keep
        # a reused index pointing at the previous cell.
        self._sig: tuple[int, int] = (0, 0)

    def reload(self) -> bool:
        """Reload the subnet map if the file has changed. Returns True if reloaded."""
        try:
            if not self.subnet_map_file.exists():
                return False
            st = self.subnet_map_file.stat()
            sig = (st.st_mtime_ns, st.st_size)
            if sig == self._sig:
                return False
            with open(self.subnet_map_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return False
            self.subnet_map = data
            self._sig = sig
            self._build_index()
            return True
        except (json.JSONDecodeError, IOError, OSError):
            return False

    def _build_index(self) -> None:
        """Build O(1) lookup index for /24 IPv4 subnets keyed by top 24 bits."""
        index: dict[int, str] = {}
        for subnet_str, cell_name in self.subnet_map.items():
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.prefixlen == 24:
                prefix = int(net.network_address) >> 8
                index[prefix] = cell_name
        self._index = index

    def get_cell_name(self, client_ip: str) -> Optional[str]:
        """Resolve a client IP to its cell name. Returns None if unknown."""
        try:
            ip = ipaddress.ip_address(client_ip)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv4Address) and self._index:
            cell = self._index.get(int(ip) >> 8)
            if cell is not None:
                return cell
        for subnet_str, cell_name in self.subnet_map.items():
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
            except ValueError:
                continue
            if ip in net:
                return cell_name
        return None


def atomic_write_json(path: Path, data, indent: Optional[int] = 2) -> None:
    """Write JSON atomically: tempfile in same dir + fsync + rename.

    POSIX rename is atomic for paths in the same filesystem, so readers either
    see the old file or the new one — never a half-written file. The fsync
    before rename guarantees the new bytes hit disk before the directory entry
    flips.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
