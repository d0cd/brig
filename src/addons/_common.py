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

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Optional


# Networks that an egress request must never resolve to. Mirrors the blocklist
# in src/brig/network/validation.py for the host-side validators.
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
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # IPv4-mapped IPv6 (covers all IPv4 ranges above when expressed as ::ffff:a.b.c.d).
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("ff00::/8"),
]


def is_blocked_ip(ip_str: str) -> bool:
    """Return True if ip_str parses to an IP inside BLOCKED_NETWORKS.

    Returns False (not blocked) on parse error so callers can apply their own
    fail-closed policy at the call site.
    """
    try:
        addr = ip_str[1:-1] if ip_str.startswith("[") and ip_str.endswith("]") else ip_str
        ip = ipaddress.ip_address(addr)
    except ValueError:
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
        self._mtime = 0.0

    def reload(self) -> bool:
        """Reload the subnet map if the file has changed. Returns True if reloaded."""
        try:
            if not self.subnet_map_file.exists():
                return False
            mtime = self.subnet_map_file.stat().st_mtime
            if mtime == self._mtime:
                return False
            with open(self.subnet_map_file, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return False
            self.subnet_map = data
            self._mtime = mtime
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
