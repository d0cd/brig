"""Tests for the shared addon helper module (src/brig/warden_addons/_common.py)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Addons live outside brig.* and import each other by sibling name.
_addons_dir = str(Path(__file__).parent.parent / "src" / "brig" / "warden_addons")
if _addons_dir not in sys.path:
    sys.path.insert(0, _addons_dir)

from _common import (  # noqa: E402
    SubnetResolver,
    atomic_write_json,
    is_blocked_ip,
)


class TestBlockedNetworks(unittest.TestCase):
    """The single source of truth for SSRF blocklists."""

    def test_rfc1918_blocked(self):
        for ip in ("10.0.0.5", "172.16.0.1", "192.168.1.1"):
            self.assertTrue(is_blocked_ip(ip), f"{ip} should be blocked")

    def test_localhost_blocked(self):
        self.assertTrue(is_blocked_ip("127.0.0.1"))

    def test_link_local_blocked(self):
        self.assertTrue(is_blocked_ip("169.254.169.254"))

    def test_cgnat_blocked(self):
        self.assertTrue(is_blocked_ip("100.64.0.1"))

    def test_ipv4_mapped_ipv6_blocked(self):
        self.assertTrue(is_blocked_ip("::ffff:10.0.0.1"))

    def test_ipv6_link_local_blocked(self):
        self.assertTrue(is_blocked_ip("fe80::1"))

    def test_ipv6_tunnel_relay_prefixes_blocked(self):
        # Prefixes that can encapsulate/route to private space — one
        # representative address per CIDR so a mistyped or deleted entry
        # fails CI (the list claims to cover these; assert it does).
        for ip in (
            "64:ff9b::1",      # NAT64 well-known prefix
            "2002::1",         # 6to4
            "100::1",          # discard-only
            "2001:db8::1",     # documentation
        ):
            self.assertTrue(is_blocked_ip(ip), f"{ip} should be blocked")

    def test_ipv4_relay_and_protocol_assignment_blocked(self):
        for ip in (
            "192.88.99.1",     # 6to4 relay anycast
            "192.0.0.170",     # NAT64 well-known address
            "198.18.0.1",      # benchmarking
        ):
            self.assertTrue(is_blocked_ip(ip), f"{ip} should be blocked")

    def test_remaining_reserved_ranges_blocked(self):
        # The remaining BLOCKED_NETWORKS classes that the other tests don't
        # cover. Together with the cases above, EVERY CIDR in the list has at
        # least one representative address asserted here — so deleting any
        # single entry makes one of these assertions fail (backs the
        # INVARIANTS "deleted/mistyped CIDR fails CI" claim).
        for ip in (
            "::1",             # ::1/128 loopback
            "::",              # ::/128 unspecified (v6 analog of 0.0.0.0)
            "fc00::1",         # fc00::/7 ULA
            "ff00::1",         # ff00::/8 multicast
            "240.0.0.1",       # 240.0.0.0/4 reserved
            "0.0.0.1",         # 0.0.0.0/8 this-network
            "224.0.0.1",       # 224.0.0.0/4 multicast
        ):
            self.assertTrue(is_blocked_ip(ip), f"{ip} should be blocked")

    def test_every_blocked_network_has_a_representative_in_tests(self):
        # Guard against the list drifting ahead of the per-class assertions
        # above: every CIDR must contain at least one of the IPs the tests in
        # this class assert blocked. If someone ADDS a CIDR without a test IP,
        # this fails — keeping the "covers every entry" claim honest.
        import ipaddress
        from _common import BLOCKED_NETWORKS
        tested = [
            "10.0.0.5", "172.16.0.1", "192.168.1.1", "127.0.0.1",
            "169.254.169.254", "100.64.0.1", "198.18.0.1", "240.0.0.1",
            "0.0.0.1", "224.0.0.1", "192.88.99.1", "192.0.0.170",
            "::1", "::", "fc00::1", "fe80::1", "ff00::1", "2001:db8::1",
            "64:ff9b::1", "100::1", "2002::1", "::ffff:10.0.0.1",
        ]
        tested_addrs = [ipaddress.ip_address(t) for t in tested]
        for net in BLOCKED_NETWORKS:
            self.assertTrue(
                any(a in net for a in tested_addrs),
                f"BLOCKED_NETWORKS entry {net} has no representative test IP",
            )

    def test_public_ip_not_blocked(self):
        for ip in ("1.1.1.1", "8.8.8.8", "93.184.216.34"):
            self.assertFalse(is_blocked_ip(ip), f"{ip} should not be blocked")

    def test_invalid_returns_false(self):
        self.assertFalse(is_blocked_ip("not an ip"))

    def test_alternate_encodings_of_loopback_blocked(self):
        # ipaddress.ip_address rejects non-canonical IPv4, but these all
        # resolve to 127.0.0.1 at connect time and must be blocked.
        for ip in ("2130706433", "0x7f000001", "0177.0.0.1", "127.1"):
            self.assertTrue(is_blocked_ip(ip), f"{ip} (==127.0.0.1) should be blocked")

    def test_alternate_encodings_of_rfc1918_blocked(self):
        # 167772161 == 10.0.0.1; 0xa000001 == 10.0.0.1.
        for ip in ("167772161", "0xa000001"):
            self.assertTrue(is_blocked_ip(ip), f"{ip} (==10.0.0.1) should be blocked")

    def test_alternate_encoding_of_public_not_blocked(self):
        # 134744072 == 8.8.8.8 — a public address must still pass.
        self.assertFalse(is_blocked_ip("134744072"))


class TestSubnetResolver(unittest.TestCase):
    """SubnetResolver replaces three duplicated copies of this logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.map_file = Path(self.tmpdir) / "subnet-map.json"

    def _write_map(self, mapping: dict):
        atomic_write_json(self.map_file, mapping)

    def test_reload_loads_mapping(self):
        self._write_map({"10.60.1.0/24": "alpha", "10.60.2.0/24": "beta"})
        r = SubnetResolver(self.map_file)
        self.assertTrue(r.reload())
        self.assertEqual(r.subnet_map["10.60.1.0/24"], "alpha")

    def test_reload_skips_when_unchanged(self):
        self._write_map({"10.60.1.0/24": "alpha"})
        r = SubnetResolver(self.map_file)
        self.assertTrue(r.reload())
        # Second reload without file change returns False.
        self.assertFalse(r.reload())

    def test_get_cell_name_fast_path(self):
        self._write_map({"10.60.1.0/24": "alpha"})
        r = SubnetResolver(self.map_file)
        r.reload()
        self.assertEqual(r.get_cell_name("10.60.1.42"), "alpha")

    def test_get_cell_name_unknown_subnet(self):
        self._write_map({"10.60.1.0/24": "alpha"})
        r = SubnetResolver(self.map_file)
        r.reload()
        self.assertIsNone(r.get_cell_name("10.60.99.5"))

    def test_get_cell_name_invalid_ip(self):
        self._write_map({"10.60.1.0/24": "alpha"})
        r = SubnetResolver(self.map_file)
        r.reload()
        self.assertIsNone(r.get_cell_name("not an ip"))

    def test_missing_file_returns_false(self):
        r = SubnetResolver(self.map_file)
        self.assertFalse(r.reload())  # File doesn't exist.

    def test_malformed_file_returns_false(self):
        self.map_file.write_text("{not json")
        r = SubnetResolver(self.map_file)
        self.assertFalse(r.reload())

    def test_reload_detects_same_mtime_different_content(self):
        """A same-second rewrite (identical mtime, changed size) must reload.

        Coarse-mtime filesystems (HFS+, some CI tmpfs) can give two writes
        the same float mtime; a reused subnet index would then keep the old
        cell's mapping and apply the wrong per-cell policy.
        """
        import os

        self._write_map({"10.60.7.0/24": "alpha"})
        r = SubnetResolver(self.map_file)
        self.assertTrue(r.reload())
        self.assertEqual(r.get_cell_name("10.60.7.2"), "alpha")

        st = self.map_file.stat()
        # Rewrite with different (longer) content, then pin mtime back to the
        # original so a float-mtime comparison would consider it unchanged.
        self._write_map({"10.60.7.0/24": "bravo-longer-name"})
        os.utime(self.map_file, ns=(st.st_mtime_ns, st.st_mtime_ns))

        self.assertTrue(r.reload(), "reload must detect the content change")
        self.assertEqual(r.get_cell_name("10.60.7.2"), "bravo-longer-name")


class TestAtomicWriteJson(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.target = Path(self.tmpdir) / "out.json"

    def test_writes_data(self):
        atomic_write_json(self.target, {"k": "v"})
        self.assertEqual(json.loads(self.target.read_text()), {"k": "v"})

    def test_creates_parent_dirs(self):
        nested = Path(self.tmpdir) / "a" / "b" / "c.json"
        atomic_write_json(nested, [1, 2, 3])
        self.assertEqual(json.loads(nested.read_text()), [1, 2, 3])

    def test_no_partial_writes_on_failure(self):
        """If json serialization fails, the original file is untouched."""
        atomic_write_json(self.target, {"original": True})
        with self.assertRaises(TypeError):
            # set() is not JSON-serializable.
            atomic_write_json(self.target, {"bad": {1, 2, 3}})
        # Original content survives.
        self.assertEqual(json.loads(self.target.read_text()), {"original": True})


if __name__ == "__main__":
    unittest.main()
