"""Tests for the shared addon helper module (src/addons/_common.py)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Addons live outside brig.* and import each other by sibling name.
_addons_dir = str(Path(__file__).parent.parent / "src" / "addons")
if _addons_dir not in sys.path:
    sys.path.insert(0, _addons_dir)

from _common import (  # noqa: E402
    BLOCKED_NETWORKS,
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

    def test_public_ip_not_blocked(self):
        for ip in ("1.1.1.1", "8.8.8.8", "93.184.216.34"):
            self.assertFalse(is_blocked_ip(ip), f"{ip} should not be blocked")

    def test_invalid_returns_false(self):
        self.assertFalse(is_blocked_ip("not an ip"))


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
