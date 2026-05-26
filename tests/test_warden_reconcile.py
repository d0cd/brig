"""Tests for warden.reconcile — subnet state reconciliation.

Tests the state consistency invariant: warden's state must match allocator state.
"""

import json
import tempfile
import unittest
from pathlib import Path

from warden.reconcile import reconcile_subnet_state


class TestReconcileSubnetState(unittest.TestCase):
    """Test reconcile_subnet_state() cross-checks."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.subnets_file = Path(self.tmpdir) / "subnets.json"
        self.map_file = Path(self.tmpdir) / "subnet-map.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def _write_subnets(self, data):
        self.subnets_file.write_text(json.dumps(data))

    def _write_map(self, data):
        self.map_file.write_text(json.dumps(data))

    def test_fresh_install_consistent(self):
        """No files, no networks = consistent."""
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file, networks=[],
        )
        self.assertEqual(errors, [])

    def test_consistent_state(self):
        """All three sources agree."""
        self._write_subnets({
            "next_index": 3,
            "allocated": {
                "cell-a": {"index": 1, "allocated_at": "2026-01-01T00:00:00Z"},
                "cell-b": {"index": 2, "allocated_at": "2026-01-01T00:00:00Z"},
            },
            "freed": [],
        })
        self._write_map({
            "10.60.1.0/24": "cell-a",
            "10.60.2.0/24": "cell-b",
        })
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-cell-a", "brig-cell-b"],
        )
        self.assertEqual(errors, [])

    def test_missing_network(self):
        """Allocator has cell but network doesn't exist."""
        self._write_subnets({
            "next_index": 2,
            "allocated": {"cell-a": {"index": 1, "allocated_at": "2026-01-01T00:00:00Z"}},
            "freed": [],
        })
        self._write_map({"10.60.1.0/24": "cell-a"})
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file, networks=[],
        )
        self.assertTrue(any("brig-cell-a" in e and "does not exist" in e for e in errors))

    def test_orphaned_network(self):
        """Network exists but not in allocator."""
        self._write_subnets({"next_index": 1, "allocated": {}, "freed": []})
        self._write_map({})
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-orphan"],
        )
        self.assertTrue(any("brig-orphan" in e and "not in" in e for e in errors))

    def test_missing_map_entry(self):
        """Allocator has cell but map file missing its entry."""
        self._write_subnets({
            "next_index": 2,
            "allocated": {"cell-a": {"index": 1, "allocated_at": "2026-01-01T00:00:00Z"}},
            "freed": [],
        })
        self._write_map({})
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-cell-a"],
        )
        self.assertTrue(any("missing entry" in e for e in errors))

    def test_map_mismatch(self):
        """Map file has wrong cell for a subnet."""
        self._write_subnets({
            "next_index": 2,
            "allocated": {"cell-a": {"index": 1, "allocated_at": "2026-01-01T00:00:00Z"}},
            "freed": [],
        })
        self._write_map({"10.60.1.0/24": "wrong-cell"})
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-cell-a"],
        )
        self.assertTrue(any("mismatch" in e for e in errors))

    def test_stale_map_entry(self):
        """Map file has entry for a freed cell."""
        self._write_subnets({"next_index": 2, "allocated": {}, "freed": [1]})
        self._write_map({"10.60.1.0/24": "deleted-cell"})
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file, networks=[],
        )
        self.assertTrue(any("stale" in e for e in errors))

    def test_malformed_subnets_file(self):
        """Corrupted subnets.json."""
        self.subnets_file.write_text("not json{{{")
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file, networks=[],
        )
        self.assertTrue(any("malformed" in e for e in errors))

    def test_malformed_map_file(self):
        """Corrupted subnet-map.json."""
        self._write_subnets({"next_index": 1, "allocated": {}, "freed": []})
        self.map_file.write_text("not json")
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file, networks=[],
        )
        self.assertTrue(any("malformed" in e for e in errors))

    def test_subnets_missing_but_networks_exist(self):
        """subnets.json absent but networks exist = drift."""
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-ghost"],
        )
        self.assertTrue(any("drifted" in e for e in errors))

    def test_missing_map_file_with_allocations(self):
        """Map file absent but allocator has cells."""
        self._write_subnets({
            "next_index": 2,
            "allocated": {"cell-a": {"index": 1, "allocated_at": "2026-01-01T00:00:00Z"}},
            "freed": [],
        })
        errors = reconcile_subnet_state(
            self.subnets_file, self.map_file, self.lock_file,
            networks=["brig-cell-a"],
        )
        self.assertTrue(any("missing" in e for e in errors))
