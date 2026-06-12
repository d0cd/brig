"""Tests for brig.network.subnet — embedded subnet allocator.

Includes concurrent race condition tests (invariant: no duplicate allocations).
"""

import json
import tempfile
import threading
import unittest
from pathlib import Path

from brig.network.subnet import (
    SubnetInfo,
    allocate,
    free,
    get,
    index_to_subnet,
    list_all,
    validate_index,
)


class TestSubnetHelpers(unittest.TestCase):
    def test_index_to_subnet(self):
        self.assertEqual(index_to_subnet(1), "10.60.1.0/24")
        self.assertEqual(index_to_subnet(254), "10.60.254.0/24")

    def test_validate_index_boundaries(self):
        self.assertTrue(validate_index(1))
        self.assertTrue(validate_index(254))
        self.assertFalse(validate_index(0))
        self.assertFalse(validate_index(255))
        self.assertFalse(validate_index(-1))


class TestAllocateAndFree(unittest.TestCase):
    """Test basic allocate/free lifecycle."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_allocate_first_cell(self):
        info = allocate("test-cell", self.state_file, self.lock_file)
        self.assertEqual(info.cell_name, "test-cell")
        self.assertEqual(info.index, 1)
        self.assertEqual(info.subnet, "10.60.1.0/24")

    def test_allocate_sequential(self):
        info1 = allocate("cell-a", self.state_file, self.lock_file)
        info2 = allocate("cell-b", self.state_file, self.lock_file)
        self.assertEqual(info1.index, 1)
        self.assertEqual(info2.index, 2)

    def test_allocate_duplicate_is_idempotent(self):
        # Re-allocating a same-named cell returns its existing subnet instead
        # of raising — lets `brig run` reclaim an orphan after a VM restart.
        first = allocate("cell-a", self.state_file, self.lock_file)
        second = allocate("cell-a", self.state_file, self.lock_file)
        self.assertEqual(first.index, second.index)
        self.assertEqual(first.subnet, second.subnet)
        self.assertEqual(first.allocated_at, second.allocated_at)
        # No second index was consumed.
        info_b = allocate("cell-b", self.state_file, self.lock_file)
        self.assertEqual(info_b.index, 2)

    def test_allocate_invalid_name_raises(self):
        with self.assertRaises(ValueError, msg="Invalid cell name"):
            allocate("INVALID!", self.state_file, self.lock_file)

    def test_free_basic(self):
        allocate("cell-a", self.state_file, self.lock_file)
        free("cell-a", self.state_file, self.lock_file)
        result = get("cell-a", self.state_file, self.lock_file)
        self.assertIsNone(result)

    def test_free_not_allocated_raises(self):
        with self.assertRaises(ValueError, msg="has no subnet"):
            free("cell-a", self.state_file, self.lock_file)

    def test_freed_index_reuse(self):
        allocate("cell-a", self.state_file, self.lock_file)
        allocate("cell-b", self.state_file, self.lock_file)
        free("cell-a", self.state_file, self.lock_file)

        # Next allocation should reuse index 1.
        info3 = allocate("cell-c", self.state_file, self.lock_file)
        self.assertEqual(info3.index, 1)

    def test_get_existing(self):
        allocate("cell-a", self.state_file, self.lock_file)
        info = get("cell-a", self.state_file, self.lock_file)
        self.assertIsNotNone(info)
        self.assertEqual(info.cell_name, "cell-a")
        self.assertEqual(info.index, 1)

    def test_get_nonexistent(self):
        self.assertIsNone(get("nope", self.state_file, self.lock_file))

    def test_list_all(self):
        allocate("cell-b", self.state_file, self.lock_file)
        allocate("cell-a", self.state_file, self.lock_file)
        result = list_all(self.state_file, self.lock_file)
        self.assertEqual(len(result), 2)
        # Sorted by index.
        self.assertEqual(result[0].cell_name, "cell-b")
        self.assertEqual(result[1].cell_name, "cell-a")

    def test_list_all_empty(self):
        self.assertEqual(list_all(self.state_file, self.lock_file), [])


class TestSubnetMap(unittest.TestCase):
    """Test that allocate()/free() keep subnet-map.json in sync on disk."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_allocate_writes_map_alongside_state(self):
        """Regression: allocate() with a custom state_file must write
        subnet-map.json next to it, not to the global SUBNET_MAP_FILE.
        Before the fix, pytest clobbered the user's real subnet-map.json
        because _write_subnet_map silently defaulted to it."""
        allocate("cell-a", self.state_file, self.lock_file)
        local_map = self.state_file.parent / "subnet-map.json"
        self.assertTrue(local_map.exists(), "subnet-map.json not written to tmpdir")
        self.assertEqual(
            json.loads(local_map.read_text()),
            {"10.60.1.0/24": "cell-a"},
        )

    def test_free_updates_map_alongside_state(self):
        """Regression: free() must update subnet-map.json next to state_file."""
        allocate("cell-a", self.state_file, self.lock_file)
        free("cell-a", self.state_file, self.lock_file)
        local_map = self.state_file.parent / "subnet-map.json"
        self.assertEqual(json.loads(local_map.read_text()), {})


class TestMaxCapacity(unittest.TestCase):
    """Test allocation at capacity limits."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_allocate_254_cells(self):
        for i in range(1, 255):
            allocate(f"cell-{i}", self.state_file, self.lock_file)
        # 255th should fail.
        with self.assertRaises(ValueError, msg="No more subnets"):
            allocate("cell-255", self.state_file, self.lock_file)

    def test_allocate_after_free_at_capacity(self):
        for i in range(1, 255):
            allocate(f"cell-{i}", self.state_file, self.lock_file)
        free("cell-100", self.state_file, self.lock_file)
        info = allocate("cell-new", self.state_file, self.lock_file)
        self.assertEqual(info.index, 100)


class TestTamperedState(unittest.TestCase):
    """subnets.json is untrusted (invariant 4): a crafted state file must not
    cause two cells to share a /24 (invariants 1, 8)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def _write(self, state: dict) -> None:
        self.state_file.write_text(json.dumps(state))

    def test_freed_index_colliding_with_allocated_not_reused(self):
        # Index 1 is allocated to cell-a but also sits in freed. Allocating a
        # new cell must NOT hand out index 1 again.
        self._write({
            "next_index": 2,
            "allocated": {"cell-a": {"index": 1, "allocated_at": "x"}},
            "freed": [1],
        })
        info = allocate("cell-b", self.state_file, self.lock_file)
        self.assertNotEqual(info.index, 1)

    def test_duplicate_freed_index_handed_out_once(self):
        # freed has [1, 1]; two allocations must get distinct indices.
        self._write({"next_index": 5, "allocated": {}, "freed": [1, 1]})
        a = allocate("cell-a", self.state_file, self.lock_file)
        b = allocate("cell-b", self.state_file, self.lock_file)
        self.assertNotEqual(a.index, b.index)

    def test_next_index_below_allocated_does_not_collide(self):
        # next_index points at an already-allocated index; the next allocation
        # must skip past it.
        self._write({
            "next_index": 3,
            "allocated": {"cell-a": {"index": 3, "allocated_at": "x"}},
            "freed": [],
        })
        info = allocate("cell-b", self.state_file, self.lock_file)
        self.assertNotEqual(info.index, 3)


class TestConcurrentAllocation(unittest.TestCase):
    """Test thread safety — no duplicate allocations under contention."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_concurrent_allocate_no_duplicates(self):
        """50 threads allocating simultaneously must produce unique indices."""
        results: list[SubnetInfo] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            try:
                info = allocate(f"cell-{i}", self.state_file, self.lock_file)
                with lock:
                    results.append(info)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        self.assertEqual(len(results), 50)

        # All indices must be unique.
        indices = [r.index for r in results]
        self.assertEqual(len(set(indices)), 50)

        # All subnets must be unique.
        subnets = [r.subnet for r in results]
        self.assertEqual(len(set(subnets)), 50)


class TestCorruptedState(unittest.TestCase):
    """Test resilience to corrupted state files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_corrupted_json(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text("not json{{{")
        # Should treat as empty and allocate normally.
        info = allocate("cell-a", self.state_file, self.lock_file)
        self.assertEqual(info.index, 1)

    def test_empty_file(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text("")
        info = allocate("cell-a", self.state_file, self.lock_file)
        self.assertEqual(info.index, 1)

    def test_wrong_type(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text('"a string"')
        info = allocate("cell-a", self.state_file, self.lock_file)
        self.assertEqual(info.index, 1)
