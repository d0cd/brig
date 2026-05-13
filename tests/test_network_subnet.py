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
    get_subnet_map,
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

    def test_allocate_duplicate_raises(self):
        allocate("cell-a", self.state_file, self.lock_file)
        with self.assertRaises(ValueError, msg="already has subnet"):
            allocate("cell-a", self.state_file, self.lock_file)

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
    """Test get_subnet_map() for enforce.py consumption."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"

    def test_map_basic(self):
        allocate("cell-a", self.state_file, self.lock_file)
        allocate("cell-b", self.state_file, self.lock_file)
        mapping = get_subnet_map(self.state_file, self.lock_file)
        self.assertEqual(mapping["10.60.1.0/24"], "cell-a")
        self.assertEqual(mapping["10.60.2.0/24"], "cell-b")

    def test_map_empty(self):
        self.assertEqual(get_subnet_map(self.state_file, self.lock_file), {})

    def test_map_after_free(self):
        allocate("cell-a", self.state_file, self.lock_file)
        free("cell-a", self.state_file, self.lock_file)
        self.assertEqual(get_subnet_map(self.state_file, self.lock_file), {})


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
