"""Tests for brig.ops.cache — TTL cache."""

import unittest

from brig.ops.cache import cached, clear, invalidate_cell_cache, set_cache


class TestCache(unittest.TestCase):
    """Test cache operations."""

    def setUp(self):
        clear()

    def tearDown(self):
        clear()

    def test_set_and_hit(self):
        set_cache("key1", "value1")
        hit, val = cached("key1")
        self.assertTrue(hit)
        self.assertEqual(val, "value1")

    def test_ttl_expiry(self):
        set_cache("key2", "value2")
        hit, _ = cached("key2", ttl=0.0)
        self.assertFalse(hit)

    def test_invalidate_cell_cache(self):
        set_cache("cell_exists:foo", True)
        set_cache("cell_running:foo", False)
        set_cache("other_key", "keep")

        invalidate_cell_cache("foo")

        hit_exists, _ = cached("cell_exists:foo")
        hit_running, _ = cached("cell_running:foo")
        hit_other, val = cached("other_key")

        self.assertFalse(hit_exists)
        self.assertFalse(hit_running)
        self.assertTrue(hit_other)
        self.assertEqual(val, "keep")
