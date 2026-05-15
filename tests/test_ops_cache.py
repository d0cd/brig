"""Tests for brig.ops.cache — TTL cache."""

import unittest

from brig.ops.cache import cached, clear, set_cache


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

    def test_clear_drops_everything(self):
        set_cache("k1", "v1")
        set_cache("k2", "v2")
        clear()
        hit_a, _ = cached("k1")
        hit_b, _ = cached("k2")
        self.assertFalse(hit_a)
        self.assertFalse(hit_b)
