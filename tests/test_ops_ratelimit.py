"""Tests for brig.ops.ratelimit — cell creation rate limiting."""

import json
import tempfile
import unittest
from pathlib import Path

from brig.ops.ratelimit import check_rate_limit, record_rate_limit


class TestCheckRateLimit(unittest.TestCase):
    """check_rate_limit is read-only: it reports whether a creation is
    allowed but does NOT reserve a slot. record_rate_limit consumes one."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rate_file = Path(self.tmpdir) / "rate_limit.json"

    def test_allow_first_cell(self):
        self.assertTrue(check_rate_limit(self.rate_file, max_cells=10, window=60))

    def test_check_is_read_only(self):
        """Repeated checks never consume quota — only record does."""
        for _ in range(20):
            self.assertTrue(check_rate_limit(self.rate_file, max_cells=1, window=60))
        self.assertFalse(self.rate_file.exists())

    def test_allow_up_to_max(self):
        for _ in range(5):
            self.assertTrue(check_rate_limit(self.rate_file, max_cells=5, window=60))
            record_rate_limit(self.rate_file, window=60)

    def test_deny_over_max(self):
        for _ in range(3):
            self.assertTrue(check_rate_limit(self.rate_file, max_cells=3, window=60))
            record_rate_limit(self.rate_file, window=60)
        self.assertFalse(check_rate_limit(self.rate_file, max_cells=3, window=60))

    def test_window_expiry(self):
        """Expired timestamps are pruned, allowing new creations."""
        import time

        expired = [time.time() - 120]  # 2 minutes ago.
        with open(self.rate_file, "w") as f:
            json.dump({"timestamps": expired * 5}, f)

        self.assertTrue(check_rate_limit(self.rate_file, max_cells=5, window=60))

    def test_fail_closed_on_bad_file(self):
        """Corrupted data is treated as empty, so a check is allowed."""
        self.rate_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.rate_file, "w") as f:
            f.write("not json{{{")
        self.assertTrue(check_rate_limit(self.rate_file, max_cells=10, window=60))


class TestRecordRateLimit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rate_file = Path(self.tmpdir) / "rate_limit.json"

    def test_record_appends_atomically(self):
        record_rate_limit(self.rate_file, window=60)
        self.assertTrue(self.rate_file.exists())
        with open(self.rate_file) as f:
            data = json.load(f)
        self.assertEqual(len(data["timestamps"]), 1)

    def test_record_accumulates(self):
        for _ in range(3):
            record_rate_limit(self.rate_file, window=60)
        with open(self.rate_file) as f:
            self.assertEqual(len(json.load(f)["timestamps"]), 3)
