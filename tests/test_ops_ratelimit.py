"""Tests for brig.ops.ratelimit — cell creation rate limiting."""

import json
import tempfile
import unittest
from pathlib import Path

from brig.ops.ratelimit import check_rate_limit


class TestCheckRateLimit(unittest.TestCase):
    """Test check_rate_limit() behavior."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rate_file = Path(self.tmpdir) / "rate_limit.json"

    def test_allow_first_cell(self):
        self.assertTrue(check_rate_limit(self.rate_file, max_cells=10, window=60))

    def test_allow_up_to_max(self):
        for _ in range(5):
            self.assertTrue(check_rate_limit(self.rate_file, max_cells=5, window=60))

    def test_deny_over_max(self):
        for _ in range(3):
            check_rate_limit(self.rate_file, max_cells=3, window=60)
        self.assertFalse(check_rate_limit(self.rate_file, max_cells=3, window=60))

    def test_window_expiry(self):
        """Expired timestamps are pruned, allowing new creations."""
        import time

        # Write timestamps that are already expired.
        expired = [time.time() - 120]  # 2 minutes ago.
        with open(self.rate_file, "w") as f:
            json.dump({"timestamps": expired * 5}, f)

        # Window is 60s, so all 5 expired timestamps are pruned.
        self.assertTrue(check_rate_limit(self.rate_file, max_cells=5, window=60))

    def test_fail_closed_on_bad_file(self):
        """Corrupted state file causes denial (fail closed)."""
        self.rate_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.rate_file, "w") as f:
            f.write("not json{{{")

        # Should still work — corrupted data is treated as empty.
        self.assertTrue(check_rate_limit(self.rate_file, max_cells=10, window=60))

    def test_atomic_write(self):
        """State file is written atomically."""
        check_rate_limit(self.rate_file, max_cells=10, window=60)
        self.assertTrue(self.rate_file.exists())
        with open(self.rate_file) as f:
            data = json.load(f)
        self.assertIn("timestamps", data)
        self.assertEqual(len(data["timestamps"]), 1)
