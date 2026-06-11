"""mutate_cell_policy: atomic read-modify-write under one exclusive lock.

The bug it closes: load_cell_policy and save_cell_policy each take and release
their own lock, so a caller doing load -> mutate -> save outside an enclosing
lock has a non-atomic RMW. Two concurrent writers both read the same baseline
and last-write-wins, silently dropping one update (e.g. a just-added deny).
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.policy.policy import mutate_cell_policy


class TestMutateCellPolicy(unittest.TestCase):

    def test_writes_and_returns_new_policy(self):
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            out = mutate_cell_policy(
                "c", lambda cur: {"allow": ["a.com"]}, policy_dir=pd,
            )
            self.assertEqual(out, {"allow": ["a.com"]})
            self.assertEqual(
                json.loads((pd / "c.json").read_text()), {"allow": ["a.com"]},
            )

    def test_none_result_skips_write(self):
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            # No prior file + mutator returns None -> nothing persisted.
            out = mutate_cell_policy("c", lambda cur: None, policy_dir=pd)
            self.assertIsNone(out)
            self.assertFalse((pd / "c.json").exists())

    def test_none_result_on_existing_file_does_not_rewrite(self):
        # Steady state (no-op mutate on an existing policy) must NOT rewrite —
        # rewriting identical content would churn mtime and trigger a needless
        # warden reload on every idempotent `brig run`. Assert the write helper
        # is not called and the current policy is returned unchanged.
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            mutate_cell_policy("c", lambda cur: {"allow": ["a"]}, policy_dir=pd)
            with patch("brig.policy.policy.atomic_write_json") as writer:
                out = mutate_cell_policy("c", lambda cur: None, policy_dir=pd)
            writer.assert_not_called()
            self.assertEqual(out, {"allow": ["a"]})

    def test_mutator_sees_current_policy(self):
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            mutate_cell_policy("c", lambda cur: {"allow": ["one"]}, policy_dir=pd)
            seen: dict = {}

            def _m(cur):
                seen["cur"] = cur
                return {"allow": cur["allow"] + ["two"]}

            out = mutate_cell_policy("c", _m, policy_dir=pd)
            self.assertEqual(seen["cur"], {"allow": ["one"]})
            self.assertEqual(out, {"allow": ["one", "two"]})

    def test_concurrent_appends_do_not_lose_updates(self):
        """N threads each append one entry under the lock. A non-atomic RMW
        would last-write-wins and lose entries; the exclusive lock held across
        load+store must land all N."""
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            mutate_cell_policy("c", lambda cur: {"allow": []}, policy_dir=pd)
            n = 20
            barrier = threading.Barrier(n)

            def _append(i):
                barrier.wait()  # maximize contention

                def _m(cur):
                    return {"allow": cur["allow"] + [f"host{i}.com"]}

                mutate_cell_policy("c", _m, policy_dir=pd)

            threads = [threading.Thread(target=_append, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            final = json.loads((pd / "c.json").read_text())
            self.assertEqual(len(final["allow"]), n, final)
            self.assertEqual(len(set(final["allow"])), n)


if __name__ == "__main__":
    unittest.main()
