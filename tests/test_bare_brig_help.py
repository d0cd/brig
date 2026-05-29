"""Bare `brig` (no subcommand) prints a friendly cheat-sheet and
exits 0, instead of argparse's "the following arguments are required:
command" error.

Why a separate path: argparse's default error dumps a wall of flags
that doesn't help a new user know what to type next. A grouped index
of common verbs is more actionable on a fresh install.
"""

from __future__ import annotations

import io
import unittest
from unittest.mock import patch


class TestBareBrigHelp(unittest.TestCase):
    def _capture_main(self, argv: list[str]) -> tuple[int, str]:
        from brig.cli import main
        out = io.StringIO()
        with patch("sys.argv", ["brig"] + argv), \
             patch("sys.stdout", out):
            try:
                main()
                rc = 0
            except SystemExit as e:
                rc = int(e.code or 0)
        return rc, out.getvalue()

    def test_no_args_prints_quickstart_and_exits_zero(self):
        rc, text = self._capture_main([])
        self.assertEqual(rc, 0)
        self.assertIn("Quickstart:", text)
        self.assertIn("brig system up", text)
        self.assertIn("brig run", text)

    def test_quickstart_lists_grouped_verbs(self):
        _, text = self._capture_main([])
        for verb in ("run", "cell", "image", "system", "policy", "secrets", "config"):
            self.assertIn(verb, text)


if __name__ == "__main__":
    unittest.main()
