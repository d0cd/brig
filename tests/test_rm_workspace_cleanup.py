"""`brig cell rm` deletes the cell's state directory by default; the
new `--keep-workspace` flag preserves it.

The default-delete behavior closes a re-use foot-gun: a prior cell may
have planted symlinks (or other cell-controlled content) in the
workspace, and a new cell with the same name would inherit them.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class TestRmWorkspaceCleanup(unittest.TestCase):

    def _patched_state(self, td: Path):
        return patch("brig.config.HostPaths.STATE_DIR", td)

    def _stub_destroy_path(self):
        """Patch the podman-touching pieces of rm_cell so the function
        runs end-to-end without a real VM, and we can observe the
        host-side cleanup."""
        observed = MagicMock()
        observed.exists = True
        observed.network_exists = True
        observed.running = False
        return [
            patch("brig.cell.lifecycle.observe", return_value=observed),
            patch("brig.network.ingress.deregister_ingress"),
            patch("brig.cell.lifecycle.plan_destroy", return_value=[]),
            patch("brig.cell.lifecycle.apply",
                  return_value=MagicMock(success=True, actions_failed=[])),
            patch("brig.cell.lifecycle.log_operation"),
            patch("brig.cell.lifecycle.log_lifecycle"),
        ]

    def test_default_removes_cell_state_dir(self):
        from brig.cell.lifecycle import rm_cell
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            cell_state = state / "alice"
            (cell_state / "workspace").mkdir(parents=True)
            (cell_state / "workspace" / "file.txt").write_text("x")
            (cell_state / "cell-metadata.json").write_text("{}")

            patches = self._stub_destroy_path()
            for p in patches:
                p.start()
            try:
                with self._patched_state(state):
                    rm_cell("alice")
                self.assertFalse(cell_state.exists(),
                    "default rm should have deleted ~/.brig/state/alice/")
            finally:
                for p in patches:
                    p.stop()

    def test_keep_workspace_preserves_dir(self):
        from brig.cell.lifecycle import rm_cell
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            cell_state = state / "bob"
            (cell_state / "workspace").mkdir(parents=True)
            (cell_state / "workspace" / "important.txt").write_text("KEEP ME")

            patches = self._stub_destroy_path()
            for p in patches:
                p.start()
            try:
                with self._patched_state(state):
                    rm_cell("bob", keep_workspace=True)
                self.assertTrue(cell_state.exists(),
                    "--keep-workspace should preserve ~/.brig/state/bob/")
                self.assertEqual(
                    (cell_state / "workspace" / "important.txt").read_text(),
                    "KEEP ME",
                )
            finally:
                for p in patches:
                    p.stop()

    def test_cleanup_is_best_effort(self):
        """If shutil.rmtree fails for some reason (perm error, mount
        busy), rm_cell should still report success — the leftover dir
        is leakage, not a correctness failure."""
        from brig.cell.lifecycle import rm_cell
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / "carol" / "workspace").mkdir(parents=True)

            patches = self._stub_destroy_path()
            for p in patches:
                p.start()
            try:
                with self._patched_state(state), \
                     patch("shutil.rmtree", side_effect=OSError("simulated")):
                    # Must not raise.
                    rm_cell("carol")
            finally:
                for p in patches:
                    p.stop()


if __name__ == "__main__":
    unittest.main()
