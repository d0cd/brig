"""Race-free workspace file access. Audit finding H2: the previous
path-returning validator was TOCTOU-unsafe (cell could swap inode
between validation and consumer's open). The replacement is a
file-descriptor-based primitive that walks each path component with
O_NOFOLLOW; the consumer never touches a path string.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _make_workspace(base: Path, cell: str) -> Path:
    ws = base / "state" / cell / "workspace"
    ws.mkdir(parents=True)
    return ws


def _patched(base: Path):
    state = base / "state"
    state.mkdir(parents=True, exist_ok=True)
    return patch("brig.workspace.validation.HostPaths.STATE_DIR", state)


class TestSafeOpenAllows(unittest.TestCase):
    """Normal reads/writes inside the workspace succeed."""

    def test_read_file_at_root_of_workspace(self):
        from brig.workspace.validation import safe_open
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "ok.txt").write_text("hello")
            with _patched(base):
                with safe_open("c1", "ok.txt", "r") as f:
                    self.assertEqual(f.read(), "hello")

    def test_read_file_in_subdir(self):
        from brig.workspace.validation import safe_open
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "a" / "b").mkdir(parents=True)
            (ws / "a" / "b" / "deep.txt").write_text("deep")
            with _patched(base):
                with safe_open("c1", "a/b/deep.txt", "r") as f:
                    self.assertEqual(f.read(), "deep")

    def test_write_creates_file(self):
        from brig.workspace.validation import safe_open
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            with _patched(base):
                with safe_open("c1", "new.txt", "w") as f:
                    f.write("wrote")
            self.assertEqual((ws / "new.txt").read_text(), "wrote")

    def test_absolute_path_inside_workspace_accepted(self):
        """If the consumer pulled workspace.host_path from cell.json and
        joined it with a relative path, the result is absolute. Still
        valid as long as it's inside the workspace."""
        from brig.workspace.validation import safe_open
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "ok.txt").write_text("yes")
            with _patched(base):
                with safe_open("c1", str(ws / "ok.txt"), "r") as f:
                    self.assertEqual(f.read(), "yes")


class TestSafeOpenRejects(unittest.TestCase):
    """The actual security tests: cell-controlled inputs must not escape."""

    def test_dotdot_escape(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "../../etc/passwd", "r"):
                        pass

    def test_absolute_path_outside_workspace(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "/etc/passwd", "r"):
                        pass

    def test_null_byte_rejected(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "ok\x00bad.txt", "r"):
                        pass

    def test_empty_path_rejected(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _make_workspace(base, "c1")
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "", "r"):
                        pass

    def test_symlink_final_component_rejected(self):
        """THE load-bearing security test: a cell that drops a symlink
        in its workspace pointing at a host secret must fail safe_open."""
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            outside = base / "host-secret"
            outside.write_text("PRIVATE-KEY")
            (ws / "innocuous.txt").symlink_to(outside)
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "innocuous.txt", "r"):
                        pass

    def test_symlink_in_intermediate_component_rejected(self):
        """A symlink at an intermediate path component is also rejected,
        even if its target is inside the workspace. The walk refuses any
        symlink anywhere — over-restrictive on purpose, since the alternative
        is to engage with the question 'is THIS symlink racy?' per-component."""
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "real").mkdir()
            (ws / "real" / "file.txt").write_text("inside")
            (ws / "link").symlink_to(ws / "real")
            with _patched(base):
                # Direct access works.
                with safe_open("c1", "real/file.txt", "r") as f:
                    self.assertEqual(f.read(), "inside")
                # Through a symlinked intermediate — refused.
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "link/file.txt", "r"):
                        pass

    def test_workspace_root_symlink_rejected(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state = base / "state"
            state.mkdir()
            # Place the actual workspace elsewhere; make the expected
            # location a symlink to it.
            real = base / "real-workspace"
            real.mkdir()
            (state / "c1").mkdir()
            (state / "c1" / "workspace").symlink_to(real)
            with patch("brig.workspace.validation.HostPaths.STATE_DIR", state):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("c1", "anything.txt", "r"):
                        pass

    def test_workspace_missing(self):
        from brig.workspace.validation import safe_open, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            (base / "state").mkdir()
            with _patched(base):
                with self.assertRaises(WorkspaceEscape):
                    with safe_open("ghost", "anything.txt", "r"):
                        pass


class TestSafeOpenTOCTOURace(unittest.TestCase):
    """The original audit attack: between validation and open, swap the
    file for a symlink. Demonstrate that safe_open is immune because the
    fd is opened during the validation itself."""

    def test_post_open_symlink_swap_does_not_affect_fd(self):
        from brig.workspace.validation import safe_open
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "innocuous.txt").write_text("original")
            secret = base / "host-secret"
            secret.write_text("PRIVATE-KEY")

            with _patched(base):
                with safe_open("c1", "innocuous.txt", "r") as f:
                    # Cell-side adversary swaps the file for a symlink
                    # AFTER safe_open returned its fd.
                    (ws / "innocuous.txt").unlink()
                    (ws / "innocuous.txt").symlink_to(secret)
                    # The fd is bound to the original inode — should
                    # still read "original", not the secret.
                    self.assertEqual(f.read(), "original")


class TestSafeDirfd(unittest.TestCase):
    """The advanced API for callers that want to do their own walk."""

    def test_returns_dirfd_for_workspace_root(self):
        from brig.workspace.validation import safe_dirfd
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            ws = _make_workspace(base, "c1")
            (ws / "test.txt").write_text("hello")
            with _patched(base):
                fd = safe_dirfd("c1")
                try:
                    # Use the dirfd to openat the file.
                    file_fd = os.open("test.txt", os.O_RDONLY, dir_fd=fd)
                    with os.fdopen(file_fd, "r") as f:
                        self.assertEqual(f.read(), "hello")
                finally:
                    os.close(fd)

    def test_rejects_symlinked_root(self):
        from brig.workspace.validation import safe_dirfd, WorkspaceEscape
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            state = base / "state"
            state.mkdir()
            real = base / "real-workspace"
            real.mkdir()
            (state / "c1").mkdir()
            (state / "c1" / "workspace").symlink_to(real)
            with patch("brig.workspace.validation.HostPaths.STATE_DIR", state):
                with self.assertRaises(WorkspaceEscape):
                    safe_dirfd("c1")


if __name__ == "__main__":
    unittest.main()
