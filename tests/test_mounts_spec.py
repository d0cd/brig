"""Validation for the per-cell `mounts:` block (scoped host-directory mounts).

mounts bypass Warden and touch real host files, so these parse-time guards +
the config.mount_roots() allowlist are the security boundary on the
cell-yaml -> host-path edge. See docs/design/host-mounts.md.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _base():
    return {"name": "c", "image": "alpine"}


class _MountsCase(unittest.TestCase):
    """Sets up a tmpdir root + a host dir under it, and patches mount_roots."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.root = Path(self._tmp) / "work"
        self.repo = self.root / "repo"
        self.repo.mkdir(parents=True)
        self._patch = patch("brig.config.mount_roots", return_value=[str(self.root)])
        self._patch.start()

    def tearDown(self):
        self._patch.stop()

    def _validate(self, mounts, **extra):
        from brig.cell.spec import validate_cell_definition
        cell_def = {**_base(), "mounts": mounts, **extra}
        return validate_cell_definition(cell_def)

    def _entry(self, **kw):
        e = {"name": "repo", "host_path": str(self.repo),
             "mount_point": "/workspace", "mode": "ro"}
        e.update(kw)
        return e


class TestValidMounts(_MountsCase):
    def test_minimal_ro_ok(self):
        self.assertFalse(self._validate([self._entry()]))

    def test_rw_ok(self):
        self.assertFalse(self._validate([self._entry(mode="rw")]))


class TestNameAndShape(_MountsCase):
    def test_not_a_list_rejected(self):
        self.assertTrue(self._validate({"name": "x"}))

    def test_entry_not_a_dict_rejected(self):
        self.assertTrue(self._validate(["nope"]))

    def test_missing_name_rejected(self):
        errs = self._validate([self._entry(name=None)])
        self.assertTrue(any("name" in e for e in errs), errs)

    def test_bad_name_rejected(self):
        self.assertTrue(self._validate([self._entry(name="Bad Name")]))

    def test_duplicate_name_rejected(self):
        errs = self._validate([self._entry(), self._entry(mount_point="/other")])
        self.assertTrue(any("uplicate" in e for e in errs), errs)


class TestHostPath(_MountsCase):
    def test_missing_host_path_rejected(self):
        self.assertTrue(self._validate([self._entry(host_path=None)]))

    def test_relative_host_path_rejected(self):
        self.assertTrue(self._validate([self._entry(host_path="repo")]))

    def test_traversal_rejected(self):
        self.assertTrue(self._validate([self._entry(host_path=str(self.root / ".." / "x"))]))

    def test_nonexistent_dir_rejected(self):
        self.assertTrue(self._validate([self._entry(host_path=str(self.root / "missing"))]))

    def test_file_not_dir_rejected(self):
        f = self.root / "afile"
        f.write_text("x")
        self.assertTrue(self._validate([self._entry(host_path=str(f))]))

    def test_outside_roots_rejected(self):
        with tempfile.TemporaryDirectory() as other:
            errs = self._validate([self._entry(host_path=other)])
            self.assertTrue(any("mount_roots" in e or "root" in e for e in errs), errs)

    def test_no_roots_configured_rejected(self):
        with patch("brig.config.mount_roots", return_value=[]):
            errs = self._validate([self._entry()])
            self.assertTrue(errs)


class TestMountPoint(_MountsCase):
    def test_relative_mount_point_rejected(self):
        self.assertTrue(self._validate([self._entry(mount_point="workspace")]))

    def test_system_path_rejected(self):
        for bad in ("/etc", "/proc", "/run/secrets", "/"):
            self.assertTrue(self._validate([self._entry(mount_point=bad)]), bad)

    def test_shadows_default_work_rejected(self):
        self.assertTrue(self._validate([self._entry(mount_point="/work")]))

    def test_colon_in_mount_point_rejected(self):
        # ':' is the podman -v field separator; it must not reach the bind arg.
        self.assertTrue(self._validate([self._entry(mount_point="/data:x")]))

    def test_duplicate_mount_point_rejected(self):
        errs = self._validate([self._entry(name="a"),
                               self._entry(name="b")])  # same /workspace
        self.assertTrue(any("uplicate" in e for e in errs), errs)


class TestMode(_MountsCase):
    def test_bad_mode_rejected(self):
        self.assertTrue(self._validate([self._entry(mode="x")]))


class TestLimitAndProfile(_MountsCase):
    def test_too_many_rejected(self):
        entries = [self._entry(name=f"m{i}", mount_point=f"/m{i}") for i in range(20)]
        errs = self._validate(entries)
        self.assertTrue(any("Too many" in e or "max" in e for e in errs), errs)

    def test_untrusted_profile_rejected(self):
        errs = self._validate([self._entry()], profile="untrusted")
        self.assertTrue(any("untrusted" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
