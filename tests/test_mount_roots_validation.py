"""config.validate_mount_roots — the mount_roots allowlist floor."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.config import validate_mount_roots


class TestValidateMountRoots(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())  # not under $HOME, not catastrophe
        (self.tmp / "work").mkdir()
        (self.tmp / "code").mkdir()

    def test_normal_root_ok(self):
        self.assertEqual(validate_mount_roots([str(self.tmp / "work")]), [])

    def test_root_under_home_ok(self):
        # The normal case — a dir UNDER $HOME must be allowed (only $HOME itself
        # or a parent is too broad). Patch home to the tmpdir so we don't write
        # under the real home.
        sub = self.tmp / "work"  # under patched-home (self.tmp)
        with patch("brig.config.Path.home", return_value=self.tmp):
            self.assertEqual(validate_mount_roots([str(sub)]), [])
            # ...but the home dir itself is rejected.
            self.assertTrue(validate_mount_roots([str(self.tmp)]))

    def test_root_slash_rejected(self):
        self.assertTrue(validate_mount_roots(["/"]))

    def test_home_itself_rejected(self):
        self.assertTrue(validate_mount_roots([str(Path.home())]))

    def test_ancestor_of_home_rejected(self):
        self.assertTrue(validate_mount_roots([str(Path.home().parent)]))

    def test_etc_rejected(self):
        self.assertTrue(validate_mount_roots(["/etc"]))

    def test_ssh_rejected(self):
        self.assertTrue(validate_mount_roots([str(Path.home() / ".ssh")]))

    def test_inside_secret_dir_rejected(self):
        self.assertTrue(validate_mount_roots([str(Path.home() / ".ssh" / "keys")]))

    def test_nonexistent_rejected(self):
        self.assertTrue(validate_mount_roots([str(self.tmp / "missing")]))

    def test_non_dir_rejected(self):
        f = self.tmp / "afile"
        f.write_text("x")
        self.assertTrue(validate_mount_roots([str(f)]))

    def test_relative_rejected(self):
        self.assertTrue(validate_mount_roots(["work"]))

    def test_illegal_char_rejected(self):
        self.assertTrue(validate_mount_roots([str(self.tmp / 'a"b')]))
        self.assertTrue(validate_mount_roots(["/tmp/a\nb"]))

    def test_slug_collision_rejected(self):
        # two different roots, same basename -> same /mnt/host/<slug>
        a = self.tmp / "x" / "work"
        b = self.tmp / "y" / "work"
        a.mkdir(parents=True)
        b.mkdir(parents=True)
        self.assertTrue(validate_mount_roots([str(a), str(b)]))

    def test_symlink_to_protected_rejected(self):
        # A symlink whose target is $HOME must be rejected — the reconciler
        # binds the realpath, so the floor must resolve symlinks too.
        link = self.tmp / "homelink"
        os.symlink(str(Path.home()), str(link))
        self.assertTrue(validate_mount_roots([str(link)]))

    def test_realpath_alias_of_protected_rejected(self):
        # e.g. macOS /etc -> /private/etc: the alias must be rejected too.
        alias = os.path.realpath("/etc")
        if alias == "/etc":
            self.skipTest("/etc is not a realpath alias on this platform")
        self.assertTrue(validate_mount_roots([alias]))

    def test_case_variant_of_secret_rejected(self):
        # On a case-insensitive filesystem ~/.SSH IS ~/.ssh.
        ssh = Path.home() / ".ssh"
        variant = Path.home() / ".SSH"
        if not ssh.is_dir() or not os.path.isdir(variant):
            self.skipTest("~/.ssh absent or filesystem is case-sensitive")
        if not os.path.samefile(ssh, variant):
            self.skipTest("filesystem is case-sensitive")
        self.assertTrue(validate_mount_roots([str(variant)]))


class TestConfigSetCoercion(unittest.TestCase):
    """`brig config set mount_roots` coerces input the same way mount_roots()
    reads it: a list or a comma-separated string; other JSON is a usage error."""

    def _set(self, value):
        from types import SimpleNamespace
        from brig.commands.config_cmd import cmd_config_set
        with patch("brig.commands.config_cmd.CONFIG_FILE", "/nonexistent/brig.json"):
            return cmd_config_set(SimpleNamespace(key="mount_roots", value=value))

    def test_dict_value_rejected_clearly(self):
        from brig.errors import BrigError
        with self.assertRaises(BrigError) as cm:
            self._set('{"x": 1}')
        self.assertIn("list or", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
