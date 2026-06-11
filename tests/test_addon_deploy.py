"""sync_addons keeps the deployed warden addons in lockstep with the package,
so an addon edit can't leave warden running stale code (the deploy-drift gotcha).
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.ops import addon_deploy


class TestSyncAddons(unittest.TestCase):
    def setUp(self):
        self.src = Path(tempfile.mkdtemp())
        self.dst = Path(tempfile.mkdtemp())
        (self.src / "enforce.py").write_text("x = 1\n")
        self._p1 = patch.object(addon_deploy, "addon_source_dir", return_value=self.src)
        self._p2 = patch("brig.ops.addon_deploy.HostPaths.ADDONS_DIR", self.dst)
        self._p1.start()
        self._p2.start()

    def tearDown(self):
        self._p1.stop()
        self._p2.stop()

    def test_copies_then_idempotent(self):
        self.assertTrue(addon_deploy.sync_addons())                  # first copy
        self.assertEqual((self.dst / "enforce.py").read_text(), "x = 1\n")
        self.assertFalse(addon_deploy.sync_addons())                 # unchanged -> no-op

    def test_resyncs_on_change(self):
        addon_deploy.sync_addons()
        (self.src / "enforce.py").write_text("x = 2\n")              # edit the source
        self.assertTrue(addon_deploy.sync_addons())
        self.assertEqual((self.dst / "enforce.py").read_text(), "x = 2\n")

    def test_source_missing_is_noop(self):
        with patch.object(addon_deploy, "addon_source_dir", return_value=None):
            self.assertFalse(addon_deploy.sync_addons())


class TestAddonSourceDir(unittest.TestCase):
    def test_resolves_addons_as_package_data(self):
        # Resolved via importlib.resources as brig package-data — works in both
        # editable and wheel installs.
        d = addon_deploy.addon_source_dir()
        self.assertIsNotNone(d)
        self.assertTrue((d / "enforce.py").exists())


if __name__ == "__main__":
    unittest.main()
