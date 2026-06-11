"""Render mount_roots into lima.yaml's managed block."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.errors import BrigError
from brig.vm.lima_mounts import render_mount_roots_block, sync_lima_mount_roots

_TEMPLATE = """\
mounts:
  - location: "~/.brig/state"
    mountPoint: "/state"
    writable: true
  # brig:mount_roots:begin (managed)
  # brig:mount_roots:end

provision: []
"""


def _real_root(parent, name):
    p = Path(parent) / name
    p.mkdir(parents=True, exist_ok=True)
    return str(p)


class TestRender(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp()  # not under $HOME / not catastrophe

    def test_renders_one_entry_per_root(self):
        work = _real_root(self.base, "work")
        code = _real_root(self.base, "code")
        block = render_mount_roots_block([work, code])
        self.assertIn(f'  - location: "{work}"', block)
        self.assertIn('    mountPoint: "/mnt/host/work"', block)
        self.assertIn('    mountPoint: "/mnt/host/code"', block)
        self.assertIn("writable: true", block)

    def test_empty_roots_empty_block(self):
        self.assertEqual(render_mount_roots_block([]), "")

    def test_slug_collision_raises(self):
        a = _real_root(self.base + "/a", "work")
        b = _real_root(self.base + "/b", "work")
        with self.assertRaises(BrigError):
            render_mount_roots_block([a, b])  # both slug "work"

    def test_invalid_root_raises(self):
        with self.assertRaises(BrigError):
            render_mount_roots_block(["/"])


class TestSync(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.tmp = self.dir / "lima.yaml"
        self.tmp.write_text(_TEMPLATE)
        self.work = _real_root(self.dir, "work")

    def test_populates_block(self):
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            changed = sync_lima_mount_roots(self.tmp)
        self.assertTrue(changed)
        text = self.tmp.read_text()
        self.assertIn('mountPoint: "/mnt/host/work"', text)
        self.assertIn("# brig:mount_roots:begin", text)
        self.assertIn("# brig:mount_roots:end", text)
        self.assertIn('mountPoint: "/state"', text)
        self.assertIn("provision: []", text)

    def test_idempotent(self):
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            self.assertTrue(sync_lima_mount_roots(self.tmp))
            self.assertFalse(sync_lima_mount_roots(self.tmp))

    def test_clearing_roots_empties_block(self):
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            sync_lima_mount_roots(self.tmp)
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[]):
            self.assertTrue(sync_lima_mount_roots(self.tmp))
        self.assertNotIn("/mnt/host/work", self.tmp.read_text())

    def test_no_markers_is_noop(self):
        self.tmp.write_text("mounts: []\nprovision: []\n")
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            self.assertFalse(sync_lima_mount_roots(self.tmp))

    def test_missing_file_is_noop(self):
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            self.assertFalse(sync_lima_mount_roots(self.dir / "nope.yaml"))

    def test_malformed_markers_raise(self):
        self.tmp.write_text(
            "mounts:\n# brig:mount_roots:end\n# brig:mount_roots:begin\nprovision: []\n"
        )
        with patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            with self.assertRaises(BrigError):
                sync_lima_mount_roots(self.tmp)


class TestSyncAll(unittest.TestCase):
    """sync_all_lima_mount_roots syncs both the template and the live instance
    config, signalling when the instance changed (→ restart needed)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.template = self.dir / "template.yaml"
        self.instance = self.dir / "instance.yaml"
        self.template.write_text(_TEMPLATE)
        self.instance.write_text(_TEMPLATE)
        self.work = _real_root(self.dir, "work")

    def test_syncs_both_and_signals_instance_change(self):
        from brig.vm import lima_mounts
        with patch("brig.vm.lima_mounts.HostPaths.LIMA_YAML", self.template), \
             patch("brig.vm.lima_mounts.lima_instance_config", return_value=self.instance), \
             patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            changed = lima_mounts.sync_all_lima_mount_roots()
        self.assertTrue(changed)  # instance changed → restart needed
        self.assertIn('mountPoint: "/mnt/host/work"', self.template.read_text())
        self.assertIn('mountPoint: "/mnt/host/work"', self.instance.read_text())

    def test_absent_instance_still_syncs_template(self):
        from brig.vm import lima_mounts
        self.instance.unlink()
        with patch("brig.vm.lima_mounts.HostPaths.LIMA_YAML", self.template), \
             patch("brig.vm.lima_mounts.lima_instance_config", return_value=self.instance), \
             patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            changed = lima_mounts.sync_all_lima_mount_roots()
        self.assertFalse(changed)  # no instance to apply to
        self.assertIn('mountPoint: "/mnt/host/work"', self.template.read_text())

    def test_malformed_instance_raises_but_template_still_synced(self):
        from brig.vm import lima_mounts
        # Operator-corrupted instance markers must not strand the template sync;
        # the raised error names the offending instance file.
        self.instance.write_text(
            "mounts:\n# brig:mount_roots:end\n# brig:mount_roots:begin\nx: 1\n"
        )
        with patch("brig.vm.lima_mounts.HostPaths.LIMA_YAML", self.template), \
             patch("brig.vm.lima_mounts.lima_instance_config", return_value=self.instance), \
             patch("brig.vm.lima_mounts.mount_roots", return_value=[self.work]):
            with self.assertRaises(BrigError) as cm:
                lima_mounts.sync_all_lima_mount_roots()
        self.assertIn(str(self.instance), str(cm.exception))
        self.assertIn('mountPoint: "/mnt/host/work"', self.template.read_text())


if __name__ == "__main__":
    unittest.main()
