"""Tests for command handler integration — the glue between CLI args and domain modules.

Proves cmd_run correctly merges profiles, cell definitions, and CLI flags
into the right CellSpec.
"""

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from brig.cell.reconciler import ReconcileResult
from brig.errors import BrigError


class TestCmdStartReplayIngress(unittest.TestCase):
    """`brig cell start` must replay ingress registration with the
    freshly-inspected cell IP. Without this, a `brig system down/up`
    cycle leaves the cell running but ingress requests through warden's
    :8443 reverse proxy return 502.
    """

    def test_start_with_ingress_in_metadata_replays_registration(self):
        from brig.commands.lifecycle_cmd import cmd_start
        ingress_entries = [
            {"name": "api", "port": 8000,
             "path_prefix": "/api", "auth": "token"},
        ]
        with patch("brig.network.proxy.proxy_running", return_value=True), \
             patch("brig.commands.lifecycle_cmd._refresh_metadata_for_start"), \
             patch("brig.commands.lifecycle_cmd.vm_run") as mock_vm, \
             patch("brig.cell.metadata.read_ingress",
                   return_value=ingress_entries) as mock_read, \
             patch("brig.cell.lifecycle.register_ingress_for") as mock_reg:
            import subprocess
            mock_vm.return_value = subprocess.CompletedProcess([], 0, "", "")
            rc = cmd_start(types.SimpleNamespace(name="cell-with-ingress"))
        self.assertEqual(rc, 0)
        mock_read.assert_called_once_with("cell-with-ingress")
        mock_reg.assert_called_once_with("cell-with-ingress", ingress_entries)

    def test_start_without_ingress_in_metadata_skips_registration(self):
        from brig.commands.lifecycle_cmd import cmd_start
        with patch("brig.network.proxy.proxy_running", return_value=True), \
             patch("brig.commands.lifecycle_cmd._refresh_metadata_for_start"), \
             patch("brig.commands.lifecycle_cmd.vm_run") as mock_vm, \
             patch("brig.cell.metadata.read_ingress", return_value=[]), \
             patch("brig.cell.lifecycle.register_ingress_for") as mock_reg:
            import subprocess
            mock_vm.return_value = subprocess.CompletedProcess([], 0, "", "")
            rc = cmd_start(types.SimpleNamespace(name="cell-without"))
        self.assertEqual(rc, 0)
        mock_reg.assert_not_called()


class TestCmdRunProfileMerge(unittest.TestCase):
    """Test that cmd_run correctly applies profiles to CellSpec."""

    def _make_args(self, **overrides):
        defaults = dict(
            name="test", image="alpine", container_cmd=[], env=None,
            secret=None, memory=None, cpus=None, pids_limit=None,
            network=None, profile=None, file=None, policy_allow=None,
            policy_deny=None, label=None, timeout=None, workspace_quota=None,
            detach=False, rm=False, tor=False, image_digest=None, workdir=None,
        )
        defaults.update(overrides)
        return types.SimpleNamespace(**defaults)

    @patch("brig.commands.lifecycle_cmd.run_cell")
    def test_untrusted_profile_sets_memory(self, mock_run):
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(profile="untrusted")
        cmd_run(args)

        spec = mock_run.call_args[0][0]
        self.assertEqual(spec.memory, "512m")
        self.assertEqual(spec.cpus, "1")
        self.assertEqual(spec.pids_limit, 256)

    @patch("brig.commands.lifecycle_cmd.run_cell")
    def test_cli_flags_override_profile(self, mock_run):
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(profile="untrusted", memory="4g")
        cmd_run(args)

        spec = mock_run.call_args[0][0]
        self.assertEqual(spec.memory, "4g")  # CLI wins over profile.

    @patch("brig.commands.lifecycle_cmd.run_cell")
    def test_cell_def_file_merged(self, mock_run):
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"name": "from-file", "image": "python:3.12",
                       "env": {"FROM_FILE": "yes"}}, f)
            f.flush()

            from brig.commands.lifecycle_cmd import cmd_run
            args = self._make_args(name=None, image=None, file=f.name)
            cmd_run(args)

        spec = mock_run.call_args[0][0]
        self.assertEqual(spec.image, "python:3.12")
        self.assertTrue(any("FROM_FILE=yes" in e for e in spec.env))

    @patch("brig.commands.lifecycle_cmd.run_cell")
    def test_auto_generated_name(self, mock_run):
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(name=None)
        cmd_run(args)

        spec = mock_run.call_args[0][0]
        self.assertIsNotNone(spec.name)
        self.assertRegex(spec.name, r'^[a-z]+-[a-z]+-\d+$')

    @patch("brig.commands.lifecycle_cmd.run_cell")
    def test_airgapped_network(self, mock_run):
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(network="none")
        cmd_run(args)

        spec = mock_run.call_args[0][0]
        self.assertEqual(spec.network, "none")
        self.assertTrue(spec.is_airgapped)


class TestCmdRunValidation(unittest.TestCase):
    """Test that cmd_run rejects invalid input."""

    def _make_args(self, **overrides):
        defaults = dict(
            name="test", image="alpine", container_cmd=[], env=None,
            secret=None, memory=None, cpus=None, pids_limit=None,
            network=None, profile=None, file=None, policy_allow=None,
            policy_deny=None, label=None, timeout=None, workspace_quota=None,
            detach=False, rm=False, tor=False, image_digest=None, workdir=None,
        )
        defaults.update(overrides)
        return types.SimpleNamespace(**defaults)

    def test_invalid_cell_name_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(name="../../../etc")
        with self.assertRaises((BrigError, ValueError)):
            cmd_run(args)

    def test_invalid_cell_def_file_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"network": "proxy-external"}, f)
            f.flush()
            args = self._make_args(file=f.name)
            with self.assertRaises(BrigError):
                cmd_run(args)

    def test_no_image_and_no_file_rejected(self):
        from brig.commands.lifecycle_cmd import cmd_run
        args = self._make_args(image=None, file=None)
        with self.assertRaises(BrigError):
            cmd_run(args)


class TestCmdPolicySet(unittest.TestCase):
    """Test policy set command handler — per-cell only."""

    def test_per_cell_edit_appends_allow(self):
        from brig.commands.policy_cmd import cmd_policy_set
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_dir = Path(tmpdir)
            (policy_dir / "alice.json").write_text(
                json.dumps({"allow": ["existing.com"], "deny": []})
            )
            args = types.SimpleNamespace(
                name="alice", allow=["new.com"], deny=None,
                remove_allow=None, remove_deny=None,
            )
            with patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda n, *a, **kw: policy_dir / f"{n}.json"), \
                 patch("brig.commands.policy_cmd.log_policy_change"), \
                 patch("brig.cell.metadata.refresh_metadata_if_present"):
                cmd_policy_set(args)
            policy = json.loads((policy_dir / "alice.json").read_text())
            self.assertIn("existing.com", policy["allow"])
            self.assertIn("new.com", policy["allow"])
