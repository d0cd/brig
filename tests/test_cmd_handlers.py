"""Tests for command handler integration — the glue between CLI args and domain modules.

Proves cmd_run correctly merges profiles, cell definitions, and CLI flags
into the right CellSpec.
"""

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from brig.cell.reconciler import CellState, ReconcileResult
from brig.cell.spec import CellSpec
from brig.errors import BrigError


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
    """Test policy set command handler."""

    def test_global_policy_edit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "network-policy.json"
            policy_path.write_text(json.dumps({"allow": ["existing.com"], "deny": []}))

            with patch("brig.commands.policy_cmd.HostPaths") as mock_paths:
                mock_paths.NETWORK_POLICY = policy_path
                from brig.commands.policy_cmd import cmd_policy_set

                args = types.SimpleNamespace(
                    name="global", allow=["new.com"], deny=None,
                    remove_allow=None, remove_deny=None,
                )
                with patch("brig.commands.policy_cmd.log_policy_change"):
                    with patch("warden.proxy.reload_policy", return_value=True):
                        cmd_policy_set(args)

            policy = json.loads(policy_path.read_text())
            self.assertIn("existing.com", policy["allow"])
            self.assertIn("new.com", policy["allow"])
