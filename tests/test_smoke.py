"""Smoke test — validates the full command chain without a real VM.

Mocks vm_run at the boundary and verifies that the entire path from
CLI args → CellSpec → reconciler → build_run_command produces a correct
podman command routed through limactl shell.

This is the closest we can get to an end-to-end test without a Mac + Lima.
"""

import subprocess
import unittest
from unittest.mock import patch

from brig.cell.reconciler import (
    ActionType,
    CellState,
    build_run_command,
    plan_run,
)
from brig.cell.spec import CellSpec
from brig.config import CONTAINER_PREFIX, RUNTIME


class TestFullRunCommandChain(unittest.TestCase):
    """Test: CellSpec → plan_run → build_run_command → verify output."""

    def test_happy_path_command_is_correct(self):
        """A complete run command has all security flags and proxy env."""
        spec = CellSpec(
            name="smoke-test",
            image="alpine:3.19",
            command=["echo", "hello"],
            memory="512m",
            cpus="1",
            pids_limit=256,
            env=["APP_ENV=production"],
            secrets=["api-key"],
        )

        cmd = build_run_command(spec, "10.60.42.1")

        # Container name.
        self.assertIn("--name", cmd)
        self.assertIn(f"{CONTAINER_PREFIX}smoke-test", cmd)

        # Invariant 5: gVisor runtime.
        idx = cmd.index("--runtime")
        self.assertEqual(cmd[idx + 1], RUNTIME)

        # Security hardening.
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        self.assertIn("no-new-privileges", cmd)

        # Resource limits.
        self.assertIn("--memory", cmd)
        self.assertIn("512m", cmd)
        self.assertIn("--cpus", cmd)
        self.assertIn("1", cmd)
        self.assertIn("--pids-limit", cmd)
        self.assertIn("256", cmd)

        # Network: per-cell internal network.
        self.assertIn("--network", cmd)
        self.assertIn(f"{CONTAINER_PREFIX}smoke-test", cmd)

        # Proxy env vars.
        cmd_str = " ".join(cmd)
        self.assertIn("http_proxy=http://warden:8080", cmd_str)
        self.assertIn("https_proxy=http://warden:8080", cmd_str)
        self.assertIn("HTTP_PROXY=http://warden:8080", cmd_str)
        self.assertIn("HTTPS_PROXY=http://warden:8080", cmd_str)
        self.assertIn("no_proxy=localhost,127.0.0.1", cmd_str)

        # User env var passed through.
        self.assertIn("APP_ENV=production", cmd)

        # Secret mounted read-only.
        self.assertIn("/run/secrets/api-key:ro", cmd_str)

        # Workspace mount.
        self.assertIn("/work:rw", cmd_str)

        # Image and command at the end.
        self.assertEqual(cmd[-3], "alpine:3.19")
        self.assertEqual(cmd[-2], "echo")
        self.assertEqual(cmd[-1], "hello")


class TestVmRunRouting(unittest.TestCase):
    """Test that vm_run wraps commands in limactl shell."""

    @patch("brig.vm.shell.subprocess.run")
    def test_vm_run_adds_limactl_prefix(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")

        from brig.vm.shell import vm_run
        vm_run(["podman", "ps"])

        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[:6], ["limactl", "shell", "--workdir", "/", "brig", "--"])
        self.assertEqual(called_cmd[6:], ["sudo", "podman", "ps"])

    @patch("brig.vm.shell.subprocess.run")
    def test_vm_run_interactive_adds_prefix(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0)

        from brig.vm.shell import vm_run_interactive
        vm_run_interactive(["podman", "exec", "-it", "brig-test", "/bin/sh"])

        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[:6], ["limactl", "shell", "--workdir", "/", "brig", "--"])

    @patch("brig.vm.shell.subprocess.run")
    def test_vm_run_sudo_true_forces_sudo_on_non_autosudo_cmd(self, mock_run):
        """`sudo=True` lets callers run root-only commands whose basename
        isn't in the auto-sudo set (e.g. `sh -c <script>` writing to a
        root-owned dir) without prefixing 'sudo' themselves."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        from brig.vm.shell import vm_run
        vm_run(["cat", "/var/log/root-owned.log"], sudo=True)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[6:], ["sudo", "cat", "/var/log/root-owned.log"])

    @patch("brig.vm.shell.subprocess.run")
    def test_vm_run_sudo_false_suppresses_auto_sudo(self, mock_run):
        """`sudo=False` defeats the auto-sudo for cmd[0]. Lets callers
        run a normally-auto-sudo basename as the lima user when that's
        what they want."""
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        from brig.vm.shell import vm_run
        vm_run(["podman", "info"], sudo=False)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd[6:], ["podman", "info"])

    def test_vm_run_rejects_explicit_sudo_prefix(self):
        """Bare `["sudo", ...]` is rejected so sudo decisions stay in one
        place (the helper) and double-sudo bugs can't slip in."""
        from brig.vm.shell import vm_run
        with self.assertRaises(ValueError):
            vm_run(["sudo", "podman", "ps"])


class TestReconcilerPlanToApply(unittest.TestCase):
    """Test the full reconciler path: observe state → plan → action sequence."""

    def test_fresh_cell_full_plan(self):
        """A fresh cell generates the complete 4-action plan."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState()  # Nothing exists.

        actions = plan_run(spec, actual)
        types = [a.type for a in actions]

        self.assertEqual(types, [
            ActionType.ALLOCATE_SUBNET,
            ActionType.CREATE_NETWORK,
            ActionType.CONNECT_PROXY,
            ActionType.PODMAN_RUN,
        ])

    def test_partial_recovery_network_exists(self):
        """If interrupted after network creation, plan skips to proxy connect."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(network_exists=True, network_internal=True)

        actions = plan_run(spec, actual)
        types = [a.type for a in actions]

        self.assertNotIn(ActionType.ALLOCATE_SUBNET, types)
        self.assertNotIn(ActionType.CREATE_NETWORK, types)
        self.assertIn(ActionType.CONNECT_PROXY, types)
        self.assertIn(ActionType.PODMAN_RUN, types)

    def test_stopped_container_gets_cleaned_up(self):
        """A stopped container from a previous run is removed before re-run."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(exists=True, running=False, network_exists=True, network_internal=True, proxy_connected=True)

        actions = plan_run(spec, actual)
        types = [a.type for a in actions]

        self.assertEqual(types[0], ActionType.PODMAN_RM)
        self.assertEqual(types[-1], ActionType.PODMAN_RUN)


class TestWardenStartCommand(unittest.TestCase):
    """Test that warden start builds the right container command."""

    @patch("warden.proxy.WARDEN_IMAGE_DIGEST", "")
    @patch("warden.proxy.vm_run")
    def test_start_command_has_hardening(self, mock_vm_run):
        """Warden start includes read-only, cap-drop, non-root, resource limits."""
        # Make is_running() return False, container_exists() return False,
        # then capture the podman run command.
        calls = []
        def fake_vm_run(cmd, **kwargs):
            calls.append(cmd)
            # is_running / container_exists checks.
            if "ps" in cmd:
                return subprocess.CompletedProcess([], 0, "\n", "")
            # The actual podman run.
            if cmd[0] == "podman" and cmd[1] == "run":
                return subprocess.CompletedProcess([], 0, "abc123\n", "")
            # network ls for reconnect.
            if "network" in cmd and "ls" in cmd:
                return subprocess.CompletedProcess([], 0, "\n", "")
            return subprocess.CompletedProcess([], 0, "", "")

        mock_vm_run.side_effect = fake_vm_run

        # Pre-flight files need to "exist" — patch Path.exists.
        with patch("warden.proxy.Path.exists", return_value=True), \
             patch("builtins.open", unittest.mock.mock_open(read_data='{"allow":[]}')):
            from warden.proxy import start
            start()

        # Find the podman run command.
        run_cmd = None
        for c in calls:
            if len(c) > 1 and c[0] == "podman" and c[1] == "run":
                run_cmd = c
                break

        self.assertIsNotNone(run_cmd, "podman run was never called")
        cmd_str = " ".join(run_cmd)

        # Hardening flags.
        self.assertIn("--cap-drop", run_cmd)
        self.assertIn("ALL", run_cmd)
        self.assertIn("--read-only", run_cmd)
        self.assertIn("no-new-privileges", cmd_str)
        self.assertIn("--user", run_cmd)
        self.assertIn("mitmproxy", run_cmd)

        # Resource limits.
        self.assertIn("--memory", run_cmd)
        self.assertIn("--cpus", run_cmd)
        self.assertIn("--pids-limit", run_cmd)

        # Required addons.
        self.assertIn("/addons/enforce.py", cmd_str)
        self.assertIn("/addons/logger.py", cmd_str)

        # Runtime is crun (not gVisor — proxy is trusted infrastructure).
        idx = run_cmd.index("--runtime")
        self.assertEqual(run_cmd[idx + 1], "crun")


class TestProxyEnvRejection(unittest.TestCase):
    """Test that all proxy env var forms are rejected."""

    def test_all_15_forms_rejected(self):
        """5 proxy vars × 3 case forms = 15 rejection tests."""
        from brig.errors import BrigError
        rejected = 0
        for var in ["http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy"]:
            for form in [var, var.upper(), var.capitalize()]:
                spec = CellSpec(name="t", image="a", env=[f"{form}=evil"])
                try:
                    build_run_command(spec, "10.60.1.1")
                    self.fail(f"{form} was not rejected")
                except BrigError:
                    rejected += 1
        self.assertEqual(rejected, 15)
