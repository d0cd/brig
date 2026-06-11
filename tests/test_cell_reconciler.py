"""Tests for brig.cell.reconciler — declarative reconciliation engine."""

import unittest

from brig.cell.reconciler import (
    ActionType,
    CellState,
    build_run_command,
    plan_destroy,
    plan_run,
    plan_stop,
)
from brig.cell.spec import CellSpec


class TestPlanRun(unittest.TestCase):
    """Test plan_run() generates correct action sequences."""

    def test_fresh_cell(self):
        """Fresh cell needs: allocate -> create network -> connect proxy -> run."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState()
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertIn(ActionType.ALLOCATE_SUBNET, types)
        self.assertIn(ActionType.CREATE_NETWORK, types)
        self.assertIn(ActionType.CONNECT_PROXY, types)
        self.assertIn(ActionType.PODMAN_RUN, types)

    def test_already_running(self):
        """Already running cell needs no actions."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(exists=True, running=True)
        actions = plan_run(spec, actual)
        self.assertEqual(actions, [])

    def test_network_exists(self):
        """If network exists, skip allocate/create but still connect proxy and run."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(network_exists=True, network_internal=True)
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertNotIn(ActionType.ALLOCATE_SUBNET, types)
        self.assertNotIn(ActionType.CREATE_NETWORK, types)
        self.assertIn(ActionType.CONNECT_PROXY, types)
        self.assertIn(ActionType.PODMAN_RUN, types)

    def test_airgapped_no_proxy_connect(self):
        """Airgapped cell skips proxy connection."""
        spec = CellSpec(name="test", image="alpine", network="none")
        actual = CellState()
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertNotIn(ActionType.CONNECT_PROXY, types)
        self.assertIn(ActionType.PODMAN_RUN, types)

    def test_proxy_already_connected(self):
        """If proxy is already connected, skip CONNECT_PROXY."""
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(network_exists=True, network_internal=True, proxy_connected=True)
        actions = plan_run(spec, actual)
        types = [a.type for a in actions]
        self.assertNotIn(ActionType.CONNECT_PROXY, types)

    def test_non_internal_network_refused(self):
        """Fail closed: a pre-existing same-named network that isn't --internal
        must not be silently adopted — it would break east-west isolation and
        bypass Warden (invariants 1 + 4: the VM network set is untrusted)."""
        from brig.errors import BrigError
        spec = CellSpec(name="test", image="alpine")
        actual = CellState(network_exists=True, network_internal=False,
                           network_name="brig-test")
        with self.assertRaises(BrigError):
            plan_run(spec, actual)


class TestPlanDestroy(unittest.TestCase):
    """Test plan_destroy() generates correct teardown actions."""

    def test_running_cell(self):
        """Running cell: kill -> rm -> disconnect -> remove network -> free subnet."""
        actual = CellState(
            exists=True, running=True,
            network_exists=True, proxy_connected=True,
        )
        actions = plan_destroy("test", actual)
        types = [a.type for a in actions]
        self.assertEqual(types[0], ActionType.PODMAN_KILL)
        self.assertEqual(types[1], ActionType.PODMAN_RM)
        self.assertIn(ActionType.DISCONNECT_PROXY, types)
        self.assertIn(ActionType.REMOVE_NETWORK, types)
        self.assertIn(ActionType.FREE_SUBNET, types)

    def test_stopped_cell(self):
        """Stopped cell: rm -> disconnect -> remove network -> free."""
        actual = CellState(
            exists=True, running=False,
            network_exists=True, proxy_connected=True,
        )
        actions = plan_destroy("test", actual)
        types = [a.type for a in actions]
        self.assertNotIn(ActionType.PODMAN_KILL, types)
        self.assertIn(ActionType.PODMAN_RM, types)

    def test_orphaned_network(self):
        """Network exists but no container: just clean up network."""
        actual = CellState(network_exists=True)
        actions = plan_destroy("test", actual)
        types = [a.type for a in actions]
        self.assertNotIn(ActionType.PODMAN_RM, types)
        self.assertIn(ActionType.REMOVE_NETWORK, types)
        self.assertIn(ActionType.FREE_SUBNET, types)

    def test_nothing_to_destroy(self):
        """Nothing exists: empty plan."""
        actual = CellState()
        actions = plan_destroy("test", actual)
        self.assertEqual(actions, [])


class TestPlanStop(unittest.TestCase):
    def test_running_cell(self):
        actual = CellState(exists=True, running=True)
        actions = plan_stop("test", actual)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].type, ActionType.PODMAN_STOP)

    def test_not_running(self):
        actual = CellState(exists=True, running=False)
        actions = plan_stop("test", actual)
        self.assertEqual(actions, [])


class TestBuildRunCommand(unittest.TestCase):
    """Test build_run_command() — invariant 5: --runtime runsc."""

    def test_runtime_always_runsc(self):
        """Invariant 5: --runtime runsc is always in the command."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--runtime", cmd)
        idx = cmd.index("--runtime")
        self.assertEqual(cmd[idx + 1], "runsc")

    def test_proxy_env_set(self):
        """Proxy env vars are injected for non-airgapped cells."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        cmd_str = " ".join(cmd)
        self.assertIn("http_proxy=http://10.60.1.1:8080", cmd_str)
        self.assertIn("https_proxy=http://10.60.1.1:8080", cmd_str)

    def test_user_emitted_when_set(self):
        spec = CellSpec(name="test", image="alpine", user="0")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--user", cmd)
        self.assertEqual(cmd[cmd.index("--user") + 1], "0")

    def test_user_omitted_by_default(self):
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertNotIn("--user", cmd)

    def test_airgapped_no_proxy(self):
        """Airgapped cells have --network none and no proxy env."""
        spec = CellSpec(name="test", image="alpine", network="none")
        cmd = build_run_command(spec, None)
        cmd_str = " ".join(cmd)
        self.assertIn("--network", cmd)
        self.assertIn("none", cmd)
        self.assertNotIn("http_proxy", cmd_str)

    def test_proxy_env_override_rejected(self):
        """User cannot override proxy env vars."""
        from brig.errors import BrigError
        spec = CellSpec(name="test", image="alpine", env=["http_proxy=evil"])
        with self.assertRaisesRegex(BrigError, "Cannot override proxy"):
            build_run_command(spec, "10.60.1.1")

    def test_all_proxy_env_names_rejected(self):
        """All 5 proxy env var names are rejected."""
        from brig.errors import BrigError
        proxy_vars = ["http_proxy", "https_proxy", "no_proxy", "all_proxy", "ftp_proxy"]
        for var in proxy_vars:
            for form in [var, var.upper(), var.capitalize()]:
                spec = CellSpec(name="test", image="alpine", env=[f"{form}=evil"])
                with self.assertRaises(BrigError, msg=f"{form} should be rejected"):
                    build_run_command(spec, "10.60.1.1")

    def test_security_hardening(self):
        """cap-drop ALL and no-new-privileges are always set."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        self.assertIn("--security-opt", cmd)
        self.assertIn("no-new-privileges", cmd)

    def test_resource_limits(self):
        spec = CellSpec(name="test", image="alpine", memory="1g", cpus="2", pids_limit=256)
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--memory", cmd)
        self.assertIn("1g", cmd)
        self.assertIn("--cpus", cmd)
        self.assertIn("2", cmd)
        self.assertIn("--pids-limit", cmd)
        self.assertIn("256", cmd)

    def test_image_and_command(self):
        spec = CellSpec(name="test", image="alpine", command=["echo", "hi"])
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("alpine", cmd)
        self.assertIn("echo", cmd)
        self.assertIn("hi", cmd)

    def test_end_of_options_separator_precedes_image(self):
        # `--` must immediately precede the image so a dash-leading positional
        # can never be parsed by podman as a flag (defense in depth alongside
        # the validator's leading-dash rejection).
        spec = CellSpec(name="test", image="alpine", command=["echo", "hi"])
        cmd = build_run_command(spec, "10.60.1.1")
        sep = cmd.index("--")
        self.assertEqual(cmd[sep + 1], "alpine")
        self.assertEqual(cmd[sep + 2:], ["echo", "hi"])

    def test_workspace_mount(self):
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        cmd_str = " ".join(cmd)
        self.assertIn("/work:rw", cmd_str)

    def test_readonly_rootfs_by_default(self):
        """Safe-by-default: cells get --read-only rootfs with sized tmpfs
        at /tmp and /run. Closes the DoS-via-writable-layer hole and the
        hidden-persistence-across-stop/start hole."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--read-only", cmd)
        # /tmp tmpfs with size cap.
        tmpfs_pairs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--tmpfs"]
        self.assertTrue(any(t.startswith("/tmp:") and "size=64m" in t
                            for t in tmpfs_pairs),
            f"expected /tmp tmpfs with 64m cap, got --tmpfs values {tmpfs_pairs}")
        # /run tmpfs.
        self.assertTrue(any(t.startswith("/run:") for t in tmpfs_pairs),
            f"expected /run tmpfs, got --tmpfs values {tmpfs_pairs}")

    def test_readonly_tmpfs_has_security_options(self):
        """Sized tmpfs is necessary but not sufficient — also need
        noexec/nosuid/nodev so the cell can't drop a SUID binary in /tmp
        and exec something privileged from there."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        tmpfs_pairs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--tmpfs"]
        for t in tmpfs_pairs:
            self.assertIn("noexec", t, f"{t} missing noexec")
            self.assertIn("nosuid", t, f"{t} missing nosuid")
            self.assertIn("nodev", t, f"{t} missing nodev")

    def test_writable_rootfs_opt_out_omits_readonly(self):
        """For cells whose images legitimately need a writable rootfs
        (legacy daemons, dev images that build at runtime), opt-out via
        writable_rootfs: true. Should skip --read-only entirely and not
        introduce the tmpfs mounts (the cell's own filesystem covers /tmp
        and /run)."""
        spec = CellSpec(name="test", image="alpine", writable_rootfs=True)
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertNotIn("--read-only", cmd)
        # /tmp and /run shouldn't appear in any --tmpfs flag.
        tmpfs_pairs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--tmpfs"]
        for t in tmpfs_pairs:
            self.assertFalse(t.startswith("/tmp:"),
                f"writable_rootfs cell shouldn't get /tmp tmpfs: {t}")
            self.assertFalse(t.startswith("/run:"),
                f"writable_rootfs cell shouldn't get /run tmpfs: {t}")

    def test_workspace_mount_override(self):
        """The new `workspace_mount` field must flow into the podman -v
        argument and -w workdir, not just sit unused on CellSpec."""
        spec = CellSpec(name="test", image="alpine", workspace_mount="/workspace")
        cmd = build_run_command(spec, "10.60.1.1")
        cmd_str = " ".join(cmd)
        self.assertIn(":/workspace:rw", cmd_str)
        # -w /workspace too, so the cell's cwd matches the mount.
        self.assertIn("-w /workspace", cmd_str)
        # Default /work should NOT appear as a mount when overridden.
        self.assertNotIn(":/work:rw", cmd_str)

    def test_user_env_accepted(self):
        """Non-proxy env vars are accepted."""
        spec = CellSpec(name="test", image="alpine", env=["FOO=bar", "BAZ=qux"])
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("FOO=bar", cmd)
        self.assertIn("BAZ=qux", cmd)
