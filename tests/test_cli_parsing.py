"""Tests for brig.cli — CLI argument parsing for all commands."""

import unittest

from brig.cli import _build_parser


class TestBrigCliParsing(unittest.TestCase):
    """Test that the CLI parser accepts expected arguments."""

    def setUp(self):
        self.parser = _build_parser()

    # --- Lifecycle ---

    def test_run(self):
        args = self.parser.parse_args(["run", "--name", "test", "alpine", "echo", "hi"])
        self.assertEqual(args.command, "run")
        self.assertEqual(args.name, "test")
        self.assertEqual(args.image, "alpine")
        self.assertEqual(args.container_cmd, ["echo", "hi"])

    def test_run_with_profile_and_env(self):
        args = self.parser.parse_args([
            "run", "--name", "t", "--profile", "untrusted", "-e", "FOO=bar", "-d", "alpine",
        ])
        self.assertEqual(args.profile, "untrusted")
        self.assertEqual(args.env, ["FOO=bar"])
        self.assertTrue(args.detach)

    def test_stop(self):
        args = self.parser.parse_args(["stop", "mycell"])
        self.assertEqual(args.command, "stop")
        self.assertEqual(args.name, "mycell")

    def test_kill(self):
        args = self.parser.parse_args(["kill", "mycell"])
        self.assertEqual(args.command, "kill")

    def test_rm_force(self):
        args = self.parser.parse_args(["rm", "-f", "mycell"])
        self.assertTrue(args.force)

    def test_start(self):
        args = self.parser.parse_args(["start", "mycell"])
        self.assertEqual(args.command, "start")

    def test_pause(self):
        args = self.parser.parse_args(["pause", "mycell"])
        self.assertEqual(args.command, "pause")

    def test_unpause(self):
        args = self.parser.parse_args(["unpause", "mycell"])
        self.assertEqual(args.command, "unpause")

    def test_wait(self):
        args = self.parser.parse_args(["wait", "mycell"])
        self.assertEqual(args.command, "wait")

    def test_exec(self):
        args = self.parser.parse_args(["exec", "mycell", "ls", "-la"])
        self.assertEqual(args.command, "exec")
        self.assertEqual(args.exec_cmd, ["ls", "-la"])

    def test_shell(self):
        args = self.parser.parse_args(["shell", "mycell"])
        self.assertEqual(args.command, "shell")

    def test_attach(self):
        args = self.parser.parse_args(["attach", "mycell"])
        self.assertEqual(args.command, "attach")

    def test_rename(self):
        args = self.parser.parse_args(["rename", "old", "new"])
        self.assertEqual(args.old_name, "old")
        self.assertEqual(args.new_name, "new")

    def test_list_json(self):
        args = self.parser.parse_args(["list", "--format", "json"])
        self.assertEqual(args.format, "json")

    # --- Info ---

    def test_inspect(self):
        args = self.parser.parse_args(["inspect", "mycell"])
        self.assertEqual(args.command, "inspect")

    def test_logs_follow(self):
        args = self.parser.parse_args(["logs", "mycell", "-f", "--tail", "50"])
        self.assertTrue(args.follow)
        self.assertEqual(args.tail, 50)

    def test_top(self):
        args = self.parser.parse_args(["top", "mycell"])
        self.assertEqual(args.command, "top")

    def test_diff(self):
        args = self.parser.parse_args(["diff", "mycell"])
        self.assertEqual(args.command, "diff")

    def test_stats(self):
        args = self.parser.parse_args(["stats"])
        self.assertEqual(args.command, "stats")

    def test_export(self):
        args = self.parser.parse_args(["export", "mycell"])
        self.assertEqual(args.command, "export")

    # --- Workspace ---

    def test_cp(self):
        args = self.parser.parse_args(["cp", "src", "dst"])
        self.assertEqual(args.src, "src")

    # --- Network/Events ---

    def test_network(self):
        args = self.parser.parse_args(["network", "mycell"])
        self.assertEqual(args.command, "network")

    def test_events(self):
        args = self.parser.parse_args(["events", "--tail", "10"])
        self.assertEqual(args.command, "events")

    # --- Image ---

    def test_pull(self):
        args = self.parser.parse_args(["pull", "alpine:latest"])
        self.assertEqual(args.image, "alpine:latest")

    def test_warmup(self):
        args = self.parser.parse_args(["warmup", "--profile", "dev"])
        self.assertEqual(args.profile, "dev")

    def test_image_verify(self):
        args = self.parser.parse_args(["image-verify", "myimage:latest"])
        self.assertEqual(args.command, "image-verify")


    # --- System ---

    def test_init(self):
        args = self.parser.parse_args(["init"])
        self.assertEqual(args.command, "init")

    def test_verify_fix(self):
        args = self.parser.parse_args(["verify", "--fix"])
        self.assertTrue(args.fix)

    def test_health(self):
        args = self.parser.parse_args(["health"])
        self.assertEqual(args.command, "health")

    def test_diagnose(self):
        args = self.parser.parse_args(["diagnose", "mycell"])
        self.assertEqual(args.command, "diagnose")

    def test_preflight(self):
        args = self.parser.parse_args(["preflight"])
        self.assertEqual(args.command, "preflight")

    def test_metrics(self):
        args = self.parser.parse_args(["metrics"])
        self.assertEqual(args.command, "metrics")

    def test_history(self):
        args = self.parser.parse_args(["history", "--tail", "50", "--cell", "mycell"])
        self.assertEqual(args.tail, 50)
        self.assertEqual(args.cell, "mycell")

    def test_upgrade(self):
        args = self.parser.parse_args(["upgrade"])
        self.assertEqual(args.command, "upgrade")

    # --- Policy ---

    def test_policy_show(self):
        args = self.parser.parse_args(["policy", "show", "mycell"])
        self.assertEqual(args.policy_command, "show")

    def test_policy_set(self):
        args = self.parser.parse_args([
            "policy", "set", "mycell", "--allow", "example.com", "--deny", "evil.com",
        ])
        self.assertEqual(args.allow, ["example.com"])
        self.assertEqual(args.deny, ["evil.com"])

    # --- Config ---

    def test_config_show(self):
        args = self.parser.parse_args(["config", "show"])
        self.assertEqual(args.config_command, "show")

    def test_config_set(self):
        args = self.parser.parse_args(["config", "set", "log.level", "debug"])
        self.assertEqual(args.key, "log.level")
        self.assertEqual(args.value, "debug")

    def test_config_reset(self):
        args = self.parser.parse_args(["config", "reset"])
        self.assertEqual(args.config_command, "reset")

    # --- Global flags ---

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_debug(self):
        args = self.parser.parse_args(["--debug", "list"])
        self.assertTrue(args.debug)

    def test_quiet(self):
        args = self.parser.parse_args(["--quiet", "list"])
        self.assertTrue(args.quiet)
