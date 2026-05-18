"""Tests for brig.cli — CLI argument parsing for all commands.

Since 0.3.0 the CLI uses noun-verb grouping: `brig cell stop foo` instead
of `brig stop foo`. Top-level `brig run` is the only flat primary verb.
"""

import unittest

from brig.cli import _build_parser


class TestBrigCliParsing(unittest.TestCase):
    """Test that the CLI parser accepts expected arguments."""

    def setUp(self):
        self.parser = _build_parser()

    # --- brig run (the only flat primary verb) ------------------------------

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

    # --- brig cell <verb> ---------------------------------------------------

    def test_cell_stop(self):
        args = self.parser.parse_args(["cell", "stop", "mycell"])
        self.assertEqual(args.command, "cell")
        self.assertEqual(args.cell_command, "stop")
        self.assertEqual(args.name, "mycell")

    def test_cell_kill(self):
        args = self.parser.parse_args(["cell", "kill", "mycell"])
        self.assertEqual(args.cell_command, "kill")

    def test_cell_rm_force(self):
        args = self.parser.parse_args(["cell", "rm", "-f", "mycell"])
        self.assertTrue(args.force)
        self.assertEqual(args.cell_command, "rm")

    def test_cell_start(self):
        args = self.parser.parse_args(["cell", "start", "mycell"])
        self.assertEqual(args.cell_command, "start")

    def test_cell_pause_unpause(self):
        for verb in ("pause", "unpause"):
            args = self.parser.parse_args(["cell", verb, "mycell"])
            self.assertEqual(args.cell_command, verb)

    def test_cell_wait(self):
        args = self.parser.parse_args(["cell", "wait", "mycell"])
        self.assertEqual(args.cell_command, "wait")

    def test_cell_exec(self):
        args = self.parser.parse_args(["cell", "exec", "mycell", "ls", "-la"])
        self.assertEqual(args.cell_command, "exec")
        self.assertEqual(args.exec_cmd, ["ls", "-la"])

    def test_cell_shell(self):
        args = self.parser.parse_args(["cell", "shell", "mycell"])
        self.assertEqual(args.cell_command, "shell")

    def test_cell_attach(self):
        args = self.parser.parse_args(["cell", "attach", "mycell"])
        self.assertEqual(args.cell_command, "attach")

    def test_cell_rename(self):
        args = self.parser.parse_args(["cell", "rename", "old", "new"])
        self.assertEqual(args.cell_command, "rename")
        self.assertEqual(args.old_name, "old")
        self.assertEqual(args.new_name, "new")

    def test_cell_list_json(self):
        args = self.parser.parse_args(["cell", "list", "--format", "json"])
        self.assertEqual(args.format, "json")

    def test_cell_inspect(self):
        args = self.parser.parse_args(["cell", "inspect", "mycell"])
        self.assertEqual(args.cell_command, "inspect")

    def test_cell_diagnose(self):
        args = self.parser.parse_args(["cell", "diagnose", "mycell"])
        self.assertEqual(args.cell_command, "diagnose")

    def test_cell_logs_follow(self):
        args = self.parser.parse_args(["cell", "logs", "mycell", "-f", "--tail", "50"])
        self.assertTrue(args.follow)
        self.assertEqual(args.tail, 50)

    def test_cell_top_diff_stats(self):
        for verb in ("top", "diff"):
            args = self.parser.parse_args(["cell", verb, "mycell"])
            self.assertEqual(args.cell_command, verb)
        args = self.parser.parse_args(["cell", "stats"])
        self.assertEqual(args.cell_command, "stats")

    def test_cell_export(self):
        args = self.parser.parse_args(["cell", "export", "mycell"])
        self.assertEqual(args.cell_command, "export")

    def test_cell_cp(self):
        args = self.parser.parse_args(["cell", "cp", "src", "dst"])
        self.assertEqual(args.src, "src")

    def test_cell_network(self):
        args = self.parser.parse_args(["cell", "network", "mycell"])
        self.assertEqual(args.cell_command, "network")

    def test_cell_network_blocked(self):
        args = self.parser.parse_args(["cell", "network", "mycell", "--blocked"])
        self.assertTrue(args.blocked)

    def test_cell_events(self):
        args = self.parser.parse_args(["cell", "events", "--tail", "10"])
        self.assertEqual(args.cell_command, "events")

    def test_cell_events_follow(self):
        args = self.parser.parse_args(["cell", "events", "-f"])
        self.assertTrue(args.follow)

    # --- brig image <verb> --------------------------------------------------

    def test_image_build(self):
        args = self.parser.parse_args(["image", "build", "cells/foo"])
        self.assertEqual(args.command, "image")
        self.assertEqual(args.image_command, "build")
        self.assertEqual(args.context, "cells/foo")

    def test_image_build_with_flags(self):
        args = self.parser.parse_args([
            "image", "build", "ctx", "-t", "myimg:dev",
            "-f", "Containerfile", "--build-arg", "K=V",
        ])
        self.assertEqual(args.tag, "myimg:dev")
        self.assertEqual(args.file, "Containerfile")
        self.assertEqual(args.build_arg, ["K=V"])

    def test_image_pull(self):
        args = self.parser.parse_args(["image", "pull", "alpine:latest"])
        self.assertEqual(args.image, "alpine:latest")

    def test_image_verify(self):
        args = self.parser.parse_args([
            "image", "verify", "myimage:latest", "--keyless",
        ])
        self.assertEqual(args.image_command, "verify")
        self.assertTrue(args.keyless)

    def test_image_warmup(self):
        args = self.parser.parse_args(["image", "warmup", "--profile", "dev"])
        self.assertEqual(args.profile, "dev")

    # --- brig system <verb> -------------------------------------------------

    def test_system_init(self):
        args = self.parser.parse_args(["system", "init"])
        self.assertEqual(args.system_command, "init")

    def test_system_up(self):
        args = self.parser.parse_args(["system", "up"])
        self.assertEqual(args.system_command, "up")

    def test_system_down_vm(self):
        args = self.parser.parse_args(["system", "down", "--vm"])
        self.assertTrue(args.vm)

    def test_system_doctor(self):
        args = self.parser.parse_args(["system", "doctor"])
        self.assertEqual(args.system_command, "doctor")
        self.assertFalse(args.quick)

    def test_system_doctor_quick(self):
        args = self.parser.parse_args(["system", "doctor", "--quick"])
        self.assertTrue(args.quick)

    def test_system_verify_fix(self):
        args = self.parser.parse_args(["system", "verify", "--fix"])
        self.assertTrue(args.fix)

    def test_system_preflight(self):
        args = self.parser.parse_args(["system", "preflight"])
        self.assertEqual(args.system_command, "preflight")

    def test_system_metrics(self):
        args = self.parser.parse_args(["system", "metrics"])
        self.assertEqual(args.system_command, "metrics")

    def test_system_prune_flags(self):
        args = self.parser.parse_args([
            "system", "prune", "--logs", "--log-days", "3", "-n",
        ])
        self.assertTrue(args.logs)
        self.assertEqual(args.log_days, 3)
        self.assertTrue(args.dry_run)

    def test_system_profiles(self):
        args = self.parser.parse_args(["system", "profiles"])
        self.assertEqual(args.system_command, "profiles")

    def test_system_watchdog(self):
        args = self.parser.parse_args([
            "system", "watchdog", "--interval", "10", "--max-restarts", "3",
        ])
        self.assertEqual(args.interval, 10)
        self.assertEqual(args.max_restarts, 3)

    def test_system_history(self):
        args = self.parser.parse_args([
            "system", "history", "--tail", "50", "--cell", "mycell",
        ])
        self.assertEqual(args.tail, 50)
        self.assertEqual(args.cell, "mycell")

    # --- Existing groups (unchanged): policy / config / secrets -------------

    def test_policy_show(self):
        args = self.parser.parse_args(["policy", "show", "mycell"])
        self.assertEqual(args.policy_command, "show")

    def test_policy_set(self):
        args = self.parser.parse_args([
            "policy", "set", "mycell", "--allow", "example.com", "--deny", "evil.com",
        ])
        self.assertEqual(args.allow, ["example.com"])
        self.assertEqual(args.deny, ["evil.com"])

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

    # --- Hard-rename regression guards: old flat names must fail -----------

    def test_old_flat_stop_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["stop", "mycell"])

    def test_old_flat_up_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["up"])

    def test_old_flat_pull_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["pull", "alpine"])

    def test_old_flat_health_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["health"])

    def test_old_flat_image_verify_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["image-verify", "img"])

    # --- Global flags -------------------------------------------------------

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            self.parser.parse_args(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_debug(self):
        args = self.parser.parse_args(["--debug", "cell", "list"])
        self.assertTrue(args.debug)

    def test_quiet(self):
        args = self.parser.parse_args(["--quiet", "cell", "list"])
        self.assertTrue(args.quiet)
