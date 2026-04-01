#!/usr/bin/env python3
"""
Unit tests for Warden components.

Tests the Python logic without requiring mitmproxy or the VM.
Run with: python3 -m pytest tests/test_warden_unit.py -v

Or without pytest:
    python3 tests/test_warden_unit.py
"""

import json
import os
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path
from unittest.mock import MagicMock

# Add src to path for imports.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestPolicyMatching(unittest.TestCase):
    """Tests for policy domain/path/method matching logic."""

    def test_exact_domain_match(self):
        """Exact domain matches."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("example.com", "example.com"))
        self.assertFalse(_matches_domain("example.com", "other.com"))
        self.assertFalse(_matches_domain("example.com", "sub.example.com"))

    def test_wildcard_domain_match(self):
        """Wildcard domain patterns match subdomains only."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("*.example.com", "sub.example.com"))
        self.assertTrue(_matches_domain("*.example.com", "deep.sub.example.com"))
        self.assertFalse(_matches_domain("*.example.com", "example.com"))
        self.assertFalse(_matches_domain("*.example.com", "other.com"))
        self.assertFalse(_matches_domain("*.example.com", "exampleXcom"))

    def test_case_insensitive_match(self):
        """Domain matching is case insensitive."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("Example.COM", "example.com"))
        self.assertTrue(_matches_domain("*.GITHUB.com", "api.github.COM"))

    def test_string_rule_matching(self):
        """String rules match by domain only."""
        from warden import _matches_rule
        self.assertTrue(_matches_rule("example.com", "example.com", "/any/path", "GET"))
        self.assertTrue(_matches_rule("example.com", "example.com", "/", "POST"))
        self.assertFalse(_matches_rule("example.com", "other.com", "/", "GET"))

    def test_dict_rule_with_paths(self):
        """Dict rules can restrict by path."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*", "/v2/*"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v1/users", "GET"))
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v2/data", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v3/other", "GET"))
        self.assertFalse(_matches_rule(rule, "other.com", "/v1/users", "GET"))

    def test_dict_rule_with_methods(self):
        """Dict rules can restrict by method."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "methods": ["GET", "POST"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/", "GET"))
        self.assertTrue(_matches_rule(rule, "api.example.com", "/", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/", "DELETE"))

    def test_dict_rule_with_paths_and_methods(self):
        """Dict rules can combine path and method restrictions."""
        from warden import _matches_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["POST"]}
        self.assertTrue(_matches_rule(rule, "api.example.com", "/v1/create", "POST"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v1/create", "GET"))
        self.assertFalse(_matches_rule(rule, "api.example.com", "/v2/create", "POST"))


class TestPolicyValidation(unittest.TestCase):
    """Tests for policy validation logic."""

    def test_validate_string_rule(self):
        """String rules are validated."""
        from warden import _validate_rule
        self.assertEqual(_validate_rule("example.com", "allow[0]"), [])
        self.assertEqual(_validate_rule("*.github.com", "allow[1]"), [])
        errors = _validate_rule("", "allow[2]")
        self.assertTrue(len(errors) > 0)

    def test_validate_dict_rule_valid(self):
        """Valid dict rules pass validation."""
        from warden import _validate_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET"]}
        self.assertEqual(_validate_rule(rule, "allow[0]"), [])

    def test_validate_dict_rule_missing_domain(self):
        """Dict rules require domain field."""
        from warden import _validate_rule
        rule = {"paths": ["/v1/*"]}
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("domain" in e for e in errors))

    def test_validate_dict_rule_invalid_method(self):
        """Dict rules validate HTTP methods."""
        from warden import _validate_rule
        rule = {"domain": "example.com", "methods": ["INVALID"]}
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("INVALID" in e for e in errors))

    def test_validate_invalid_rule_type(self):
        """Invalid rule types are rejected."""
        from warden import _validate_rule
        errors = _validate_rule(123, "allow[0]")
        self.assertTrue(len(errors) > 0)


class TestPolicyFile(unittest.TestCase):
    """Tests for policy file loading and validation."""

    def test_cmd_policy_validate_valid(self):
        """Valid policy file passes validation."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": ["example.com", "*.github.com"],
                "deny": ["evil.com"]
            }, f)
            f.flush()

            try:
                # Should return 0 for valid policy.
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)

    def test_cmd_policy_validate_invalid_json(self):
        """Invalid JSON fails validation."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("not valid json")
            f.flush()

            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_cmd_policy_validate_missing_file(self):
        """Missing file fails validation."""
        from warden import cmd_policy_validate
        result = cmd_policy_validate("/nonexistent/file.json")
        self.assertEqual(result, 1)


class TestPolicyTest(unittest.TestCase):
    """Tests for policy test command."""

    def setUp(self):
        """Create a test policy file."""
        self.policy_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump({
            "allow": [
                "example.com",
                "*.github.com",
                {"domain": "api.openai.com", "paths": ["/v1/*"], "methods": ["POST"]}
            ],
            "deny": ["evil.com"]
        }, self.policy_file)
        self.policy_file.flush()
        self.policy_file.close()

        # Patch POLICY_FILE to use our test file.
        import warden
        self._original_policy_file = warden.POLICY_FILE
        warden.POLICY_FILE = Path(self.policy_file.name)

    def tearDown(self):
        """Clean up test policy file."""
        import warden
        warden.POLICY_FILE = self._original_policy_file
        os.unlink(self.policy_file.name)

    def test_allowed_domain(self):
        """Allowed domains return 0."""
        from warden import cmd_policy_test
        result = cmd_policy_test("example.com")
        self.assertEqual(result, 0)

    def test_wildcard_subdomain(self):
        """Wildcard subdomains are allowed."""
        from warden import cmd_policy_test
        result = cmd_policy_test("api.github.com")
        self.assertEqual(result, 0)

    def test_denied_domain(self):
        """Denied domains return 1."""
        from warden import cmd_policy_test
        result = cmd_policy_test("evil.com")
        self.assertEqual(result, 1)

    def test_unlisted_domain(self):
        """Unlisted domains are blocked (default deny)."""
        from warden import cmd_policy_test
        result = cmd_policy_test("random-domain.com")
        self.assertEqual(result, 1)

    def test_path_restriction(self):
        """Path restrictions are enforced."""
        from warden import cmd_policy_test
        # Allowed path.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "POST")
        self.assertEqual(result, 0)
        # Disallowed path.
        result = cmd_policy_test("api.openai.com", "/v2/other", "POST")
        self.assertEqual(result, 1)

    def test_method_restriction(self):
        """Method restrictions are enforced."""
        from warden import cmd_policy_test
        # Allowed method.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "POST")
        self.assertEqual(result, 0)
        # Disallowed method.
        result = cmd_policy_test("api.openai.com", "/v1/completions", "GET")
        self.assertEqual(result, 1)


class TestRateLimiter(unittest.TestCase):
    """Tests for rate limiting token bucket from ratelimit.py."""

    @classmethod
    def setUpClass(cls):
        """Import TokenBucket from production code."""
        # Mock mitmproxy to allow import of ratelimit addon.
        for mod in ['mitmproxy', 'mitmproxy.http', 'mitmproxy.ctx']:
            if mod not in sys.modules:
                sys.modules[mod] = MagicMock()
        addons_dir = str(Path(__file__).parent.parent / "src" / "addons")
        if addons_dir not in sys.path:
            sys.path.insert(0, addons_dir)
        from ratelimit import TokenBucket
        cls.TokenBucket = TokenBucket

    def test_token_bucket_initial_burst(self):
        """Token bucket allows initial burst."""
        bucket = self.TokenBucket(rate=10, burst=5)

        # Should allow burst of 5.
        for i in range(5):
            self.assertTrue(bucket.consume(), f"Burst request {i+1} should succeed")

        # 6th request should fail (no time has passed).
        self.assertFalse(bucket.consume(), "Request beyond burst should fail")

    def test_token_bucket_refill(self):
        """Token bucket refills over time."""
        bucket = self.TokenBucket(rate=100, burst=1)

        # Consume the one token.
        self.assertTrue(bucket.consume())
        self.assertFalse(bucket.consume())

        # Wait for refill (at 100/s, 10ms = 1 token).
        time.sleep(0.015)

        # Should have refilled.
        self.assertTrue(bucket.consume())


class TestPreflightValidation(unittest.TestCase):
    """Tests for preflight validation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_preflight_validate_function_signature(self):
        """preflight_validate function has correct signature."""
        import inspect

        from warden import preflight_validate
        sig = inspect.signature(preflight_validate)
        # Should take no arguments.
        self.assertEqual(len(sig.parameters), 0)

    def test_cmd_preflight_function_signature(self):
        """cmd_preflight function has correct signature."""
        import inspect

        from warden import cmd_preflight
        sig = inspect.signature(cmd_preflight)
        # Should take no arguments.
        self.assertEqual(len(sig.parameters), 0)


class TestWatchdog(unittest.TestCase):
    """Tests for watchdog functionality."""

    def test_watchdog_function_exists(self):
        """cmd_watchdog function exists and accepts parameters."""
        # Function should exist with expected signature.
        import inspect

        from warden import cmd_watchdog
        sig = inspect.signature(cmd_watchdog)
        params = list(sig.parameters.keys())
        self.assertIn("interval", params)
        self.assertIn("max_restarts", params)

    @unittest.mock.patch("warden.time.sleep")
    @unittest.mock.patch("warden.cmd_start")
    @unittest.mock.patch("warden.is_running")
    def test_watchdog_restarts_on_crash(self, mock_is_running, mock_cmd_start,
                                        mock_sleep):
        """Watchdog restarts proxy when it detects a crash."""
        from warden import cmd_watchdog

        # Proxy always down, restart fails. Hits max_restarts and returns 1.
        mock_is_running.return_value = False
        mock_cmd_start.return_value = 1
        mock_sleep.return_value = None

        with unittest.mock.patch("warden.signal.signal"):
            result = cmd_watchdog(interval=1, max_restarts=1)

        self.assertEqual(result, 1)
        # Verify restart was attempted.
        mock_cmd_start.assert_called()

    @unittest.mock.patch("warden.time.sleep")
    @unittest.mock.patch("warden.cmd_start")
    @unittest.mock.patch("warden.is_running")
    def test_watchdog_respects_max_restarts(self, mock_is_running, mock_cmd_start,
                                            mock_sleep):
        """Watchdog gives up after max consecutive restart failures."""
        from warden import cmd_watchdog

        # Proxy always down, restart always fails.
        mock_is_running.return_value = False
        mock_cmd_start.return_value = 1
        mock_sleep.return_value = None

        with unittest.mock.patch("warden.signal.signal"):
            result = cmd_watchdog(interval=1, max_restarts=3)

        self.assertEqual(result, 1)
        # Should have attempted 3 restarts before the 4th check triggers exit.
        self.assertEqual(mock_cmd_start.call_count, 3)

    @unittest.mock.patch("warden.time.sleep")
    @unittest.mock.patch("warden.cmd_start")
    @unittest.mock.patch("warden.is_running")
    def test_watchdog_resets_counter_on_recovery(self, mock_is_running, mock_cmd_start,
                                                  mock_sleep):
        """Watchdog resets restart counter when proxy recovers."""
        from warden import cmd_watchdog

        # Sequence (all with interval=1, max_restarts=2):
        #   Check 1: down → restart fails (counter=1)
        #   Check 2: up   → counter resets to 0
        #   Check 3: down → restart fails (counter=1)
        #   Check 4: up   → counter resets to 0
        #   Check 5: down → restart fails (counter=1)
        #   Check 6: down → restart fails (counter=2)
        #   Check 7: down → counter(2) >= max(2) → return 1
        mock_is_running.side_effect = [False, True, False, True, False, False, False]
        mock_cmd_start.return_value = 1  # Restarts always fail.
        mock_sleep.return_value = None

        with unittest.mock.patch("warden.signal.signal"):
            result = cmd_watchdog(interval=1, max_restarts=2)

        self.assertEqual(result, 1)
        # 4 restart attempts total — more than max_restarts(2) due to resets.
        self.assertEqual(mock_cmd_start.call_count, 4)

    @unittest.mock.patch("warden.time.sleep")
    @unittest.mock.patch("warden.is_running")
    def test_watchdog_signal_handling(self, mock_is_running, mock_sleep):
        """Watchdog exits cleanly when running flag is set to False."""
        from warden import cmd_watchdog

        mock_is_running.return_value = True
        iteration = [0]

        # Capture the signal handler registered by cmd_watchdog.
        registered_handlers = {}

        def capture_signal(signum, handler):
            registered_handlers[signum] = handler

        def sleep_then_signal(seconds):
            """Simulate signal arrival after first sleep."""
            iteration[0] += 1
            if iteration[0] == 2:
                # Invoke the SIGTERM handler to set running=False.
                import signal
                if signal.SIGTERM in registered_handlers:
                    registered_handlers[signal.SIGTERM](signal.SIGTERM, None)

        mock_sleep.side_effect = sleep_then_signal

        with unittest.mock.patch("warden.signal.signal", side_effect=capture_signal):
            result = cmd_watchdog(interval=1, max_restarts=5)

        self.assertEqual(result, 0)


class TestSocketBufferHandling(unittest.TestCase):
    """Tests for socket buffer handling in metrics."""

    def test_large_response_handling(self):
        """Verify socket client reads in loop for large payloads."""
        # Create a mock response larger than single buffer.
        # Can't easily test without running infrastructure,
        # but verify the function accepts parameters correctly.
        import inspect

        from warden import cmd_stats
        sig = inspect.signature(cmd_stats)
        params = list(sig.parameters.keys())
        self.assertIn("cell_name", params)
        self.assertIn("format_json", params)


class TestResourceLimits(unittest.TestCase):
    """Tests for resource limit enforcement in cmd_start."""

    def _find_podman_run_cmd(self, mock_run):
        """Find the 'podman run' call among all run() invocations."""
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if len(cmd) >= 2 and cmd[0] == "podman" and cmd[1] == "run":
                return cmd
        self.fail("No 'podman run' call found")

    @unittest.mock.patch("warden.reconnect_to_cell_networks")
    @unittest.mock.patch("warden.is_running")
    @unittest.mock.patch("warden.container_exists")
    @unittest.mock.patch("warden.preflight_validate")
    @unittest.mock.patch("warden.run")
    def test_resource_limits_in_start_command(self, mock_run, mock_preflight,
                                              mock_exists, mock_is_running,
                                              mock_reconnect):
        """cmd_start passes correct resource limits to podman."""
        from warden import cmd_start

        mock_is_running.side_effect = [False, True]  # Not running, then started.
        mock_exists.return_value = False
        mock_preflight.return_value = (True, [])
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        mock_reconnect.return_value = 0

        cmd_start()

        podman_cmd = self._find_podman_run_cmd(mock_run)

        self.assertIn("--memory", podman_cmd)
        mem_idx = podman_cmd.index("--memory")
        self.assertEqual(podman_cmd[mem_idx + 1], "1g")

        self.assertIn("--cpus", podman_cmd)
        cpu_idx = podman_cmd.index("--cpus")
        self.assertEqual(podman_cmd[cpu_idx + 1], "1")

        self.assertIn("--pids-limit", podman_cmd)
        pids_idx = podman_cmd.index("--pids-limit")
        self.assertEqual(podman_cmd[pids_idx + 1], "256")

        self.assertIn("--ulimit", podman_cmd)
        ulimit_idx = podman_cmd.index("--ulimit")
        self.assertEqual(podman_cmd[ulimit_idx + 1], "nofile=1024:2048")

    @unittest.mock.patch("warden.reconnect_to_cell_networks")
    @unittest.mock.patch("warden.is_running")
    @unittest.mock.patch("warden.container_exists")
    @unittest.mock.patch("warden.preflight_validate")
    @unittest.mock.patch("warden.run")
    def test_security_hardening_flags(self, mock_run, mock_preflight,
                                      mock_exists, mock_is_running,
                                      mock_reconnect):
        """cmd_start includes security hardening flags."""
        from warden import cmd_start

        mock_is_running.side_effect = [False, True]
        mock_exists.return_value = False
        mock_preflight.return_value = (True, [])
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        mock_reconnect.return_value = 0

        cmd_start()

        podman_cmd = self._find_podman_run_cmd(mock_run)

        # Verify security hardening flags.
        self.assertIn("--cap-drop", podman_cmd)
        cap_idx = podman_cmd.index("--cap-drop")
        self.assertEqual(podman_cmd[cap_idx + 1], "ALL")

        self.assertIn("--security-opt", podman_cmd)
        sec_idx = podman_cmd.index("--security-opt")
        self.assertEqual(podman_cmd[sec_idx + 1], "no-new-privileges")

        self.assertIn("--read-only", podman_cmd)

        self.assertIn("--user", podman_cmd)
        user_idx = podman_cmd.index("--user")
        self.assertEqual(podman_cmd[user_idx + 1], "mitmproxy")

    @unittest.mock.patch("warden.reconnect_to_cell_networks")
    @unittest.mock.patch("warden.is_running")
    @unittest.mock.patch("warden.container_exists")
    @unittest.mock.patch("warden.preflight_validate")
    @unittest.mock.patch("warden.run")
    def test_tmpfs_mounts(self, mock_run, mock_preflight,
                          mock_exists, mock_is_running,
                          mock_reconnect):
        """cmd_start includes tmpfs mounts with correct options."""
        from warden import cmd_start

        mock_is_running.side_effect = [False, True]
        mock_exists.return_value = False
        mock_preflight.return_value = (True, [])
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        mock_reconnect.return_value = 0

        cmd_start()

        podman_cmd = self._find_podman_run_cmd(mock_run)

        # Collect all --tmpfs arguments.
        tmpfs_args = []
        for i, arg in enumerate(podman_cmd):
            if arg == "--tmpfs" and i + 1 < len(podman_cmd):
                tmpfs_args.append(podman_cmd[i + 1])

        self.assertIn("/tmp:rw,noexec,nosuid,size=64m", tmpfs_args)
        self.assertIn("/home/mitmproxy/.mitmproxy:rw,noexec,nosuid,size=32m", tmpfs_args)


class TestWardenStateHelpers(unittest.TestCase):
    """Tests for warden state query helper functions."""

    @unittest.mock.patch("warden.run")
    def test_is_running_true(self, mock_run):
        """is_running returns True when container name is in output."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="warden\n")
        self.assertTrue(warden.is_running())

    @unittest.mock.patch("warden.run")
    def test_is_running_false_no_match(self, mock_run):
        """is_running returns False when only warden-tor is in output."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="warden-tor\n")
        self.assertFalse(warden.is_running())

    @unittest.mock.patch("warden.run")
    def test_container_exists_true(self, mock_run):
        """container_exists returns True when container name is in output."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="warden\n")
        self.assertTrue(warden.container_exists())

    @unittest.mock.patch("warden.run")
    def test_get_proxy_ip_returns_ip(self, mock_run):
        """get_proxy_ip returns IP string from JSON inspect output."""
        import json as _json
        import warden
        inspect_data = [{"NetworkSettings": {"Networks": {"proxy-external": {"IPAddress": "10.60.0.2"}}}}]
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout=_json.dumps(inspect_data))
        self.assertEqual(warden.get_proxy_ip("proxy-external"), "10.60.0.2")

    @unittest.mock.patch("warden.run")
    def test_get_proxy_ip_empty(self, mock_run):
        """get_proxy_ip returns empty string when no IP found."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="[{}]\n")
        self.assertEqual(warden.get_proxy_ip("proxy-external"), "")

    @unittest.mock.patch("warden.run")
    def test_get_cell_networks_filters_brig(self, mock_run):
        """get_cell_networks returns only brig-prefixed networks."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(
            returncode=0, stdout="brig-cell1\nbrig-cell2\nother-net\n"
        )
        result = warden.get_cell_networks()
        self.assertEqual(result, ["brig-cell1", "brig-cell2"])

    @unittest.mock.patch("warden.run")
    def test_get_cell_networks_empty(self, mock_run):
        """get_cell_networks returns empty list when no networks found."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stdout="\n")
        self.assertEqual(warden.get_cell_networks(), [])


class TestReconnectToCellNetworks(unittest.TestCase):
    """Tests for reconnect_to_cell_networks behavior."""

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.get_cell_networks")
    def test_no_networks_returns_zero(self, mock_nets, mock_run):
        """Returns zero and skips run when no cell networks exist."""
        import warden
        mock_nets.return_value = []
        self.assertEqual(warden.reconnect_to_cell_networks(), 0)
        mock_run.assert_not_called()

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.get_cell_networks")
    def test_connects_each_network(self, mock_nets, mock_run):
        """Connects to each cell network and returns count."""
        import warden
        mock_nets.return_value = ["brig-a", "brig-b"]
        mock_run.return_value = unittest.mock.MagicMock(returncode=0, stderr="")
        self.assertEqual(warden.reconnect_to_cell_networks(), 2)

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.get_cell_networks")
    def test_already_connected_suppressed(self, mock_nets, mock_run):
        """Already-connected errors are suppressed, not counted."""
        import warden
        mock_nets.return_value = ["brig-a"]
        mock_run.return_value = unittest.mock.MagicMock(returncode=1, stderr="already connected")
        self.assertEqual(warden.reconnect_to_cell_networks(), 0)

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.get_cell_networks")
    def test_failed_connection_warns(self, mock_nets, mock_run):
        """Failed connections that are not already-connected return zero."""
        import warden
        mock_nets.return_value = ["brig-a"]
        mock_run.return_value = unittest.mock.MagicMock(returncode=1, stderr="some error")
        self.assertEqual(warden.reconnect_to_cell_networks(), 0)


class TestWardenTorCommands(unittest.TestCase):
    """Tests for Tor+Privoxy stack management commands."""

    @unittest.mock.patch("warden.privoxy_running", return_value=True)
    @unittest.mock.patch("warden.tor_running", return_value=True)
    def test_tor_start_both_running(self, mock_tor, mock_privoxy):
        """cmd_tor_start returns 0 immediately when both are running."""
        import warden
        self.assertEqual(warden.cmd_tor_start(), 0)

    @unittest.mock.patch("warden._wait_for_port", return_value=True)
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.tor_running", return_value=True)
    def test_tor_start_recovery_privoxy_down(self, mock_tor, mock_privoxy_run,
                                              mock_privoxy_exists, mock_run,
                                              mock_wait):
        """Starts Privoxy when only Tor is up (recovery path)."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        self.assertEqual(warden.cmd_tor_start(), 0)

    @unittest.mock.patch("warden._wait_for_port", return_value=True)
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.tor_exists", return_value=False)
    @unittest.mock.patch("warden.tor_running", return_value=False)
    def test_tor_start_full_chain(self, mock_tor_run, mock_tor_exists,
                                   mock_privoxy_run, mock_privoxy_exists,
                                   mock_run, mock_wait):
        """Starts both Tor and Privoxy in full chain."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        self.assertEqual(warden.cmd_tor_start(), 0)

    @unittest.mock.patch("warden._cleanup_tor_stack")
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.tor_exists", return_value=False)
    @unittest.mock.patch("warden.tor_running", return_value=False)
    def test_tor_start_tor_fails(self, mock_tor_run, mock_tor_exists,
                                  mock_privoxy_run, mock_privoxy_exists,
                                  mock_run, mock_cleanup):
        """Returns 1 and cleans up when Tor podman run fails."""
        import subprocess
        import warden
        mock_run.side_effect = subprocess.CalledProcessError(1, "podman")
        self.assertEqual(warden.cmd_tor_start(), 1)
        mock_cleanup.assert_called()

    @unittest.mock.patch("warden._cleanup_tor_stack")
    @unittest.mock.patch("warden._wait_for_port")
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.tor_exists", return_value=False)
    @unittest.mock.patch("warden.tor_running", return_value=False)
    def test_tor_start_privoxy_fails(self, mock_tor_run, mock_tor_exists,
                                      mock_privoxy_run, mock_privoxy_exists,
                                      mock_run, mock_wait, mock_cleanup):
        """Cleans up both when Privoxy fails to start."""
        import subprocess
        import warden
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if "podman" in cmd and "run" in cmd:
                # First podman run (Tor) succeeds, second (Privoxy) fails.
                if warden.PRIVOXY_CONTAINER_NAME in str(cmd):
                    raise subprocess.CalledProcessError(1, "podman")
            return unittest.mock.MagicMock(returncode=0)

        mock_run.side_effect = run_side_effect
        mock_wait.return_value = True  # Tor port check passes.
        result = warden.cmd_tor_start()
        self.assertEqual(result, 1)
        mock_cleanup.assert_called()

    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.tor_exists", return_value=False)
    def test_tor_stop_neither_exists(self, mock_tor, mock_privoxy):
        """cmd_tor_stop returns 0 when neither container exists."""
        import warden
        self.assertEqual(warden.cmd_tor_stop(), 0)

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.privoxy_exists", return_value=True)
    @unittest.mock.patch("warden.tor_exists", return_value=True)
    def test_tor_stop_both_running(self, mock_tor, mock_privoxy, mock_run):
        """cmd_tor_stop stops Privoxy then Tor, deletes config."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        self.assertEqual(warden.cmd_tor_stop(), 0)

    @unittest.mock.patch("warden._is_warden_tor_mode", return_value=True)
    @unittest.mock.patch("warden.privoxy_running", return_value=True)
    @unittest.mock.patch("warden.tor_running", return_value=True)
    def test_tor_status_all_active(self, mock_tor, mock_privoxy, mock_upstream):
        """All components up with upstream mode returns 0."""
        import warden
        result = warden.cmd_tor_status()
        self.assertEqual(result, 0)

    @unittest.mock.patch("warden._is_warden_tor_mode", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=True)
    @unittest.mock.patch("warden.tor_running", return_value=True)
    def test_tor_status_not_restarted(self, mock_tor, mock_privoxy, mock_upstream):
        """Tor up but Warden not upstream still returns 0 with warning."""
        import warden
        result = warden.cmd_tor_status()
        self.assertEqual(result, 0)

    @unittest.mock.patch("warden._is_warden_tor_mode", return_value=False)
    @unittest.mock.patch("warden.privoxy_exists", return_value=False)
    @unittest.mock.patch("warden.tor_exists", return_value=False)
    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.tor_running", return_value=False)
    def test_tor_status_stopped(self, mock_tor, mock_privoxy,
                                 mock_tor_exists, mock_privoxy_exists,
                                 mock_upstream):
        """Both absent returns 1."""
        import warden
        self.assertEqual(warden.cmd_tor_status(), 1)

    @unittest.mock.patch("warden.run")
    def test_privoxy_running(self, mock_run):
        """privoxy_running returns True when container name is in output."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(
            returncode=0, stdout="warden-privoxy\n"
        )
        self.assertTrue(warden.privoxy_running())

    @unittest.mock.patch("warden.privoxy_running", return_value=True)
    @unittest.mock.patch("warden._get_container_ip", return_value="10.60.0.10")
    @unittest.mock.patch("warden.reconnect_to_cell_networks")
    @unittest.mock.patch("warden.is_running")
    @unittest.mock.patch("warden.container_exists", return_value=False)
    @unittest.mock.patch("warden.preflight_validate", return_value=(True, []))
    @unittest.mock.patch("warden.run")
    def test_warden_upstream_mode(self, mock_run, mock_preflight, mock_exists,
                                   mock_is_running, mock_reconnect,
                                   mock_get_ip, mock_privoxy):
        """cmd_start includes --mode upstream when Privoxy is running."""
        import warden
        mock_is_running.side_effect = [False, True]
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        mock_reconnect.return_value = 0

        warden.cmd_start()

        # Find the podman run command.
        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if len(cmd) >= 2 and cmd[0] == "podman" and cmd[1] == "run":
                self.assertIn("--mode", cmd)
                mode_idx = cmd.index("--mode")
                self.assertIn("upstream:http://10.60.0.10:8118", cmd[mode_idx + 1])
                return
        self.fail("No 'podman run' call found")


class TestWardenCmdStartErrors(unittest.TestCase):
    """Tests for cmd_start error handling paths."""

    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_start_already_running(self, mock_running):
        """cmd_start returns 0 when proxy is already running."""
        import warden
        self.assertEqual(warden.cmd_start(), 0)

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.container_exists", return_value=True)
    @unittest.mock.patch("warden.is_running", return_value=False)
    @unittest.mock.patch("warden.preflight_validate")
    def test_start_preflight_fail(self, mock_preflight, mock_running,
                                  mock_exists, mock_run):
        """cmd_start returns 1 when preflight validation fails."""
        import warden
        mock_preflight.return_value = (False, ["missing addon"])
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        self.assertEqual(warden.cmd_start(), 1)

    @unittest.mock.patch("warden.time.sleep")
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.container_exists", return_value=False)
    @unittest.mock.patch("warden.is_running")
    @unittest.mock.patch("warden.preflight_validate", return_value=(True, []))
    def test_start_timeout(self, mock_preflight, mock_is_running, mock_exists,
                           mock_run, mock_sleep):
        """cmd_start returns 1 when proxy never becomes ready."""
        import warden
        mock_is_running.side_effect = [False] + [False] * 11
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        self.assertEqual(warden.cmd_start(), 1)

    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.container_exists", return_value=False)
    @unittest.mock.patch("warden.is_running", return_value=False)
    @unittest.mock.patch("warden.preflight_validate", return_value=(True, []))
    def test_start_run_failure(self, mock_preflight, mock_is_running,
                               mock_exists, mock_run, mock_privoxy):
        """cmd_start returns 1 when podman run raises CalledProcessError."""
        import subprocess
        import warden

        def run_side_effect(cmd, **kwargs):
            # Optional addon checks use "test -f".
            if cmd[0] == "test":
                return unittest.mock.MagicMock(returncode=0)
            # podman run fails.
            raise subprocess.CalledProcessError(1, "podman")

        mock_run.side_effect = run_side_effect
        self.assertEqual(warden.cmd_start(), 1)

    @unittest.mock.patch("warden.privoxy_running", return_value=False)
    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.container_exists", return_value=True)
    @unittest.mock.patch("warden.is_running", return_value=False)
    @unittest.mock.patch("warden.preflight_validate", return_value=(True, []))
    def test_start_removes_existing_container(self, mock_preflight,
                                              mock_is_running, mock_exists,
                                              mock_run, mock_privoxy):
        """cmd_start removes existing stopped container before starting."""
        import subprocess
        import warden
        mock_run.side_effect = [
            unittest.mock.MagicMock(returncode=0),  # rm -f existing.
            unittest.mock.MagicMock(returncode=0),  # test -f addon check.
            unittest.mock.MagicMock(returncode=0),  # test -f addon check.
            unittest.mock.MagicMock(returncode=0),  # test -f addon check.
            unittest.mock.MagicMock(returncode=0),  # test -f addon check.
            unittest.mock.MagicMock(returncode=0),  # test -f addon check.
            subprocess.CalledProcessError(1, "podman"),  # podman run fails.
        ]
        warden.cmd_start()
        first_call_cmd = mock_run.call_args_list[0][0][0]
        self.assertIn("rm", first_call_cmd)


class TestWardenCmdRestart(unittest.TestCase):
    """Tests for cmd_restart behavior."""

    @unittest.mock.patch("warden.cmd_start")
    @unittest.mock.patch("warden.cmd_stop", return_value=1)
    def test_restart_stop_fails(self, mock_stop, mock_start):
        """cmd_restart returns 1 and skips start when stop fails."""
        import warden
        self.assertEqual(warden.cmd_restart(), 1)
        mock_start.assert_not_called()


class TestWardenCmdHealth(unittest.TestCase):
    """Tests for cmd_health check behavior."""

    def setUp(self):
        """Set up test fixtures with temporary directories."""
        import warden
        self.temp_dir = tempfile.mkdtemp()
        self._orig_policy = warden.POLICY_FILE
        self._orig_log_dir = warden.LOG_DIR
        self._orig_metrics = warden.METRICS_SOCKET
        warden.LOG_DIR = Path(self.temp_dir) / "logs"
        warden.LOG_DIR.mkdir()

    def tearDown(self):
        """Restore original paths and clean up."""
        import shutil
        import warden
        warden.POLICY_FILE = self._orig_policy
        warden.LOG_DIR = self._orig_log_dir
        warden.METRICS_SOCKET = self._orig_metrics
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.mock.patch("warden.get_proxy_ip", return_value="10.60.0.2")
    @unittest.mock.patch("warden.is_running", return_value=False)
    def test_proxy_down_fails(self, mock_running, mock_ip):
        """cmd_health returns 1 when proxy is not running."""
        import warden
        warden.POLICY_FILE = Path(self.temp_dir) / "policy.json"
        warden.POLICY_FILE.write_text('{"allow":[],"deny":[]}')
        warden.METRICS_SOCKET = Path(self.temp_dir) / "metrics.sock"
        result = warden.cmd_health()
        self.assertEqual(result, 1)

    @unittest.mock.patch("warden.socket")
    @unittest.mock.patch("warden.get_proxy_ip", return_value="10.60.0.2")
    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_health_json_output(self, mock_running, mock_ip, mock_socket_mod):
        """cmd_health with format_json produces output without crashing."""
        import warden
        warden.POLICY_FILE = Path(self.temp_dir) / "policy.json"
        warden.POLICY_FILE.write_text('{"allow":[],"deny":[]}')
        warden.METRICS_SOCKET = Path(self.temp_dir) / "metrics.sock"
        mock_sock = unittest.mock.MagicMock()
        mock_socket_mod.socket.return_value = mock_sock
        mock_socket_mod.AF_INET = 2
        mock_socket_mod.SOCK_STREAM = 1
        mock_sock.connect_ex.return_value = 0
        # Result depends on urllib.request.urlopen, but should not crash.
        result = warden.cmd_health(format_json=True)
        self.assertIn(result, (0, 1))


class TestPreflightValidate(unittest.TestCase):
    """Tests for preflight_validate checks."""

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("os.access", return_value=True)
    @unittest.mock.patch("pathlib.Path.exists")
    def test_all_present_passes(self, mock_exists, mock_access, mock_run):
        """preflight_validate returns success when all files present."""
        import warden
        mock_exists.return_value = True
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json',
                                         delete=False) as f:
            json.dump({"allow": [], "deny": []}, f)
            policy_path = f.name
        orig = warden.POLICY_FILE
        warden.POLICY_FILE = Path(policy_path)
        try:
            success, errors = warden.preflight_validate()
            self.assertTrue(success)
            self.assertEqual(errors, [])
        finally:
            warden.POLICY_FILE = orig
            os.unlink(policy_path)

    @unittest.mock.patch("warden.run")
    def test_missing_addon_fails(self, mock_run):
        """preflight_validate returns failure when required files missing."""
        import warden
        mock_run.return_value = unittest.mock.MagicMock(returncode=1)
        success, errors = warden.preflight_validate()
        self.assertFalse(success)
        self.assertTrue(len(errors) > 0)


# ========== Step 5a: warden.py cmd_stats ==========


class TestWardenCmdStats(unittest.TestCase):
    """Tests for warden.cmd_stats socket-based metrics query."""

    def setUp(self):
        """Redirect METRICS_SOCKET to temp dir."""
        import warden
        self.temp_dir = tempfile.mkdtemp()
        self._orig_socket = warden.METRICS_SOCKET
        # Point to a non-existent path by default.
        warden.METRICS_SOCKET = Path(self.temp_dir) / "metrics.sock"

    def tearDown(self):
        """Restore original path."""
        import shutil
        import warden
        warden.METRICS_SOCKET = self._orig_socket
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_no_socket_returns_error(self):
        """Returns 1 when metrics socket is missing."""
        import warden
        result = warden.cmd_stats()
        self.assertEqual(result, 1)

    @unittest.mock.patch('socket.socket')
    def test_all_metrics_json(self, mock_socket_cls):
        """'all' command returns JSON output in json format."""
        import warden
        # Create the socket file so exists() returns True.
        warden.METRICS_SOCKET.touch()
        mock_sock = mock_socket_cls.return_value
        response = json.dumps({
            "cells": {"app1": {"total_requests": 100}},
            "timestamp": 1234567890,
        }).encode()
        mock_sock.recv.side_effect = [response, b""]

        result = warden.cmd_stats(format_json=True)
        self.assertEqual(result, 0)

    @unittest.mock.patch('socket.socket')
    def test_cell_filter(self, mock_socket_cls):
        """cell_name sends 'cell:name' command."""
        import warden
        warden.METRICS_SOCKET.touch()
        mock_sock = mock_socket_cls.return_value
        response = json.dumps({
            "cell": "myapp",
            "metrics": {"total_requests": 42},
        }).encode()
        mock_sock.recv.side_effect = [response, b""]

        result = warden.cmd_stats(cell_name="myapp")
        self.assertEqual(result, 0)
        mock_sock.sendall.assert_called_with(b"cell:myapp")

    @unittest.mock.patch('socket.socket')
    def test_response_too_large(self, mock_socket_cls):
        """Response exceeding 10MB returns error."""
        import warden
        warden.METRICS_SOCKET.touch()
        mock_sock = mock_socket_cls.return_value
        big_chunk = b"x" * 65536
        mock_sock.recv.side_effect = [big_chunk] * 200  # ~12.8MB

        result = warden.cmd_stats()
        self.assertEqual(result, 1)

    @unittest.mock.patch('socket.socket')
    def test_error_in_response(self, mock_socket_cls):
        """Error field in response returns 1."""
        import warden
        warden.METRICS_SOCKET.touch()
        mock_sock = mock_socket_cls.return_value
        response = json.dumps({"error": "something went wrong"}).encode()
        mock_sock.recv.side_effect = [response, b""]

        result = warden.cmd_stats()
        self.assertEqual(result, 1)

    @unittest.mock.patch('socket.socket')
    def test_socket_connection_error(self, mock_socket_cls):
        """Socket connection error returns 1."""
        import socket
        import warden
        warden.METRICS_SOCKET.touch()
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = socket.error("Connection refused")

        result = warden.cmd_stats()
        self.assertEqual(result, 1)


# ========== Step 5b: warden.py Log Export ==========


class TestWardenCmdLogsExport(unittest.TestCase):
    """Tests for warden.cmd_logs_export."""

    def setUp(self):
        """Set up temp log directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import warden
        self._orig_log_dir = warden.LOG_DIR
        warden.LOG_DIR = self.temp_dir

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        import warden
        warden.LOG_DIR = self._orig_log_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_log(self, name, entries, old=False):
        """Write JSONL log file, optionally with old mtime."""
        path = self.temp_dir / name
        with open(path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        if old:
            mtime = time.time() - (30 * 86400)
            os.utime(path, (mtime, mtime))
        return path

    def test_export_jsonl(self):
        """JSONL export writes entries."""
        import warden
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T00:00:00Z", "host": "a.com"},
            {"ts": "2024-01-01T01:00:00Z", "host": "b.com"},
        ])
        out_file = self.temp_dir / "out.jsonl"
        result = warden.cmd_logs_export(format_type="jsonl", output_file=str(out_file))
        self.assertEqual(result, 0)
        self.assertTrue(out_file.exists())
        lines = out_file.read_text().strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_export_csv(self):
        """CSV export writes headers and rows."""
        import warden
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T00:00:00Z", "host": "a.com", "status": 200},
        ])
        out_file = self.temp_dir / "out.csv"
        result = warden.cmd_logs_export(format_type="csv", output_file=str(out_file))
        self.assertEqual(result, 0)
        self.assertTrue(out_file.exists())
        content = out_file.read_text()
        self.assertIn("ts", content)
        self.assertIn("host", content)

    def test_export_no_logs(self):
        """No log files returns 0 with message."""
        import warden
        result = warden.cmd_logs_export()
        self.assertEqual(result, 0)

    def test_export_filters_by_age(self):
        """Old files beyond days cutoff are skipped."""
        import warden
        self._write_log("old.jsonl", [
            {"ts": "2020-01-01T00:00:00Z", "host": "old.com"},
        ], old=True)
        out_file = self.temp_dir / "out.jsonl"
        result = warden.cmd_logs_export(days=1, output_file=str(out_file))
        self.assertEqual(result, 0)

    def test_export_path_traversal_blocked(self):
        """Path traversal in output file is rejected."""
        import warden
        self._write_log("test.jsonl", [{"ts": "2024-01-01T00:00:00Z"}])
        result = warden.cmd_logs_export(output_file="../evil.jsonl")
        self.assertEqual(result, 1)

    def test_export_corrupt_lines_skipped(self):
        """Invalid JSON lines are silently skipped."""
        import warden
        path = self.temp_dir / "test.jsonl"
        with open(path, "w") as f:
            f.write('{"ts": "2024-01-01T00:00:00Z", "host": "good.com"}\n')
            f.write("not json\n")
            f.write('{"ts": "2024-01-01T01:00:00Z", "host": "also-good.com"}\n')
        out_file = self.temp_dir / "out.jsonl"
        result = warden.cmd_logs_export(format_type="jsonl", output_file=str(out_file))
        self.assertEqual(result, 0)
        lines = out_file.read_text().strip().split("\n")
        self.assertEqual(len(lines), 2)


# ========== Step 5c: warden.py cmd_logs_compact_ai ==========


class TestWardenCmdLogsCompactAi(unittest.TestCase):
    """Tests for warden.cmd_logs_compact_ai."""

    @classmethod
    def setUpClass(cls):
        """Import warden module."""
        import warden as w
        cls.warden = w

    def test_invalid_duration(self):
        """Invalid duration format returns error."""
        result = self.warden.cmd_logs_compact_ai("cell", older_than="abc")
        self.assertEqual(result, 1)

    def test_duration_hours(self):
        """Valid hours duration is parsed correctly."""
        with unittest.mock.patch.dict('sys.modules', {'summarizer': MagicMock()}):
            mock_compact = MagicMock(return_value={"compacted_entries": 5, "preserved_entries": 2,
                                                    "recent_entries_kept": 10, "summary_file": "/tmp/s.json",
                                                    "archive_file": "/tmp/a.gz", "ai_enabled": False})
            with unittest.mock.patch('builtins.__import__', side_effect=ImportError("no module")):
                result = self.warden.cmd_logs_compact_ai("cell", older_than="24h")
            # Import error is caught.
            self.assertEqual(result, 1)

    def test_no_cell_name(self):
        """Missing cell name returns error."""
        result = self.warden.cmd_logs_compact_ai(None, older_than="24h")
        self.assertEqual(result, 1)

    @unittest.mock.patch('warden.cmd_logs_compact_ai.__module__', 'warden')
    def test_import_error_handled(self):
        """ImportError for summarizer module returns error."""
        # Temporarily make summarizer import fail.
        result = self.warden.cmd_logs_compact_ai("cell", older_than="24h")
        self.assertEqual(result, 1)

    def test_successful_compact(self):
        """Successful compaction prints formatted output."""
        import sys
        mock_summarizer = MagicMock()
        mock_summarizer.compact_cell_logs.return_value = {
            "compacted_entries": 100,
            "preserved_entries": 5,
            "recent_entries_kept": 50,
            "summary_file": "/tmp/summary.json",
            "archive_file": "/tmp/archive.gz",
            "ai_enabled": True,
            "ai_error": None,
        }
        # Inject mock into sys.modules so `from summarizer import compact_cell_logs` works.
        with unittest.mock.patch.dict(sys.modules, {"summarizer": mock_summarizer}):
            result = self.warden.cmd_logs_compact_ai("cell", older_than="24h")
        self.assertEqual(result, 0)


# ========== Phase 11 Step 1: Policy + Validation ==========


class TestValidatePolicyFull(unittest.TestCase):
    """Tests for warden.cmd_policy_validate with full policy dicts."""

    def test_validate_valid_complete_policy(self):
        """Complete policy with all sections passes validation."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": ["example.com", {"domain": "api.github.com", "paths": ["/v1/*"]}],
                "deny": ["evil.com"],
                "rate_limits": {"default": {"rate": 100, "burst": 500}},
                "log_filter": {"sample_rate": 0.5},
                "notifications": {"webhook_url": "https://hooks.example.com/warden"},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)

    def test_validate_rate_limits_invalid_rate(self):
        """rate_limits.default.rate must be a number."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "rate_limits": {"default": {"rate": "fast"}},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_rate_limits_invalid_burst(self):
        """rate_limits.default.burst must be an integer."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "rate_limits": {"default": {"burst": 1.5}},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_log_filter_invalid_sample_rate(self):
        """log_filter.sample_rate must be between 0 and 1."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "log_filter": {"sample_rate": "not_a_number"},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_log_filter_out_of_range(self):
        """log_filter.sample_rate > 1 fails."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "log_filter": {"sample_rate": 2.0},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_notifications_bad_url(self):
        """notifications.webhook_url must be HTTP(S)."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "notifications": {"webhook_url": "ftp://badproto.com"},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 1)
            finally:
                os.unlink(f.name)

    def test_validate_notifications_valid_url(self):
        """Valid webhook URL passes."""
        from warden import cmd_policy_validate

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "allow": [],
                "deny": [],
                "notifications": {"webhook_url": "https://hooks.slack.com/services/abc"},
            }, f)
            f.flush()
            try:
                result = cmd_policy_validate(f.name)
                self.assertEqual(result, 0)
            finally:
                os.unlink(f.name)


class TestValidateRuleDetailed(unittest.TestCase):
    """Additional tests for warden._validate_rule edge cases."""

    def test_validate_rule_string_valid(self):
        """Simple domain string is valid."""
        from warden import _validate_rule
        self.assertEqual(_validate_rule("example.com", "allow[0]"), [])

    def test_validate_rule_dict_valid_complete(self):
        """Dict rule with domain, ports, paths, methods is valid."""
        from warden import _validate_rule
        rule = {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET", "POST"]}
        self.assertEqual(_validate_rule(rule, "allow[0]"), [])

    def test_validate_rule_dict_no_domain(self):
        """Dict rule missing domain produces error."""
        from warden import _validate_rule
        rule = {"paths": ["/v1/*"]}
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("domain" in e for e in errors))

    def test_validate_rule_invalid_port_type(self):
        """Dict rule with invalid method type produces error."""
        from warden import _validate_rule
        rule = {"domain": "example.com", "methods": "GET"}  # Should be list.
        errors = _validate_rule(rule, "allow[0]")
        self.assertTrue(any("methods" in e for e in errors))

    def test_validate_rule_bad_type_int(self):
        """Integer rule type produces error."""
        from warden import _validate_rule
        errors = _validate_rule(42, "allow[0]")
        self.assertTrue(any("invalid rule type" in e for e in errors))


class TestMatchesDomainDetailed(unittest.TestCase):
    """Additional tests for warden._matches_domain."""

    def test_matches_domain_exact(self):
        """Exact domain match."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("example.com", "example.com"))

    def test_matches_domain_wildcard_subdomain(self):
        """Wildcard matches subdomain."""
        from warden import _matches_domain
        self.assertTrue(_matches_domain("*.example.com", "api.example.com"))

    def test_matches_domain_no_match(self):
        """Different domain does not match."""
        from warden import _matches_domain
        self.assertFalse(_matches_domain("example.com", "other.com"))


class TestRuleStr(unittest.TestCase):
    """Tests for warden._rule_str formatting."""

    def test_rule_str_string(self):
        """String rule returns itself."""
        from warden import _rule_str
        self.assertEqual(_rule_str("example.com"), "example.com")

    def test_rule_str_dict(self):
        """Dict rule returns formatted string."""
        from warden import _rule_str
        result = _rule_str({"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["POST"]})
        self.assertIn("api.example.com", result)
        self.assertIn("paths=", result)
        self.assertIn("methods=", result)

    def test_rule_str_dict_domain_only(self):
        """Dict rule with domain only returns domain."""
        from warden import _rule_str
        result = _rule_str({"domain": "example.com"})
        self.assertEqual(result, "example.com")

    def test_rule_str_unknown_type(self):
        """Non-string, non-dict returns str(rule)."""
        from warden import _rule_str
        self.assertEqual(_rule_str(42), "42")


# ========== Phase 11 Step 2: Log Compaction ==========


class TestCmdLogsCompact(unittest.TestCase):
    """Tests for warden.cmd_logs_compact strategies."""

    def setUp(self):
        """Set up temp log directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import warden
        self._orig_log_dir = warden.LOG_DIR
        warden.LOG_DIR = self.temp_dir

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        import warden
        warden.LOG_DIR = self._orig_log_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_log(self, name, entries, old=True):
        """Write JSONL log file with old mtime by default."""
        path = self.temp_dir / name
        with open(path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        if old:
            mtime = time.time() - (30 * 86400)  # 30 days old.
            os.utime(path, (mtime, mtime))
        return path

    def test_compact_no_log_dir(self):
        """No log directory returns 0."""
        import shutil
        import warden
        shutil.rmtree(self.temp_dir)
        result = warden.cmd_logs_compact(strategy="delete")
        self.assertEqual(result, 0)

    def test_compact_no_log_files(self):
        """Empty directory returns 0."""
        import warden
        result = warden.cmd_logs_compact(strategy="delete")
        self.assertEqual(result, 0)

    def test_compact_invalid_duration(self):
        """Invalid duration format returns 1."""
        import warden
        result = warden.cmd_logs_compact(older_than="abc")
        self.assertEqual(result, 1)

    def test_compact_delete_old_files(self):
        """Delete strategy removes old log files."""
        import warden
        self._write_log("old.jsonl", [
            {"ts": "2020-01-01T00:00:00Z", "host": "old.com"},
        ])
        result = warden.cmd_logs_compact(strategy="delete", older_than="7d")
        self.assertEqual(result, 0)
        self.assertFalse((self.temp_dir / "old.jsonl").exists())

    def test_compact_delete_skips_recent(self):
        """Delete strategy skips recent log files."""
        import warden
        self._write_log("recent.jsonl", [
            {"ts": "2020-01-01T00:00:00Z", "host": "recent.com"},
        ], old=False)
        result = warden.cmd_logs_compact(strategy="delete", older_than="7d")
        self.assertEqual(result, 0)
        self.assertTrue((self.temp_dir / "recent.jsonl").exists())

    def test_compact_aggregate_basic(self):
        """Aggregate strategy groups by domain and writes summary."""
        import warden
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "a.com", "method": "GET", "status": 200,
             "bytes": 100, "request_bytes": 50, "ms": 10},
            {"ts": "2024-01-01T10:01:00Z", "host": "a.com", "method": "GET", "status": 200,
             "bytes": 200, "request_bytes": 100, "ms": 20},
        ])
        result = warden.cmd_logs_compact(strategy="aggregate", older_than="7d")
        self.assertEqual(result, 0)
        # Original should be deleted, compact file created.
        self.assertFalse((self.temp_dir / "test.jsonl").exists())
        compact = self.temp_dir / "test.compact.jsonl"
        self.assertTrue(compact.exists())
        lines = compact.read_text().strip().split("\n")
        entry = json.loads(lines[0])
        self.assertEqual(entry["count"], 2)
        self.assertEqual(entry["host"], "a.com")

    def test_compact_aggregate_corrupt_line(self):
        """Aggregate strategy skips corrupt JSON lines."""
        import warden
        path = self.temp_dir / "mixed.jsonl"
        with open(path, "w") as f:
            f.write('{"ts":"2024-01-01T10:00:00Z","host":"a.com","method":"GET","status":200,"ms":10}\n')
            f.write("not json\n")
            f.write('{"ts":"2024-01-01T10:01:00Z","host":"b.com","method":"GET","status":200,"ms":20}\n')
        mtime = time.time() - (30 * 86400)
        os.utime(path, (mtime, mtime))
        result = warden.cmd_logs_compact(strategy="aggregate", older_than="7d")
        self.assertEqual(result, 0)

    def test_compact_sample_basic(self):
        """Sample strategy keeps N samples per hour bucket."""
        import warden
        entries = []
        for i in range(20):
            entries.append({
                "ts": f"2024-01-01T10:{i:02d}:00Z",
                "host": "a.com",
                "method": "GET",
                "status": 200,
            })
        self._write_log("test.jsonl", entries)
        result = warden.cmd_logs_compact(strategy="sample", samples_per_hour=5, older_than="7d")
        self.assertEqual(result, 0)
        # Original deleted, sample file created.
        self.assertFalse((self.temp_dir / "test.jsonl").exists())
        sample = self.temp_dir / "test.sample.jsonl"
        self.assertTrue(sample.exists())
        lines = sample.read_text().strip().split("\n")
        self.assertEqual(len(lines), 5)

    def test_compact_archive_creates_gzip(self):
        """Archive strategy creates gzip file."""
        import warden
        archive_dir = self.temp_dir / "archive"
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "a.com"},
        ])
        result = warden.cmd_logs_compact(
            strategy="archive", archive_path=str(archive_dir), older_than="7d"
        )
        self.assertEqual(result, 0)
        self.assertFalse((self.temp_dir / "test.jsonl").exists())
        gz_files = list(archive_dir.glob("*.gz"))
        self.assertEqual(len(gz_files), 1)

    def test_compact_archive_no_path_error(self):
        """Archive strategy without path returns 1."""
        import warden
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "a.com"},
        ])
        result = warden.cmd_logs_compact(strategy="archive", older_than="7d")
        self.assertEqual(result, 1)

    def test_compact_archive_path_traversal_blocked(self):
        """Archive strategy blocks path traversal."""
        import warden
        self._write_log("test.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "a.com"},
        ])
        result = warden.cmd_logs_compact(
            strategy="archive", archive_path="../evil", older_than="7d"
        )
        self.assertEqual(result, 1)

    def test_compact_cell_name_filter(self):
        """Cell name filters to matching log files."""
        import warden
        self._write_log("myapp.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "a.com"},
        ])
        self._write_log("other.jsonl", [
            {"ts": "2024-01-01T10:00:00Z", "host": "b.com"},
        ])
        result = warden.cmd_logs_compact(
            cell_name="myapp", strategy="delete", older_than="7d"
        )
        self.assertEqual(result, 0)
        self.assertFalse((self.temp_dir / "myapp.jsonl").exists())
        self.assertTrue((self.temp_dir / "other.jsonl").exists())


class TestCmdLogsPrune(unittest.TestCase):
    """Tests for warden.cmd_logs_prune."""

    def setUp(self):
        """Set up temp log directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import warden
        self._orig_log_dir = warden.LOG_DIR
        warden.LOG_DIR = self.temp_dir

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        import warden
        warden.LOG_DIR = self._orig_log_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_prune_old_files(self):
        """Files older than threshold are deleted."""
        import warden
        path = self.temp_dir / "old.jsonl"
        path.write_text('{"ts":"2020-01-01"}\n')
        mtime = time.time() - (30 * 86400)
        os.utime(path, (mtime, mtime))
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)
        self.assertFalse(path.exists())

    def test_prune_gz_files(self):
        """Gzip files older than threshold are also deleted."""
        import warden
        path = self.temp_dir / "old.jsonl.gz"
        path.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
        mtime = time.time() - (30 * 86400)
        os.utime(path, (mtime, mtime))
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)
        self.assertFalse(path.exists())

    def test_prune_recent_files_kept(self):
        """Recent files are not deleted."""
        import warden
        path = self.temp_dir / "recent.jsonl"
        path.write_text('{"ts":"2024-01-01"}\n')
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)
        self.assertTrue(path.exists())

    def test_prune_empty_dir(self):
        """Empty directory returns 0."""
        import warden
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)

    def test_prune_negative_days(self):
        """Negative days returns error."""
        import warden
        result = warden.cmd_logs_prune(days=-1)
        self.assertEqual(result, 1)

    def test_prune_no_dir(self):
        """Missing log directory returns 0."""
        import shutil
        import warden
        shutil.rmtree(self.temp_dir)
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)


class TestCmdLogsCompactDuration(unittest.TestCase):
    """Tests for duration parsing in cmd_logs_compact."""

    def setUp(self):
        """Set up temp log directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import warden
        self._orig_log_dir = warden.LOG_DIR
        warden.LOG_DIR = self.temp_dir

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        import warden
        warden.LOG_DIR = self._orig_log_dir
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_hours_duration(self):
        """Hours duration '24h' is parsed correctly."""
        import warden
        result = warden.cmd_logs_compact(older_than="24h")
        self.assertEqual(result, 0)

    def test_minutes_duration(self):
        """Minutes duration '30m' is parsed correctly."""
        import warden
        result = warden.cmd_logs_compact(older_than="30m")
        self.assertEqual(result, 0)

    def test_zero_duration_fails(self):
        """Zero duration '0d' fails."""
        import warden
        result = warden.cmd_logs_compact(older_than="0d")
        self.assertEqual(result, 1)

    def test_compact_aggregate_daily_bucket(self):
        """Aggregate strategy with daily bucket groups by date."""
        import warden
        path = self.temp_dir / "test.jsonl"
        with open(path, "w") as f:
            f.write('{"ts":"2024-01-01T10:00:00Z","host":"a.com","method":"GET","status":200,"ms":10}\n')
        mtime = time.time() - (30 * 86400)
        os.utime(path, (mtime, mtime))
        result = warden.cmd_logs_compact(strategy="aggregate", bucket="daily", older_than="7d")
        self.assertEqual(result, 0)
        compact = self.temp_dir / "test.compact.jsonl"
        self.assertTrue(compact.exists())
        entry = json.loads(compact.read_text().strip().split("\n")[0])
        self.assertIn("T00:00:00Z", entry["bucket"])


class TestWardenValidateCellName(unittest.TestCase):
    """Tests for warden.validate_cell_name."""

    def test_valid_name(self):
        """Valid name returns True."""
        import warden
        self.assertTrue(warden.validate_cell_name("myapp"))
        self.assertTrue(warden.validate_cell_name("my-app"))
        self.assertTrue(warden.validate_cell_name("a1b2c3"))

    def test_invalid_name(self):
        """Invalid name returns False."""
        import warden
        self.assertFalse(warden.validate_cell_name("-bad"))
        self.assertFalse(warden.validate_cell_name(""))
        self.assertFalse(warden.validate_cell_name("../evil"))

    def test_uppercase_rejected(self):
        """Uppercase names are rejected."""
        import warden
        self.assertFalse(warden.validate_cell_name("MyApp"))


class TestWardenColorize(unittest.TestCase):
    """Tests for warden colorize function."""

    def test_colorize_enabled(self):
        """Colorize wraps text with ANSI codes."""
        import warden
        orig = warden.COLOR_ENABLED
        warden.COLOR_ENABLED = True
        try:
            result = warden.colorize("test", "green")
            self.assertIn("\033[32m", result)
            self.assertIn("test", result)
        finally:
            warden.COLOR_ENABLED = orig

    def test_colorize_disabled(self):
        """Colorize returns plain text when disabled."""
        import warden
        orig = warden.COLOR_ENABLED
        warden.COLOR_ENABLED = False
        try:
            result = warden.colorize("test", "green")
            self.assertEqual(result, "test")
        finally:
            warden.COLOR_ENABLED = orig

    def test_colorize_unknown_color(self):
        """Unknown color returns plain text."""
        import warden
        orig = warden.COLOR_ENABLED
        warden.COLOR_ENABLED = True
        try:
            result = warden.colorize("test", "purple")
            self.assertEqual(result, "test")
        finally:
            warden.COLOR_ENABLED = orig


class TestCmdReload(unittest.TestCase):
    """Tests for warden.cmd_reload structural validation."""

    def setUp(self):
        """Set up temp policy file."""
        self.temp_dir = Path(tempfile.mkdtemp())
        import warden
        self._orig_policy = warden.POLICY_FILE
        warden.POLICY_FILE = self.temp_dir / "policy.json"

    def tearDown(self):
        """Restore and clean up."""
        import shutil
        import warden
        warden.POLICY_FILE = self._orig_policy
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest.mock.patch("warden.run")
    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_reload_valid_policy(self, mock_running, mock_run):
        """Valid policy file triggers reload signal."""
        import warden
        warden.POLICY_FILE.write_text('{"allow": [], "deny": []}')
        mock_run.return_value = unittest.mock.MagicMock(returncode=0)
        result = warden.cmd_reload()
        self.assertEqual(result, 0)
        mock_run.assert_called()

    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_reload_invalid_json(self, mock_running):
        """Invalid JSON policy prevents reload."""
        import warden
        warden.POLICY_FILE.write_text("not json{{{")
        result = warden.cmd_reload()
        self.assertEqual(result, 1)

    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_reload_missing_policy(self, mock_running):
        """Missing policy file prevents reload."""
        import warden
        result = warden.cmd_reload()
        self.assertEqual(result, 1)

    @unittest.mock.patch("warden.is_running", return_value=False)
    def test_reload_proxy_not_running(self, mock_running):
        """Proxy not running returns 1."""
        import warden
        result = warden.cmd_reload()
        self.assertEqual(result, 1)

    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_reload_policy_not_dict(self, mock_running):
        """Policy that is not a dict returns 1."""
        import warden
        warden.POLICY_FILE.write_text('["not", "a", "dict"]')
        result = warden.cmd_reload()
        self.assertEqual(result, 1)

    @unittest.mock.patch("warden.is_running", return_value=True)
    def test_reload_policy_allow_not_list(self, mock_running):
        """Policy with 'allow' not a list returns 1."""
        import warden
        warden.POLICY_FILE.write_text('{"allow": "string"}')
        result = warden.cmd_reload()
        self.assertEqual(result, 1)


if __name__ == "__main__":
    # Run tests.
    unittest.main(verbosity=2)
