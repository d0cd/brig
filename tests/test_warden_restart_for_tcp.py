"""Cell lifecycle prompts for warden restart when a new TCP host_service
needs a listener bound. mitmproxy can't hot-add `--mode reverse:tcp`
listeners, so a cell yaml that adds a TCP port must trigger restart;
operators get a yes/no prompt unless --yes is set.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch


def _spec(host_services=None):
    from brig.cell.spec import CellSpec
    return CellSpec(
        name="alice", image="alpine",
        host_services=host_services or [],
    )


class TestMaybeRestartWardenForTcp(unittest.TestCase):
    def test_no_tcp_services_is_noop(self):
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        with patch("warden.proxy.get_bound_tcp_ports") as mock_bound, \
             patch("warden.proxy.start") as mock_start, \
             patch("warden.proxy.stop") as mock_stop:
            _maybe_restart_warden_for_tcp(
                _spec(host_services=[{"name": "api", "port": 4000}]),  # http
                yes=True,
            )
        mock_bound.assert_not_called()
        mock_start.assert_not_called()
        mock_stop.assert_not_called()

    def test_already_bound_is_noop(self):
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[5432]), \
             patch("warden.proxy.start") as mock_start, \
             patch("warden.proxy.stop") as mock_stop:
            _maybe_restart_warden_for_tcp(
                _spec(host_services=[
                    {"name": "db", "port": 5432, "protocol": "tcp"},
                ]),
                yes=True,
            )
        mock_start.assert_not_called()
        mock_stop.assert_not_called()

    def test_missing_port_triggers_restart_when_yes(self):
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[]), \
             patch("warden.proxy.start", return_value=True) as mock_start, \
             patch("warden.proxy.stop") as mock_stop:
            _maybe_restart_warden_for_tcp(
                _spec(host_services=[
                    {"name": "db", "port": 5432, "protocol": "tcp"},
                ]),
                yes=True,  # auto-confirm
            )
        mock_stop.assert_called()
        mock_start.assert_called()

    def test_missing_port_prompt_decline_raises(self):
        """Operator declining the prompt must abort with a clear
        suggestion, NOT silently start the cell into a broken state."""
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        from brig.errors import BrigError
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[]), \
             patch("warden.proxy.start") as mock_start, \
             patch("warden.proxy.stop") as mock_stop, \
             patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            with self.assertRaises(BrigError) as ctx:
                _maybe_restart_warden_for_tcp(
                    _spec(host_services=[
                        {"name": "db", "port": 5432, "protocol": "tcp"},
                    ]),
                    yes=False,
                )
        mock_start.assert_not_called()
        mock_stop.assert_not_called()
        self.assertIn("declined", str(ctx.exception))
        self.assertIn("--yes", ctx.exception.suggestion or "")

    def test_missing_port_prompt_accept_restarts(self):
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[]), \
             patch("warden.proxy.start", return_value=True) as mock_start, \
             patch("warden.proxy.stop") as mock_stop, \
             patch("sys.stdin.isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            _maybe_restart_warden_for_tcp(
                _spec(host_services=[
                    {"name": "db", "port": 5432, "protocol": "tcp"},
                ]),
                yes=False,
            )
        mock_start.assert_called()
        mock_stop.assert_called()

    def test_missing_port_non_tty_raises(self):
        """A non-interactive caller (no TTY) without --yes must fail fast with an
        actionable error, not block on a prompt / EOF-driven abort."""
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        from brig.errors import BrigError
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[]), \
             patch("warden.proxy.start") as mock_start, \
             patch("warden.proxy.stop") as mock_stop, \
             patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(BrigError) as ctx:
                _maybe_restart_warden_for_tcp(
                    _spec(host_services=[
                        {"name": "db", "port": 5432, "protocol": "tcp"},
                    ]),
                    yes=False,
                )
        mock_start.assert_not_called()
        mock_stop.assert_not_called()
        self.assertIn("--yes", ctx.exception.suggestion or "")

    def test_warden_restart_failure_raises(self):
        from brig.commands.lifecycle_run import _maybe_restart_warden_for_tcp
        from brig.errors import BrigError
        with patch("warden.proxy.get_bound_tcp_ports", return_value=[]), \
             patch("warden.proxy.start", return_value=False), \
             patch("warden.proxy.stop"):
            with self.assertRaises(BrigError) as ctx:
                _maybe_restart_warden_for_tcp(
                    _spec(host_services=[
                        {"name": "db", "port": 5432, "protocol": "tcp"},
                    ]),
                    yes=True,
                )
        self.assertIn("Warden restart failed", str(ctx.exception))


class TestGetBoundTcpPorts(unittest.TestCase):
    def test_missing_runtime_file_returns_empty(self):
        """Fail-safe: no runtime file = act as if nothing bound (will
        trigger restart in the lifecycle path, which is correct)."""
        import tempfile
        from pathlib import Path
        from warden import proxy
        with tempfile.TemporaryDirectory() as td:
            with patch.object(proxy, "WARDEN_RUNTIME_FILE",
                              Path(td) / "warden-runtime.json"):
                self.assertEqual(proxy.get_bound_tcp_ports(), [])

    def test_reads_recorded_ports(self):
        import json
        import tempfile
        from pathlib import Path
        from warden import proxy
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "warden-runtime.json"
            f.write_text(json.dumps({"tcp_host_service_ports": [6379, 5432]}))
            with patch.object(proxy, "WARDEN_RUNTIME_FILE", f):
                # Sorted on return.
                self.assertEqual(proxy.get_bound_tcp_ports(), [5432, 6379])

    def test_corrupted_runtime_file_returns_empty(self):
        import tempfile
        from pathlib import Path
        from warden import proxy
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "warden-runtime.json"
            f.write_text("not json{{{")
            with patch.object(proxy, "WARDEN_RUNTIME_FILE", f):
                self.assertEqual(proxy.get_bound_tcp_ports(), [])


if __name__ == "__main__":
    unittest.main()
