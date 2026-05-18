"""Tests for `brig up` — its proxy-state check must agree with warden.proxy.

Regression for A3: cmd_up used to do its own `podman inspect` with the
literal string "warden" while warden.proxy.is_running() used a separate
`podman ps --filter name=warden` (substring). The two could disagree, and
the difference let `brig up` print "Warden is running" while warden was
actually exited (and vice versa). cmd_up now calls is_running() directly.
"""

from __future__ import annotations

import types
import unittest
from unittest.mock import MagicMock, patch


def _args() -> types.SimpleNamespace:
    return types.SimpleNamespace()


class TestBrigUpDelegatesToIsRunning(unittest.TestCase):
    """cmd_up must use warden.proxy.is_running(), not roll its own check."""

    @patch("warden.proxy.start")
    @patch("warden.proxy.is_running")
    @patch("brig.vm.shell.vm_exists", return_value=True)
    @patch("brig.vm.shell.vm_running", return_value=True)
    def test_skips_start_when_proxy_running(
        self, mock_vm_running, mock_vm_exists, mock_is_running, mock_start
    ):
        mock_is_running.return_value = True
        from brig.commands.convenience_cmd import cmd_up

        with patch("brig.config.HostPaths.BRIG_HOME") as mock_home:
            mock_home.exists.return_value = True
            rc = cmd_up(_args())

        self.assertEqual(rc, 0)
        mock_is_running.assert_called()
        mock_start.assert_not_called()

    @patch("warden.proxy.start", return_value=True)
    @patch("warden.proxy.is_running")
    @patch("brig.vm.shell.vm_exists", return_value=True)
    @patch("brig.vm.shell.vm_running", return_value=True)
    def test_starts_when_proxy_not_running(
        self, mock_vm_running, mock_vm_exists, mock_is_running, mock_start
    ):
        mock_is_running.return_value = False
        from brig.commands.convenience_cmd import cmd_up

        with patch("brig.config.HostPaths.BRIG_HOME") as mock_home:
            mock_home.exists.return_value = True
            rc = cmd_up(_args())

        self.assertEqual(rc, 0)
        mock_start.assert_called_once()

    @patch("warden.proxy.start", return_value=False)
    @patch("warden.proxy.is_running", return_value=False)
    @patch("brig.vm.shell.vm_exists", return_value=True)
    @patch("brig.vm.shell.vm_running", return_value=True)
    def test_returns_nonzero_when_start_fails(
        self, mock_vm_running, mock_vm_exists, mock_is_running, mock_start
    ):
        from brig.commands.convenience_cmd import cmd_up

        with patch("brig.config.HostPaths.BRIG_HOME") as mock_home:
            mock_home.exists.return_value = True
            rc = cmd_up(_args())

        self.assertEqual(rc, 1)


class TestBrigUpDoesNotLieAboutExitedContainer(unittest.TestCase):
    """If is_running() reports False because the container exists-but-exited,
    cmd_up must run start() (which removes the stale container and restarts)."""

    @patch("warden.proxy.start", return_value=True)
    @patch("warden.proxy.is_running", return_value=False)
    @patch("warden.proxy.container_exists", return_value=True)
    @patch("brig.vm.shell.vm_exists", return_value=True)
    @patch("brig.vm.shell.vm_running", return_value=True)
    def test_recovers_from_exited_container(
        self, mock_vm_running, mock_vm_exists,
        mock_container_exists, mock_is_running, mock_start,
    ):
        from brig.commands.convenience_cmd import cmd_up

        with patch("brig.config.HostPaths.BRIG_HOME") as mock_home:
            mock_home.exists.return_value = True
            rc = cmd_up(_args())

        self.assertEqual(rc, 0)
        mock_start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
