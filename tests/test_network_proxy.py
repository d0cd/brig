"""Tests for brig.network.proxy — proxy state queries."""

import subprocess
import unittest
from unittest.mock import patch

from brig.network.proxy import proxy_running
from brig.ops.cache import clear as clear_cache


class TestProxyRunning(unittest.TestCase):
    def setUp(self):
        clear_cache()

    def tearDown(self):
        clear_cache()

    @patch("brig.network.proxy.vm_run")
    def test_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="running\n", stderr=""
        )
        self.assertTrue(proxy_running())

    @patch("brig.network.proxy.vm_run")
    def test_not_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="exited\n", stderr=""
        )
        self.assertFalse(proxy_running())

    @patch("brig.network.proxy.vm_run")
    def test_container_not_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=125, stdout="", stderr="no such container"
        )
        self.assertFalse(proxy_running())
