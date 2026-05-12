"""Tests for brig.network.proxy — proxy state queries."""

import subprocess
import unittest
from unittest.mock import patch

from brig.network.proxy import (
    connect_proxy_to_network,
    disconnect_proxy_from_network,
    get_proxy_ip,
    proxy_running,
)
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


class TestGetProxyIp(unittest.TestCase):
    @patch("brig.network.proxy.vm_run")
    def test_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='[{"NetworkSettings":{"Networks":{"brig-mycell":{"IPAddress":"10.60.1.1"}}}}]',
            stderr="",
        )
        self.assertEqual(get_proxy_ip("mycell"), "10.60.1.1")

    @patch("brig.network.proxy.vm_run")
    def test_not_connected(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='[{"NetworkSettings":{"Networks":{}}}]',
            stderr="",
        )
        self.assertIsNone(get_proxy_ip("mycell"))


class TestConnectDisconnect(unittest.TestCase):
    @patch("brig.network.proxy.vm_run")
    def test_connect_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.assertTrue(connect_proxy_to_network("mycell"))

    @patch("brig.network.proxy.vm_run")
    def test_connect_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        self.assertFalse(connect_proxy_to_network("mycell"))

    @patch("brig.network.proxy.vm_run")
    def test_disconnect_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.assertTrue(disconnect_proxy_from_network("mycell"))
