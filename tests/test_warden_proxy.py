"""Tests for warden.proxy — proxy container lifecycle."""

import subprocess
import unittest
from unittest.mock import patch

from warden.proxy import container_exists, get_status, is_running, reload_policy, stop


class TestIsRunning(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "warden\n", "")
        self.assertTrue(is_running())

    @patch("warden.proxy.vm_run")
    def test_not_running(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "\n", "")
        self.assertFalse(is_running())


class TestContainerExists(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_exists(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "warden\n", "")
        self.assertTrue(container_exists())

    @patch("warden.proxy.vm_run")
    def test_not_exists(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "\n", "")
        self.assertFalse(container_exists())


class TestStop(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_stop_is_idempotent(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(stop())


class TestReloadPolicy(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        self.assertTrue(reload_policy())

    @patch("warden.proxy.vm_run")
    def test_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 1, "", "error")
        self.assertFalse(reload_policy())


class TestGetStatus(unittest.TestCase):
    @patch("warden.proxy.vm_run")
    def test_running_status(self, mock_run):
        import json
        data = [{"State": {"Status": "running"}, "NetworkSettings": {"Networks": {"proxy-external": {}}}}]
        mock_run.return_value = subprocess.CompletedProcess([], 0, json.dumps(data), "")
        status = get_status()
        self.assertTrue(status["running"])
        self.assertIn("proxy-external", status["networks"])

    @patch("warden.proxy.vm_run")
    def test_not_found(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess([], 125, "", "no such container")
        status = get_status()
        self.assertFalse(status["running"])
        self.assertFalse(status["exists"])
