"""Tests for brig.sdk — programmatic interface."""

import unittest
from unittest.mock import MagicMock, patch

from brig.errors import BrigError
from brig.sdk import Brig, Cell, CellNotFoundError, ProfileError


class TestBrigRunSync(unittest.TestCase):
    """Test Brig.run_sync() validation and delegation."""

    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_creates_cell(self, mock_observe, mock_run):
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc123")

        b = Brig()
        cell = b.run_sync(name="test", image="alpine")
        self.assertEqual(cell.name, "test")
        mock_run.assert_called_once()

    def test_run_invalid_name_raises(self):
        b = Brig()
        with self.assertRaises(BrigError):
            b.run_sync(name="INVALID!", image="alpine")

    @patch("brig.sdk.run_cell")
    @patch("brig.sdk.observe")
    def test_run_with_profile(self, mock_observe, mock_run):
        from brig.cell.reconciler import ReconcileResult
        mock_run.return_value = ReconcileResult(success=True, container_id="abc")

        b = Brig()
        cell = b.run_sync(name="test", image="alpine", profile="untrusted")
        self.assertEqual(cell.name, "test")

    def test_run_unknown_profile_raises(self):
        b = Brig()
        with self.assertRaises(ProfileError):
            b.run_sync(name="test", image="alpine", profile="nonexistent")


class TestBrigListSync(unittest.TestCase):
    @patch("brig.sdk.vm_run")
    def test_list_empty(self, mock_run):
        import subprocess
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")

        b = Brig()
        cells = b.list_sync()
        self.assertEqual(cells, [])

    @patch("brig.sdk.vm_run")
    def test_list_with_cells(self, mock_run):
        import json
        import subprocess
        containers = [
            {"Names": ["brig-cell1"], "State": "running", "Image": "alpine"},
            {"Names": ["warden"], "State": "running", "Image": "mitmproxy"},
        ]
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(containers), "",
        )

        b = Brig()
        cells = b.list_sync()
        self.assertEqual(len(cells), 1)
        self.assertEqual(cells[0].name, "cell1")


class TestBrigCell(unittest.TestCase):
    @patch("brig.sdk.observe")
    def test_cell_not_found(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(exists=False)

        b = Brig()
        with self.assertRaises(CellNotFoundError):
            b.cell("nonexistent")

    @patch("brig.sdk.observe")
    def test_cell_found(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(exists=True, running=True)

        b = Brig()
        cell = b.cell("test")
        self.assertEqual(cell.name, "test")


class TestCell(unittest.TestCase):
    @patch("brig.sdk.observe")
    def test_is_alive_running(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(running=True)

        cell = Cell("test")
        self.assertTrue(cell.is_alive())

    @patch("brig.sdk.observe")
    def test_is_alive_stopped(self, mock_observe):
        from brig.cell.reconciler import CellState
        mock_observe.return_value = CellState(running=False)

        cell = Cell("test")
        self.assertFalse(cell.is_alive())

    @patch("brig.sdk.vm_run")
    def test_logs_sync(self, mock_run):
        import subprocess
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, "hello world\n", "",
        )

        cell = Cell("test")
        logs = cell.logs_sync()
        self.assertIn("hello world", logs)
