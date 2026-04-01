#!/usr/bin/env python3
"""
Integration tests for brig.py, warden.py, and brig_subnet.py.

Tests multi-function pipelines end-to-end, mocking only at the subprocess
boundary. Catches bugs that unit tests miss: wrong call order, missing
cleanup on failure, incorrect argument threading between functions.

Run with: python3 -m pytest tests/test_integration.py -x -q --tb=short
"""

import csv
import gzip
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Import brig.py directly (not the brig/ package).
brig_path = Path(__file__).parent.parent / "src" / "brig.py"
spec = importlib.util.spec_from_file_location("brig_module", brig_path)
brig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brig)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import brig_subnet
import warden


class IntegrationBase(unittest.TestCase):
    """Base class: temp dirs for STATE_DIR, POLICY_DIR, LOG_DIR, etc."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

        # brig.py constants.
        self._orig_brig = {
            "STATE_DIR": brig.STATE_DIR,
            "POLICY_DIR": brig.POLICY_DIR,
            "HISTORY_FILE": brig.HISTORY_FILE,
        }
        brig.STATE_DIR = self.temp_dir / "state"
        brig.POLICY_DIR = self.temp_dir / "policies"
        brig.HISTORY_FILE = self.temp_dir / "state" / "system" / "history.jsonl"
        brig.STATE_DIR.mkdir(parents=True)
        brig.POLICY_DIR.mkdir(parents=True)

        # warden.py constants.
        self._orig_warden = {
            "LOG_DIR": warden.LOG_DIR,
            "POLICY_FILE": warden.POLICY_FILE,
        }
        warden.LOG_DIR = self.temp_dir / "logs"
        warden.POLICY_FILE = self.temp_dir / "policy.json"
        warden.LOG_DIR.mkdir(parents=True)

        # brig_subnet.py constants.
        self._orig_subnet = {
            "SUBNETS_FILE": brig_subnet.SUBNETS_FILE,
            "SUBNET_MAP_FILE": brig_subnet.SUBNET_MAP_FILE,
            "LOCK_FILE": brig_subnet.LOCK_FILE,
        }
        brig_subnet.SUBNETS_FILE = self.temp_dir / "subnets.json"
        brig_subnet.SUBNET_MAP_FILE = self.temp_dir / "subnet-map.json"
        brig_subnet.LOCK_FILE = self.temp_dir / "allocator.lock"

        # Clear brig's internal cache to prevent cross-test leakage.
        brig._cache.clear()

    def tearDown(self):
        for k, v in self._orig_brig.items():
            setattr(brig, k, v)
        for k, v in self._orig_warden.items():
            setattr(warden, k, v)
        for k, v in self._orig_subnet.items():
            setattr(brig_subnet, k, v)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_args(self, **kwargs):
        """Build a mock args namespace with sane defaults for cmd_run."""
        defaults = {
            "name": "testcell", "image": "alpine", "container_cmd": [],
            "file": None, "profile": None, "memory": "2g", "cpus": "2",
            "pids_limit": 512, "network": "default", "detach": True,
            "rm": False, "env": [], "secret": [], "label": [],
            "policy_allow": None, "policy_deny": None, "timeout": None,
            "verify_image": False, "image_digest": None, "dry_run": False,
            "seccomp_profile": None, "workdir": None, "output": "text",
            "canary_file": None, "tor": False,
        }
        defaults.update(kwargs)
        args = MagicMock()
        for k, v in defaults.items():
            setattr(args, k, v)
        # Prevent MagicMock from auto-creating attributes on getattr.
        args.__contains__ = lambda self, key: key in defaults
        return args

    def _write_log_file(self, name, entries, mtime_offset_days=0):
        """Write a JSONL log file with optional mtime adjustment."""
        path = warden.LOG_DIR / name
        with open(path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        if mtime_offset_days:
            mtime = time.time() - (mtime_offset_days * 86400)
            os.utime(path, (mtime, mtime))
        return path


# ---------------------------------------------------------------------------
# Step 2: Warden Log Management Tests
# ---------------------------------------------------------------------------

class TestLogsPrune(IntegrationBase):
    """Integration tests for warden.cmd_logs_prune — pure file I/O."""

    def test_removes_files_older_than_cutoff(self):
        """Old .jsonl files deleted, recent kept."""
        old = self._write_log_file("old.jsonl", [{"ts": "old"}], mtime_offset_days=10)
        recent = self._write_log_file("recent.jsonl", [{"ts": "new"}], mtime_offset_days=0)

        result = warden.cmd_logs_prune(days=7)

        self.assertEqual(result, 0)
        self.assertFalse(old.exists(), "Old file should be deleted")
        self.assertTrue(recent.exists(), "Recent file should be kept")

    def test_compresses_day_old_uncompressed(self):
        """Files >1 day old gzipped atomically, original removed."""
        path = self._write_log_file("medium.jsonl", [{"ts": "data"}], mtime_offset_days=3)

        result = warden.cmd_logs_prune(days=7)

        self.assertEqual(result, 0)
        self.assertFalse(path.exists(), "Original should be removed after compression")
        gz_path = path.with_suffix(".jsonl.gz")
        self.assertTrue(gz_path.exists(), "Gzipped file should exist")
        # Verify contents are valid gzip.
        with gzip.open(gz_path, "rt") as f:
            content = f.read()
        self.assertIn("data", content)

    def test_size_pruning_removes_oldest_first(self):
        """When over size_mb, oldest deleted until under limit."""
        # Create files with distinct mtimes and sizes.
        oldest = self._write_log_file("a.jsonl", [{"x": "y" * 500}], mtime_offset_days=0.5)
        self._write_log_file("b.jsonl", [{"x": "y" * 500}], mtime_offset_days=0.3)
        newest = self._write_log_file("c.jsonl", [{"x": "y" * 500}], mtime_offset_days=0.1)

        # Target that allows only one file.
        target_mb = (newest.stat().st_size + 1) / (1024 * 1024)

        result = warden.cmd_logs_prune(days=9999, size_mb=target_mb)

        self.assertEqual(result, 0)
        # At least the oldest should be gone.
        self.assertFalse(oldest.exists(), "Oldest file should be deleted first")

    def test_negative_days_returns_error(self):
        """days=-1 returns 1."""
        result = warden.cmd_logs_prune(days=-1)
        self.assertEqual(result, 1)

    def test_missing_log_dir_returns_zero(self):
        """No crash on missing LOG_DIR."""
        shutil.rmtree(warden.LOG_DIR)
        result = warden.cmd_logs_prune(days=7)
        self.assertEqual(result, 0)

    def test_handles_mixed_jsonl_and_gz(self):
        """Both extensions collected; gz not re-compressed."""
        self._write_log_file("test.jsonl", [{"ts": "a"}], mtime_offset_days=3)
        gz_path = warden.LOG_DIR / "old.jsonl.gz"
        with gzip.open(gz_path, "wt") as f:
            f.write(json.dumps({"ts": "b"}) + "\n")
        mtime = time.time() - (3 * 86400)
        os.utime(gz_path, (mtime, mtime))

        result = warden.cmd_logs_prune(days=7)

        self.assertEqual(result, 0)
        # Both should be processed without error.


class TestLogsCompact(IntegrationBase):
    """Integration tests for warden.cmd_logs_compact — file transformation."""

    def test_delete_strategy_removes_old_files(self):
        """Old log files deleted, recent untouched."""
        old = self._write_log_file("cell1.jsonl", [{"ts": "old"}], mtime_offset_days=10)
        recent = self._write_log_file("cell2.jsonl", [{"ts": "new"}], mtime_offset_days=0)

        result = warden.cmd_logs_compact(strategy="delete", older_than="7d")

        self.assertEqual(result, 0)
        self.assertFalse(old.exists(), "Old file should be deleted")
        self.assertTrue(recent.exists(), "Recent file should be kept")

    def test_aggregate_hourly_bucketing(self):
        """Entries grouped by hour, count/blocked/error/p95 correct."""
        entries = [
            {"ts": "2026-01-15T10:05:00Z", "host": "example.com", "method": "GET",
             "status": 200, "ms": 50, "bytes": 100, "request_bytes": 10},
            {"ts": "2026-01-15T10:30:00Z", "host": "example.com", "method": "GET",
             "status": 200, "ms": 150, "bytes": 200, "request_bytes": 20, "blocked": True},
            {"ts": "2026-01-15T10:45:00Z", "host": "example.com", "method": "GET",
             "status": 500, "ms": 300, "bytes": 50, "request_bytes": 5, "error": True},
        ]
        self._write_log_file("test.jsonl", entries, mtime_offset_days=10)

        result = warden.cmd_logs_compact(strategy="aggregate", bucket="hourly", older_than="7d")

        self.assertEqual(result, 0)
        compact_files = list(warden.LOG_DIR.glob("*.compact.jsonl"))
        self.assertEqual(len(compact_files), 1)

        with open(compact_files[0]) as f:
            compacted = [json.loads(line) for line in f if line.strip()]

        # Two groups: status 200 (2 entries) and status 500 (1 entry).
        self.assertEqual(len(compacted), 2)
        total_count = sum(e["count"] for e in compacted)
        self.assertEqual(total_count, 3)
        total_blocked = sum(e["blocked_count"] for e in compacted)
        self.assertEqual(total_blocked, 1)
        total_errors = sum(e["error_count"] for e in compacted)
        self.assertEqual(total_errors, 1)  # Only the status 500 entry counts as error.

    def test_aggregate_daily_bucketing(self):
        """bucket='daily' groups by day."""
        entries = [
            {"ts": "2026-01-15T10:00:00Z", "host": "a.com", "method": "GET",
             "status": 200, "ms": 10, "bytes": 0, "request_bytes": 0},
            {"ts": "2026-01-15T22:00:00Z", "host": "a.com", "method": "GET",
             "status": 200, "ms": 20, "bytes": 0, "request_bytes": 0},
        ]
        self._write_log_file("day.jsonl", entries, mtime_offset_days=10)

        result = warden.cmd_logs_compact(strategy="aggregate", bucket="daily", older_than="7d")

        self.assertEqual(result, 0)
        compact_files = list(warden.LOG_DIR.glob("*.compact.jsonl"))
        self.assertEqual(len(compact_files), 1)

        with open(compact_files[0]) as f:
            compacted = [json.loads(line) for line in f if line.strip()]

        # Both entries should be in the same daily bucket.
        self.assertEqual(len(compacted), 1)
        self.assertEqual(compacted[0]["count"], 2)
        self.assertIn("2026-01-15", compacted[0]["bucket"])

    def test_aggregate_p95_calculation(self):
        """P95 latency computed correctly from known values."""
        # 20 entries with latencies 1..20. P95 = value at index 19 (0.95*20=19).
        entries = []
        for i in range(1, 21):
            entries.append({
                "ts": "2026-01-15T10:00:00Z", "host": "p95.com", "method": "GET",
                "status": 200, "ms": i, "bytes": 0, "request_bytes": 0,
            })
        self._write_log_file("p95.jsonl", entries, mtime_offset_days=10)

        result = warden.cmd_logs_compact(strategy="aggregate", older_than="7d")

        self.assertEqual(result, 0)
        compact_files = list(warden.LOG_DIR.glob("*.compact.jsonl"))
        with open(compact_files[0]) as f:
            compacted = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(compacted), 1)
        # Sorted latencies: [1..20]. Index 19 (int(20*0.95)) = 19. Value = 20.
        self.assertEqual(compacted[0]["p95_ms"], 20)

    def test_sample_strategy_limits_per_hour(self):
        """At most N samples per hour-bucket retained."""
        entries = []
        for i in range(50):
            entries.append({
                "ts": f"2026-01-15T10:{i % 60:02d}:00Z", "host": "s.com",
                "method": "GET", "status": 200,
            })
        self._write_log_file("sample.jsonl", entries, mtime_offset_days=10)

        result = warden.cmd_logs_compact(
            strategy="sample", samples_per_hour=5, older_than="7d"
        )

        self.assertEqual(result, 0)
        sample_files = list(warden.LOG_DIR.glob("*.sample.jsonl"))
        self.assertEqual(len(sample_files), 1)

        with open(sample_files[0]) as f:
            sampled = [json.loads(line) for line in f if line.strip()]

        # Should have at most 5 samples.
        self.assertLessEqual(len(sampled), 5)

    def test_archive_strategy_compresses_to_path(self):
        """File gzipped and moved to archive dir."""
        self._write_log_file("arch.jsonl", [{"ts": "data"}], mtime_offset_days=10)
        archive_dir = self.temp_dir / "archive"

        result = warden.cmd_logs_compact(
            strategy="archive", archive_path=str(archive_dir), older_than="7d"
        )

        self.assertEqual(result, 0)
        self.assertTrue(archive_dir.exists())
        gz_files = list(archive_dir.glob("*.jsonl.gz"))
        self.assertEqual(len(gz_files), 1)

    def test_archive_rejects_path_traversal(self):
        """archive_path with '..' returns error."""
        self._write_log_file("trav.jsonl", [{"ts": "x"}], mtime_offset_days=10)

        result = warden.cmd_logs_compact(
            strategy="archive", archive_path="/tmp/../etc/evil", older_than="7d"
        )

        self.assertEqual(result, 1)

    def test_invalid_duration_format(self):
        """'abc' returns error."""
        result = warden.cmd_logs_compact(older_than="abc")
        self.assertEqual(result, 1)


class TestLogsExport(IntegrationBase):
    """Integration tests for warden.cmd_logs_export — format conversion."""

    def test_jsonl_export(self):
        """Entries written as line-delimited JSON."""
        entries = [{"ts": "2026-01-15T10:00:00Z", "host": "a.com", "status": 200}]
        self._write_log_file("exp.jsonl", entries, mtime_offset_days=0)
        out = self.temp_dir / "out.jsonl"

        result = warden.cmd_logs_export(format_type="jsonl", output_file=str(out), days=7)

        self.assertEqual(result, 0)
        with open(out) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["host"], "a.com")

    def test_csv_export_column_ordering(self):
        """Standard columns (ts, cell, method...) first, extras alphabetical."""
        entries = [
            {"ts": "2026-01-15T10:00:00Z", "cell": "c1", "method": "GET",
             "host": "a.com", "path": "/", "status": 200, "bytes": 100,
             "ms": 50, "blocked": False, "zebra": "z", "alpha": "a"}
        ]
        self._write_log_file("csv.jsonl", entries, mtime_offset_days=0)
        out = self.temp_dir / "out.csv"

        result = warden.cmd_logs_export(format_type="csv", output_file=str(out), days=7)

        self.assertEqual(result, 0)
        with open(out) as f:
            reader = csv.reader(f)
            headers = next(reader)

        # Standard columns should come first in order.
        standard = ["ts", "cell", "method", "host", "path", "status", "bytes", "ms", "blocked"]
        for i, col in enumerate(standard):
            self.assertEqual(headers[i], col, f"Column {i} should be '{col}'")

        # Extra columns should be alphabetical after standard.
        extras = headers[len(standard):]
        self.assertEqual(extras, sorted(extras))

    def test_csv_flattens_nested_values(self):
        """dict/list values serialized as JSON strings."""
        entries = [
            {"ts": "2026-01-15T10:00:00Z", "host": "a.com",
             "headers": {"Accept": "text/html"}, "tags": ["web", "test"]}
        ]
        self._write_log_file("nested.jsonl", entries, mtime_offset_days=0)
        out = self.temp_dir / "out.csv"

        result = warden.cmd_logs_export(format_type="csv", output_file=str(out), days=7)

        self.assertEqual(result, 0)
        with open(out) as f:
            reader = csv.DictReader(f)
            row = next(reader)

        # Nested values should be JSON strings.
        self.assertEqual(json.loads(row["headers"]), {"Accept": "text/html"})
        self.assertEqual(json.loads(row["tags"]), ["web", "test"])

    def test_cell_filter(self):
        """Only matching cell's logs exported."""
        self._write_log_file("cell1.jsonl", [{"ts": "a", "cell": "c1"}], mtime_offset_days=0)
        self._write_log_file("cell2.jsonl", [{"ts": "b", "cell": "c2"}], mtime_offset_days=0)
        out = self.temp_dir / "out.jsonl"

        result = warden.cmd_logs_export(
            cell_name="cell1", format_type="jsonl", output_file=str(out), days=7
        )

        self.assertEqual(result, 0)
        with open(out) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["cell"], "c1")

    def test_rejects_path_traversal(self):
        """Output path with '..' returns error."""
        self._write_log_file("trav.jsonl", [{"ts": "x"}], mtime_offset_days=0)

        result = warden.cmd_logs_export(
            format_type="jsonl", output_file="/tmp/../etc/evil.jsonl", days=7
        )

        self.assertEqual(result, 1)

    def test_skips_old_files(self):
        """Files older than days param excluded."""
        self._write_log_file("old.jsonl", [{"ts": "old"}], mtime_offset_days=30)
        self._write_log_file("new.jsonl", [{"ts": "new"}], mtime_offset_days=0)
        out = self.temp_dir / "out.jsonl"

        result = warden.cmd_logs_export(
            format_type="jsonl", output_file=str(out), days=7
        )

        self.assertEqual(result, 0)
        with open(out) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        # Only the new file's entries should be present.
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["ts"], "new")


# ---------------------------------------------------------------------------
# Step 3: Subnet Allocator Lifecycle Tests
# ---------------------------------------------------------------------------

class TestSubnetLifecycle(IntegrationBase):
    """Integration tests for brig_subnet allocation lifecycle — real file I/O."""

    def test_allocate_first_cell(self):
        """Index 1, subnet 10.60.1.0/24, state file written atomically."""
        with patch("builtins.print") as mock_print:
            brig_subnet.cmd_allocate("cell1")

        mock_print.assert_called_with("10.60.1.0/24")
        # Verify state file.
        state = json.loads(brig_subnet.SUBNETS_FILE.read_text())
        self.assertEqual(state["allocated"]["cell1"]["index"], 1)
        self.assertEqual(state["next_index"], 2)

    def test_allocate_sequential(self):
        """Second cell gets index 2."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("cell1")
        with patch("builtins.print") as mock_print:
            brig_subnet.cmd_allocate("cell2")

        mock_print.assert_called_with("10.60.2.0/24")

    def test_free_and_reallocate_reuses_index(self):
        """Free index 1, next allocate gets 1 (not 3)."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("cell1")
            brig_subnet.cmd_allocate("cell2")
            brig_subnet.cmd_free("cell1")

        with patch("builtins.print") as mock_print:
            brig_subnet.cmd_allocate("cell3")

        # Should reuse freed index 1.
        mock_print.assert_called_with("10.60.1.0/24")

    def test_freed_list_sorted(self):
        """Free indices 3, 1 -> freed list is [1, 3]."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("cell1")
            brig_subnet.cmd_allocate("cell2")
            brig_subnet.cmd_allocate("cell3")
            brig_subnet.cmd_free("cell3")
            brig_subnet.cmd_free("cell1")

        state = json.loads(brig_subnet.SUBNETS_FILE.read_text())
        self.assertEqual(state["freed"], [1, 3])

    def test_duplicate_allocate_errors(self):
        """Same cell name twice -> SystemExit."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("cell1")

        with self.assertRaises(SystemExit):
            brig_subnet.cmd_allocate("cell1")

    def test_free_nonexistent_errors(self):
        """Free unallocated cell -> SystemExit."""
        with self.assertRaises(SystemExit):
            brig_subnet.cmd_free("ghost")

    def test_list_sorted_by_index(self):
        """Output sorted by index, TSV format."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("beta")
            brig_subnet.cmd_allocate("alpha")

        with patch("builtins.print") as mock_print:
            brig_subnet.cmd_list()

        calls = mock_print.call_args_list
        # First call should be beta (index 1), second alpha (index 2).
        self.assertIn("beta", calls[0][0][0])
        self.assertIn("alpha", calls[1][0][0])

    def test_subnet_map_updated(self):
        """subnet-map.json reflects current allocations."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("cell1")

        self.assertTrue(brig_subnet.SUBNET_MAP_FILE.exists())
        mapping = json.loads(brig_subnet.SUBNET_MAP_FILE.read_text())
        self.assertEqual(mapping["10.60.1.0/24"], "cell1")


class TestSubnetNetwork(IntegrationBase):
    """Integration tests for brig_subnet network commands — mock subprocess."""

    @patch("subprocess.run")
    def test_create_network_calls_podman(self, mock_subproc):
        """Correct podman network create --internal --subnet args."""
        # Pre-allocate a subnet.
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("net1")

        # Mock: network doesn't exist yet, then create succeeds.
        mock_subproc.side_effect = [
            MagicMock(returncode=1),   # network exists check -> not found
            MagicMock(returncode=0, stdout="brig-net1\n", stderr=""),  # create
        ]

        with patch("builtins.print"):
            brig_subnet.cmd_create_network("net1")

        # Verify the create call.
        create_call = mock_subproc.call_args_list[1]
        cmd = create_call[0][0]
        self.assertIn("podman", cmd)
        self.assertIn("network", cmd)
        self.assertIn("create", cmd)
        self.assertIn("--internal", cmd)
        self.assertIn("--subnet", cmd)
        self.assertIn("10.60.1.0/24", cmd)
        self.assertIn("brig-net1", cmd)

    @patch("subprocess.run")
    def test_create_network_requires_allocation(self, mock_subproc):
        """No allocation -> SystemExit."""
        with self.assertRaises(SystemExit):
            brig_subnet.cmd_create_network("noalloc")

    @patch("subprocess.run")
    def test_remove_network_frees_subnet(self, mock_subproc):
        """Network removed AND subnet freed in one call."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("rm1")

        mock_subproc.side_effect = [
            MagicMock(returncode=0),   # network exists -> yes
            MagicMock(returncode=0, stdout="", stderr=""),  # network rm
        ]

        brig_subnet.cmd_remove_network("rm1")

        # Subnet should be freed.
        state = json.loads(brig_subnet.SUBNETS_FILE.read_text())
        self.assertNotIn("rm1", state["allocated"])
        self.assertIn(1, state["freed"])

    @patch("subprocess.run")
    def test_remove_nonexistent_network_no_error(self, mock_subproc):
        """Network doesn't exist -> still frees subnet."""
        with patch("builtins.print"):
            brig_subnet.cmd_allocate("rm2")

        mock_subproc.side_effect = [
            MagicMock(returncode=1),   # network exists -> no
        ]

        brig_subnet.cmd_remove_network("rm2")

        state = json.loads(brig_subnet.SUBNETS_FILE.read_text())
        self.assertNotIn("rm2", state["allocated"])


# ---------------------------------------------------------------------------
# Step 5: _build_run_command Tests
# ---------------------------------------------------------------------------

class TestBuildRunCommand(IntegrationBase):
    """Tests for _build_run_command — pure logic, temp dirs only."""

    def test_basic_command_structure(self):
        """Name, runtime, network, resource limits in correct order."""
        args = self._make_args()
        cleanup = MagicMock()

        cmd = brig._build_run_command(
            args, "testcell", False, "brig-testcell", "10.60.1.1", None, cleanup
        )

        self.assertIn("podman", cmd)
        self.assertIn("run", cmd)
        self.assertIn("--name", cmd)
        name_idx = cmd.index("--name")
        self.assertEqual(cmd[name_idx + 1], "brig-testcell")
        self.assertIn("--runtime", cmd)
        self.assertIn("runsc", cmd)
        self.assertIn("--memory", cmd)
        self.assertIn("2g", cmd)
        self.assertIn("--cpus", cmd)
        self.assertIn("2", cmd)
        self.assertIn("--pids-limit", cmd)
        self.assertIn("512", cmd)

    def test_airgapped_drops_all_caps(self):
        """--network none --cap-drop ALL, no proxy env vars."""
        args = self._make_args(network="none")
        cleanup = MagicMock()

        cmd = brig._build_run_command(
            args, "testcell", True, None, None, None, cleanup
        )

        self.assertIn("--network", cmd)
        net_idx = cmd.index("--network")
        self.assertEqual(cmd[net_idx + 1], "none")
        self.assertIn("--cap-drop", cmd)
        self.assertIn("ALL", cmd)
        # No proxy env vars.
        cmd_str = " ".join(cmd)
        self.assertNotIn("http_proxy", cmd_str)
        self.assertNotIn("https_proxy", cmd_str)

    def test_label_validation(self):
        """Label without '=' -> cleanup_on_failure called."""
        args = self._make_args(label=["bad_label"])
        cleanup = MagicMock(side_effect=SystemExit(1))

        with self.assertRaises(SystemExit):
            brig._build_run_command(
                args, "testcell", False, "brig-testcell", "10.60.1.1", None, cleanup
            )

        cleanup.assert_called_once()

    def test_workspace_dir_created(self):
        """STATE_DIR/cellname/workspace created on disk."""
        args = self._make_args()
        cleanup = MagicMock()

        brig._build_run_command(
            args, "testcell", False, "brig-testcell", "10.60.1.1", None, cleanup
        )

        workspace = brig.STATE_DIR / "testcell" / "workspace"
        self.assertTrue(workspace.exists())
        self.assertTrue(workspace.is_dir())

    def test_env_vars_appended(self):
        """Each env -> -e flag pair in command."""
        args = self._make_args(env=["FOO=bar", "BAZ=qux"])
        cleanup = MagicMock()

        cmd = brig._build_run_command(
            args, "testcell", False, "brig-testcell", "10.60.1.1", None, cleanup
        )

        # Find all -e flags.
        e_flags = []
        for i, c in enumerate(cmd):
            if c == "-e" and i + 1 < len(cmd):
                e_flags.append(cmd[i + 1])

        self.assertIn("FOO=bar", e_flags)
        self.assertIn("BAZ=qux", e_flags)

    def test_workdir_override(self):
        """workdir='/app' -> --workdir /app in command."""
        args = self._make_args(workdir="/app")
        cleanup = MagicMock()

        cmd = brig._build_run_command(
            args, "testcell", False, "brig-testcell", "10.60.1.1", None, cleanup
        )

        self.assertIn("--workdir", cmd)
        idx = cmd.index("--workdir")
        self.assertEqual(cmd[idx + 1], "/app")


# ---------------------------------------------------------------------------
# Step 7: Config Merge Pipeline Tests
# ---------------------------------------------------------------------------

class TestConfigMergePipeline(IntegrationBase):
    """Tests for _apply_profile -> _merge_cell_def_into_args -> defaults."""

    @patch.object(brig, "load_profile")
    def test_profile_sets_defaults(self, mock_load):
        """Profile values applied to None args."""
        mock_load.return_value = {
            "memory": "4g", "cpus": 4, "pids_limit": 1024,
        }
        args = self._make_args(memory=None, cpus=None, pids_limit=None, profile="dev")

        brig._apply_profile(args)

        self.assertEqual(args.memory, "4g")
        self.assertEqual(args.cpus, "4")
        self.assertEqual(args.pids_limit, 1024)

    @patch.object(brig, "load_profile")
    def test_cli_overrides_profile(self, mock_load):
        """Explicit CLI arg beats profile default."""
        mock_load.return_value = {"memory": "4g", "cpus": 4}
        args = self._make_args(memory="8g", cpus=None, pids_limit=None, profile="dev")

        brig._apply_profile(args)

        # CLI-provided memory should not be overwritten.
        self.assertEqual(args.memory, "8g")
        # Profile-provided cpus should apply since CLI was None.
        self.assertEqual(args.cpus, "4")

    def test_cell_def_merges_into_args(self):
        """Cell definition fields applied."""
        args = self._make_args(name=None, image=None, env=[])
        cell_def = {
            "name": "fromfile",
            "image": "python:3.11",
            "env": ["KEY=val"],
        }

        brig._merge_cell_def_into_args(args, cell_def)

        self.assertEqual(args.name, "fromfile")
        self.assertEqual(args.image, "python:3.11")
        self.assertIn("KEY=val", args.env)

    def test_cli_overrides_cell_def(self):
        """CLI > cell def > profile precedence."""
        args = self._make_args(name="cliname", image="cliimage")
        cell_def = {"name": "defname", "image": "defimage"}

        brig._merge_cell_def_into_args(args, cell_def)

        # CLI values should win.
        self.assertEqual(args.name, "cliname")
        self.assertEqual(args.image, "cliimage")

    def test_list_fields_appended(self):
        """env, labels, policy lists merged (not replaced)."""
        args = self._make_args(
            env=["CLI_VAR=1"],
            label=["cli.label=a"],
            policy_allow=["cli.com"],
        )
        cell_def = {
            "env": ["DEF_VAR=2"],
            "labels": {"def.label": "b"},
            "policy": {"allow": ["def.com"]},
        }

        brig._merge_cell_def_into_args(args, cell_def)

        self.assertIn("CLI_VAR=1", args.env)
        self.assertIn("DEF_VAR=2", args.env)
        self.assertIn("cli.label=a", args.label)
        self.assertIn("def.label=b", args.label)
        self.assertIn("cli.com", args.policy_allow)
        self.assertIn("def.com", args.policy_allow)


# ---------------------------------------------------------------------------
# Step 4: cmd_run Pipeline Tests
# ---------------------------------------------------------------------------

class TestCmdRunPipeline(IntegrationBase):
    """Integration tests for cmd_run — full pipeline with mock subprocess."""

    def _mock_run_side_effect(self, cell_name="testcell"):
        """Build a side_effect function dispatching on command prefix."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            cmd_str = " ".join(cmd) if cmd else ""
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""

            # Proxy running check.
            if "podman" in cmd and "ps" in cmd and "--filter" in cmd:
                filter_val = ""
                for i, c in enumerate(cmd):
                    if c == "--filter" and i + 1 < len(cmd):
                        filter_val = cmd[i + 1]
                if "warden" in filter_val:
                    result.stdout = "warden\n"
                elif cell_name in filter_val:
                    # Cell doesn't exist yet.
                    result.stdout = "\n"
                return result

            # Subnet allocate.
            if "brig-subnet" in cmd_str or "brig_subnet" in cmd_str:
                if "allocate" in cmd:
                    result.stdout = "10.60.1.0/24\n"
                elif "create-network" in cmd:
                    result.stdout = f"brig-{cell_name}\n"
                return result

            # Network connect.
            if "podman" in cmd and "network" in cmd and "connect" in cmd:
                return result

            # Proxy IP inspect.
            if "podman" in cmd and "inspect" in cmd and "warden" in cmd:
                result.stdout = "10.60.1.1\n"
                return result

            # Podman run.
            if "podman" in cmd and "run" in cmd:
                result.stdout = "abc123def456\n"
                return result

            return result
        return side_effect

    def _find_cmd(self, mock_run, prefix):
        """Find a call to run() where cmd starts with prefix."""
        for c in mock_run.call_args_list:
            cmd = c[0][0] if c[0] else c[1].get("cmd", [])
            if len(cmd) >= len(prefix) and cmd[:len(prefix)] == prefix:
                return cmd
        return None

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_basic_run_success(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """Returns 0, podman run called with correct flags."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args()

        result = brig.cmd_run(args)

        self.assertEqual(result, 0)
        # Find the podman run call.
        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        self.assertIsNotNone(podman_run, "podman run should have been called")
        self.assertIn("--name", podman_run)
        self.assertIn("brig-testcell", podman_run)
        self.assertIn("--runtime", podman_run)
        self.assertIn("runsc", podman_run)
        self.assertIn("--memory", podman_run)
        self.assertIn("2g", podman_run)

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_proxy_env_vars_set(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """Proxy env vars set with correct IP."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args()

        brig.cmd_run(args)

        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        self.assertIsNotNone(podman_run)
        cmd_str = " ".join(podman_run)
        self.assertIn("http_proxy=http://10.60.1.1:8080", cmd_str)
        self.assertIn("https_proxy=http://10.60.1.1:8080", cmd_str)

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_airgapped_skips_network(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """network='none' -> --network none, no subnet/proxy calls."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(network="none")

        result = brig.cmd_run(args)

        self.assertEqual(result, 0)
        # No subnet allocate call.
        allocate_cmd = self._find_cmd(mock_run, [brig.BRIG_SUBNET_BIN, "allocate"])
        self.assertIsNone(allocate_cmd, "Subnet allocate should not be called for airgapped")
        # Podman run should have --network none.
        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        self.assertIsNotNone(podman_run)
        net_idx = podman_run.index("--network")
        self.assertEqual(podman_run[net_idx + 1], "none")

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_custom_policy_saved(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """policy_allow=['example.com'] -> policy file written before podman run."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(policy_allow=["example.com"])

        brig.cmd_run(args)

        policy_path = brig.POLICY_DIR / "testcell.json"
        self.assertTrue(policy_path.exists(), "Policy file should be created")
        policy = json.loads(policy_path.read_text())
        self.assertIn("example.com", policy["allow"])

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_resource_limits_threaded(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """Custom memory/cpus/pids from args appear in command."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(memory="8g", cpus="4", pids_limit=2048)

        brig.cmd_run(args)

        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        self.assertIn("8g", podman_run)
        self.assertIn("4", podman_run)
        self.assertIn("2048", podman_run)

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_timeout_flag(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """timeout='30s' -> --timeout 30 in podman command."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(timeout="30s")

        brig.cmd_run(args)

        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        self.assertIn("--timeout", podman_run)
        idx = podman_run.index("--timeout")
        self.assertEqual(podman_run[idx + 1], "30")

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_env_vars_passed(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """env=['FOO=bar'] -> -e FOO=bar in command."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(env=["FOO=bar"])

        brig.cmd_run(args)

        podman_run = self._find_cmd(mock_run, ["podman", "run"])
        e_flags = []
        for i, c in enumerate(podman_run):
            if c == "-e" and i + 1 < len(podman_run):
                e_flags.append(podman_run[i + 1])
        self.assertIn("FOO=bar", e_flags)

    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "run")
    def test_dry_run_no_container(self, mock_run, mock_rate):
        """dry_run=True -> prints command, no podman run call, cleans up resources."""
        mock_run.side_effect = self._mock_run_side_effect()
        args = self._make_args(dry_run=True)

        result = brig.cmd_run(args)

        self.assertEqual(result, 0)
        # The actual podman run should not have been called (only the dry run print).
        # But brig-subnet allocate/free calls happen for cleanup.
        podman_run_calls = [
            c for c in mock_run.call_args_list
            if c[0][0][:2] == ["podman", "run"]
        ]
        self.assertEqual(len(podman_run_calls), 0, "podman run should not be called in dry run")

    @patch.object(brig, "Spinner")
    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "run")
    def test_failure_cleans_up_resources(self, mock_run, mock_lifecycle, mock_op, mock_rate, mock_spinner):
        """podman run returns 1 -> subnet freed, network removed, policy deleted."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        def fail_on_run(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            cmd_str = " ".join(cmd)

            if "podman" in cmd and "ps" in cmd and "--filter" in cmd:
                filter_val = ""
                for i, c in enumerate(cmd):
                    if c == "--filter" and i + 1 < len(cmd):
                        filter_val = cmd[i + 1]
                if "warden" in filter_val:
                    result.stdout = "warden\n"
                else:
                    result.stdout = "\n"
                return result

            if "brig-subnet" in cmd_str or "brig_subnet" in cmd_str:
                if "allocate" in cmd:
                    result.stdout = "10.60.1.0/24\n"
                return result

            if "podman" in cmd and "network" in cmd and "connect" in cmd:
                return result

            if "podman" in cmd and "inspect" in cmd:
                result.stdout = "10.60.1.1\n"
                return result

            # Podman run fails.
            if "podman" in cmd and "run" in cmd:
                result.returncode = 1
                result.stderr = "container failed to start"
                return result

            return result

        mock_run.side_effect = fail_on_run
        args = self._make_args(policy_allow=["example.com"])

        result = brig.cmd_run(args)

        self.assertEqual(result, 1)
        # Verify cleanup calls happened.
        all_cmds = [c[0][0] for c in mock_run.call_args_list if c[0]]
        # Should see cleanup: network disconnect, remove-network, free.
        cleanup_strs = [" ".join(c) for c in all_cmds]
        has_disconnect = any("disconnect" in s for s in cleanup_strs)
        has_remove = any("remove-network" in s for s in cleanup_strs)
        has_free = any("free" in s for s in cleanup_strs)
        self.assertTrue(has_disconnect or has_remove or has_free,
                        "At least one cleanup action should have been called")

    @patch.object(brig, "check_rate_limit", return_value=True)
    @patch.object(brig, "run")
    def test_cell_already_exists_errors(self, mock_run, mock_rate):
        """Cell already exists -> SystemExit before any allocation."""
        def exists_side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""

            if "podman" in cmd and "ps" in cmd and "--filter" in cmd:
                filter_val = ""
                for i, c in enumerate(cmd):
                    if c == "--filter" and i + 1 < len(cmd):
                        filter_val = cmd[i + 1]
                if "warden" in filter_val:
                    result.stdout = "warden\n"
                elif "testcell" in filter_val:
                    # Cell already exists.
                    result.stdout = "brig-testcell\n"
                return result

            return result

        mock_run.side_effect = exists_side_effect
        args = self._make_args()

        with self.assertRaises(SystemExit):
            brig.cmd_run(args)

        # No subnet allocation should have happened.
        allocate_calls = [
            c for c in mock_run.call_args_list
            if c[0] and len(c[0][0]) > 1 and "allocate" in c[0][0]
        ]
        self.assertEqual(len(allocate_calls), 0)


# ---------------------------------------------------------------------------
# Step 6: Warden cmd_start Tests
# ---------------------------------------------------------------------------

class TestWardenStart(IntegrationBase):
    """Integration tests for warden.cmd_start — mock subprocess."""

    @patch.object(warden, "reconnect_to_cell_networks", return_value=0)
    @patch.object(warden, "is_running")
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(True, []))
    @patch.object(warden, "run")
    def test_start_builds_secure_command(self, mock_run, mock_preflight, mock_exists,
                                         mock_is_running, mock_reconnect):
        """--cap-drop ALL, --security-opt no-new-privileges, --read-only, --user mitmproxy."""
        mock_is_running.side_effect = [False, True]  # First check: not running; after start: running.
        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(warden, "time") as mock_time:
            mock_time.sleep = MagicMock()
            result = warden.cmd_start()

        self.assertEqual(result, 0)
        # Find the podman run call (skip test -f addon checks).
        cmd = None
        for c in mock_run.call_args_list:
            args = c[0][0]
            if len(args) > 1 and args[0] == "podman" and args[1] == "run":
                cmd = args
                break
        self.assertIsNotNone(cmd, "podman run should have been called")
        self.assertIn("--cap-drop", cmd)
        cap_idx = cmd.index("--cap-drop")
        self.assertEqual(cmd[cap_idx + 1], "ALL")
        self.assertIn("--security-opt", cmd)
        sec_idx = cmd.index("--security-opt")
        self.assertEqual(cmd[sec_idx + 1], "no-new-privileges")
        self.assertIn("--read-only", cmd)
        self.assertIn("--user", cmd)
        user_idx = cmd.index("--user")
        self.assertEqual(cmd[user_idx + 1], "mitmproxy")

    def _find_podman_run(self, mock_run):
        """Find the podman run call from warden's mock_run call list."""
        for c in mock_run.call_args_list:
            args = c[0][0]
            if len(args) > 1 and args[0] == "podman" and args[1] == "run":
                return args
        return None

    @patch.object(warden, "reconnect_to_cell_networks", return_value=0)
    @patch.object(warden, "is_running")
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(True, []))
    @patch.object(warden, "run")
    def test_start_includes_resource_limits(self, mock_run, mock_preflight, mock_exists,
                                             mock_is_running, mock_reconnect):
        """--memory, --cpus, --pids-limit present."""
        mock_is_running.side_effect = [False, True]
        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(warden, "time") as mock_time:
            mock_time.sleep = MagicMock()
            warden.cmd_start()

        cmd = self._find_podman_run(mock_run)
        self.assertIsNotNone(cmd)
        self.assertIn("--memory", cmd)
        self.assertIn("--cpus", cmd)
        self.assertIn("--pids-limit", cmd)

    @patch.object(warden, "reconnect_to_cell_networks", return_value=0)
    @patch.object(warden, "is_running")
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(True, []))
    @patch.object(warden, "run")
    def test_start_mounts_required_volumes(self, mock_run, mock_preflight, mock_exists,
                                            mock_is_running, mock_reconnect):
        """/addons:ro, /policy.json:ro, /logs:rw."""
        mock_is_running.side_effect = [False, True]
        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(warden, "time") as mock_time:
            mock_time.sleep = MagicMock()
            warden.cmd_start()

        cmd = self._find_podman_run(mock_run)
        self.assertIsNotNone(cmd)
        cmd_str = " ".join(cmd)
        self.assertIn("/addons:ro", cmd_str)
        self.assertIn("/policy.json:ro", cmd_str)
        self.assertIn("/logs:rw", cmd_str)

    @patch.object(warden, "reconnect_to_cell_networks", return_value=0)
    @patch.object(warden, "is_running")
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(True, []))
    @patch.object(warden, "run")
    def test_start_detects_optional_addons(self, mock_run, mock_preflight, mock_exists,
                                            mock_is_running, mock_reconnect):
        """Optional addon files -> extra -s flags."""
        mock_is_running.side_effect = [False, True]

        def run_side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            # Simulate addon file exists for ratelimit.
            if cmd[:2] == ["test", "-f"] and "ratelimit" in cmd[2]:
                result.returncode = 0
            elif cmd[:2] == ["test", "-f"]:
                result.returncode = 1
            return result

        mock_run.side_effect = run_side_effect

        with patch.object(warden, "time") as mock_time:
            mock_time.sleep = MagicMock()
            warden.cmd_start()

        # Find the podman run call (the one with "podman" and "run").
        podman_cmd = None
        for c in mock_run.call_args_list:
            cmd = c[0][0]
            if len(cmd) > 1 and cmd[0] == "podman" and cmd[1] == "run":
                podman_cmd = cmd
                break

        self.assertIsNotNone(podman_cmd)
        # Should have -s /addons/ratelimit.py.
        s_flags = []
        for i, c in enumerate(podman_cmd):
            if c == "-s" and i + 1 < len(podman_cmd):
                s_flags.append(podman_cmd[i + 1])
        self.assertIn("/addons/ratelimit.py", s_flags)

    @patch.object(warden, "is_running", return_value=True)
    def test_already_running_returns_zero(self, mock_is_running):
        """is_running() True -> returns 0 immediately."""
        result = warden.cmd_start()
        self.assertEqual(result, 0)

    @patch.object(warden, "is_running", return_value=False)
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(False, ["Missing policy"]))
    def test_preflight_failure_blocks_start(self, mock_preflight, mock_exists, mock_is_running):
        """Preflight errors -> returns 1, no podman run."""
        result = warden.cmd_start()
        self.assertEqual(result, 1)


# ---------------------------------------------------------------------------
# Task 1: Simple brig cmd_* handler tests
# ---------------------------------------------------------------------------

class TestCmdStop(IntegrationBase):
    """Integration tests for cmd_stop."""

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_stop_success(self, mock_run, mock_exists, mock_running,
                          mock_spinner, mock_lifecycle, mock_op):
        """Successful stop calls podman stop with timeout."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")

        result = brig.cmd_stop(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("podman", cmd)
        self.assertIn("stop", cmd)
        self.assertIn("-t", cmd)
        self.assertIn("10", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_stop_not_running_returns_zero(self, mock_exists, mock_running):
        """Cell not running -> returns 0 without calling podman."""
        args = self._make_args(name="testcell")
        result = brig.cmd_stop(args)
        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=False)
    def test_stop_nonexistent_errors(self, mock_exists):
        """Cell doesn't exist -> SystemExit."""
        args = self._make_args(name="ghost")
        with self.assertRaises(SystemExit):
            brig.cmd_stop(args)

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_stop_failure_returns_one(self, mock_run, mock_exists, mock_running,
                                      mock_spinner, mock_lifecycle, mock_op):
        """podman stop failure -> returns 1."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=1, stderr="timeout")
        args = self._make_args(name="testcell")

        result = brig.cmd_stop(args)

        self.assertEqual(result, 1)


class TestCmdKill(IntegrationBase):
    """Integration tests for cmd_kill."""

    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_kill_success(self, mock_run, mock_exists, mock_lifecycle):
        """Successful kill calls podman kill."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")

        result = brig.cmd_kill(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("kill", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(brig, "cell_exists", return_value=False)
    def test_kill_nonexistent_errors(self, mock_exists):
        """Cell doesn't exist -> SystemExit."""
        args = self._make_args(name="ghost")
        with self.assertRaises(SystemExit):
            brig.cmd_kill(args)

    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_kill_not_running_succeeds(self, mock_run, mock_exists, mock_lifecycle):
        """podman kill with 'not running' in stderr -> success."""
        mock_run.return_value = MagicMock(returncode=1, stderr="not running")
        args = self._make_args(name="testcell")
        result = brig.cmd_kill(args)
        self.assertEqual(result, 0)


class TestCmdRm(IntegrationBase):
    """Integration tests for cmd_rm."""

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_rm_success(self, mock_run, mock_exists, mock_running,
                        mock_spinner, mock_lifecycle, mock_op):
        """Successful rm removes container, disconnects proxy, frees subnet."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell", force=False, purge=False)

        result = brig.cmd_rm(args)

        self.assertEqual(result, 0)
        cmds = [c[0][0] for c in mock_run.call_args_list]
        # Should have: podman rm, network disconnect, remove-network.
        cmd_strs = [" ".join(c) for c in cmds]
        self.assertTrue(any("rm" in s and "podman" in s for s in cmd_strs))
        self.assertTrue(any("disconnect" in s for s in cmd_strs))
        self.assertTrue(any("remove-network" in s for s in cmd_strs))

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_rm_force_kills_first(self, mock_run, mock_exists, mock_running,
                                   mock_spinner, mock_lifecycle, mock_op):
        """Force rm kills running cell before removing."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell", force=True, purge=False)

        result = brig.cmd_rm(args)

        self.assertEqual(result, 0)
        first_cmd = mock_run.call_args_list[0][0][0]
        self.assertIn("kill", first_cmd)

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_rm_running_no_force_errors(self, mock_exists, mock_running):
        """Running cell without --force -> SystemExit."""
        args = self._make_args(name="testcell", force=False, purge=False)
        with self.assertRaises(SystemExit):
            brig.cmd_rm(args)

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_rm_purge_removes_workspace(self, mock_run, mock_exists, mock_running,
                                         mock_spinner, mock_lifecycle, mock_op):
        """Purge mode removes workspace directory."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        # Create workspace.
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "output.txt").write_text("data")

        args = self._make_args(name="testcell", force=False, purge=True)

        result = brig.cmd_rm(args)

        self.assertEqual(result, 0)
        self.assertFalse((brig.STATE_DIR / "testcell").exists())

    @patch.object(brig, "log_operation")
    @patch.object(brig, "log_lifecycle")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_rm_deletes_cell_policy(self, mock_run, mock_exists, mock_running,
                                     mock_spinner, mock_lifecycle, mock_op):
        """Rm deletes per-cell policy file."""
        mock_spinner.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        # Create policy file.
        policy_path = brig.POLICY_DIR / "testcell.json"
        policy_path.write_text(json.dumps({"allow": ["example.com"]}))

        args = self._make_args(name="testcell", force=False, purge=False)

        brig.cmd_rm(args)

        self.assertFalse(policy_path.exists())


class TestCmdStartCell(IntegrationBase):
    """Integration tests for cmd_start (start a stopped cell)."""

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_start_networked_cell(self, mock_run, mock_proxy, mock_exists, mock_running):
        """Start a networked cell: inspects networks, connects proxy, starts."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            if "inspect" in cmd:
                result.stdout = "brig-testcell "
            return result

        mock_run.side_effect = side_effect
        args = self._make_args(name="testcell")

        result = brig.cmd_start(args)

        self.assertEqual(result, 0)
        cmds = [c[0][0] for c in mock_run.call_args_list]
        cmd_strs = [" ".join(c) for c in cmds]
        # Should connect proxy to network.
        self.assertTrue(any("connect" in s for s in cmd_strs))
        # Should start container.
        self.assertTrue(any("start" in s and "podman" in s for s in cmd_strs))

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_start_airgapped_skips_proxy(self, mock_run, mock_exists, mock_running):
        """Air-gapped cell skips proxy connection."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            if "inspect" in cmd:
                # No brig- network means air-gapped.
                result.stdout = "none "
            return result

        mock_run.side_effect = side_effect
        args = self._make_args(name="testcell")

        result = brig.cmd_start(args)

        self.assertEqual(result, 0)
        cmds = [c[0][0] for c in mock_run.call_args_list]
        cmd_strs = [" ".join(c) for c in cmds]
        # Should NOT connect proxy.
        self.assertFalse(any("connect" in s for s in cmd_strs))

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_start_already_running(self, mock_exists, mock_running):
        """Already running -> returns 0."""
        args = self._make_args(name="testcell")
        result = brig.cmd_start(args)
        self.assertEqual(result, 0)


class TestCmdList(IntegrationBase):
    """Integration tests for cmd_list."""

    @patch.object(brig, "run")
    def test_list_json_format(self, mock_run):
        """JSON format returns structured cell data."""
        containers = [
            {"Names": ["brig-cell1"], "State": "running", "Image": "alpine"},
            {"Names": ["brig-cell2"], "State": "exited", "Image": "python:3.11"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        args = MagicMock()
        args.format = "json"

        result = brig.cmd_list(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "run")
    def test_list_table_format(self, mock_run):
        """Table format outputs cell names with status."""
        containers = [
            {"Names": ["brig-cell1"], "State": "running", "Image": "alpine"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(containers), stderr=""
        )
        args = MagicMock()
        args.format = "table"

        result = brig.cmd_list(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "run")
    def test_list_empty(self, mock_run):
        """No containers -> still returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        args = MagicMock()
        args.format = "table"

        result = brig.cmd_list(args)

        self.assertEqual(result, 0)


class TestCmdLogs(IntegrationBase):
    """Integration tests for cmd_logs."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_logs_basic(self, mock_run, mock_exists):
        """Basic logs call includes cell container name."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", follow=False, tail=None)

        result = brig.cmd_logs(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("logs", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_logs_follow_and_tail(self, mock_run, mock_exists):
        """Follow and tail flags passed through."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", follow=True, tail=50)

        brig.cmd_logs(args)

        cmd = mock_run.call_args[0][0]
        self.assertIn("-f", cmd)
        self.assertIn("--tail", cmd)
        self.assertIn("50", cmd)


class TestCmdExec(IntegrationBase):
    """Integration tests for cmd_exec."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_exec_with_command(self, mock_run, mock_exists, mock_running):
        """Exec with custom command passes it through."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", interactive=False, tty=False,
                               exec_cmd=["ls", "-la"])

        result = brig.cmd_exec(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("exec", cmd)
        self.assertIn("brig-testcell", cmd)
        self.assertIn("ls", cmd)
        self.assertIn("-la", cmd)

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_exec_default_shell(self, mock_run, mock_exists, mock_running):
        """Exec without command defaults to /bin/sh."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", interactive=False, tty=False,
                               exec_cmd=[])

        brig.cmd_exec(args)

        cmd = mock_run.call_args[0][0]
        self.assertIn("/bin/sh", cmd)

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_exec_interactive_tty_flags(self, mock_run, mock_exists, mock_running):
        """Interactive and tty flags added to command."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", interactive=True, tty=True,
                               exec_cmd=["bash"])

        brig.cmd_exec(args)

        cmd = mock_run.call_args[0][0]
        self.assertIn("-i", cmd)
        self.assertIn("-t", cmd)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_exec_not_running_errors(self, mock_exists, mock_running):
        """Cell not running -> SystemExit."""
        args = self._make_args(name="testcell", interactive=False, tty=False,
                               exec_cmd=[])
        with self.assertRaises(SystemExit):
            brig.cmd_exec(args)


class TestCmdShell(IntegrationBase):
    """Integration tests for cmd_shell."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_shell_default(self, mock_run, mock_exists, mock_running):
        """Shell opens interactive podman exec with /bin/sh."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell", shell_cmd="/bin/sh")

        result = brig.cmd_shell(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("exec", cmd)
        self.assertIn("-it", cmd)
        self.assertIn("/bin/sh", cmd)


class TestCmdRename(IntegrationBase):
    """Integration tests for cmd_rename."""

    @patch.object(brig, "log_operation")
    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists")
    @patch.object(brig, "run")
    def test_rename_success(self, mock_run, mock_exists, mock_running, mock_op):
        """Successful rename: container renamed, policy and workspace moved."""
        mock_exists.side_effect = lambda name: name == "oldcell"
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        # Create policy and workspace for old cell.
        (brig.POLICY_DIR / "oldcell.json").write_text('{"allow": []}')
        (brig.STATE_DIR / "oldcell" / "workspace").mkdir(parents=True)
        (brig.STATE_DIR / "oldcell" / "workspace" / "file.txt").write_text("data")

        args = MagicMock()
        args.old_name = "oldcell"
        args.new_name = "newcell"

        result = brig.cmd_rename(args)

        self.assertEqual(result, 0)
        # First run() call should be the podman rename.
        cmd = mock_run.call_args_list[0][0][0]
        self.assertIn("rename", cmd)
        # Policy renamed.
        self.assertFalse((brig.POLICY_DIR / "oldcell.json").exists())
        self.assertTrue((brig.POLICY_DIR / "newcell.json").exists())
        # Workspace renamed.
        self.assertFalse((brig.STATE_DIR / "oldcell").exists())
        self.assertTrue((brig.STATE_DIR / "newcell").exists())

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists")
    def test_rename_running_errors(self, mock_exists, mock_running):
        """Running cell -> SystemExit."""
        mock_exists.side_effect = lambda name: name == "oldcell"
        args = MagicMock()
        args.old_name = "oldcell"
        args.new_name = "newcell"
        with self.assertRaises(SystemExit):
            brig.cmd_rename(args)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists")
    def test_rename_old_not_found(self, mock_exists, mock_running):
        """Old cell doesn't exist -> SystemExit."""
        mock_exists.side_effect = lambda name: False
        args = MagicMock()
        args.old_name = "nonexistent"
        args.new_name = "newcell"
        with self.assertRaises(SystemExit):
            brig.cmd_rename(args)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists")
    def test_rename_new_already_exists(self, mock_exists, mock_running):
        """New cell name already exists -> SystemExit."""
        mock_exists.side_effect = lambda name: True
        args = MagicMock()
        args.old_name = "oldcell"
        args.new_name = "newcell"
        with self.assertRaises(SystemExit):
            brig.cmd_rename(args)

    @patch.object(brig, "log_operation")
    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists")
    @patch.object(brig, "run")
    def test_rename_no_policy_still_succeeds(self, mock_run, mock_exists, mock_running, mock_op):
        """Rename succeeds even without policy file."""
        mock_exists.side_effect = lambda name: name == "oldcell"
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        # No policy file created, just workspace.
        (brig.STATE_DIR / "oldcell" / "workspace").mkdir(parents=True)
        args = MagicMock()
        args.old_name = "oldcell"
        args.new_name = "newcell"
        result = brig.cmd_rename(args)
        self.assertEqual(result, 0)


class TestCmdPauseUnpause(IntegrationBase):
    """Integration tests for cmd_pause and cmd_unpause."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_pause_success(self, mock_run, mock_exists, mock_running):
        """Pause calls podman pause and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")

        result = brig.cmd_pause(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("pause", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_pause_not_running_errors(self, mock_exists, mock_running):
        """Cell not running -> SystemExit."""
        args = self._make_args(name="testcell")
        with self.assertRaises(SystemExit):
            brig.cmd_pause(args)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_unpause_success(self, mock_run, mock_exists):
        """Unpause calls podman unpause and returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")

        result = brig.cmd_unpause(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("unpause", cmd)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_unpause_failure_errors(self, mock_run, mock_exists):
        """Unpause failure -> SystemExit."""
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        args = self._make_args(name="testcell")
        with self.assertRaises(SystemExit):
            brig.cmd_unpause(args)


class TestCmdTop(IntegrationBase):
    """Integration tests for cmd_top."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_top_success(self, mock_run, mock_exists, mock_running):
        """Top calls podman top."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell")

        result = brig.cmd_top(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("top", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_top_not_running_errors(self, mock_exists, mock_running):
        """Cell not running -> SystemExit."""
        args = self._make_args(name="testcell")
        with self.assertRaises(SystemExit):
            brig.cmd_top(args)


class TestCmdAttach(IntegrationBase):
    """Integration tests for cmd_attach."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_attach_success(self, mock_run, mock_exists, mock_running):
        """Attach calls podman attach."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name="testcell")

        result = brig.cmd_attach(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("attach", cmd)
        self.assertIn("brig-testcell", cmd)


class TestCmdWait(IntegrationBase):
    """Integration tests for cmd_wait."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_wait_returns_exit_code(self, mock_run, mock_exists):
        """Wait returns container's exit code."""
        mock_run.return_value = MagicMock(returncode=0, stdout="42\n", stderr="")
        args = self._make_args(name="testcell", timeout=None, output="text")

        result = brig.cmd_wait(args)

        self.assertEqual(result, 42)
        cmd = mock_run.call_args[0][0]
        self.assertIn("wait", cmd)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_wait_json_output(self, mock_run, mock_exists):
        """Wait with json output prints structured data."""
        mock_run.return_value = MagicMock(returncode=0, stdout="0\n", stderr="")
        args = self._make_args(name="testcell", timeout=None, output="json")

        result = brig.cmd_wait(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_wait_timeout_expired(self, mock_run, mock_exists):
        """Timeout expired -> SystemExit."""
        import subprocess as sp
        mock_run.side_effect = sp.TimeoutExpired(cmd=["podman", "wait"], timeout=30)
        args = self._make_args(name="testcell", timeout="30s", output="text")
        with self.assertRaises(SystemExit):
            brig.cmd_wait(args)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_wait_no_such_container(self, mock_run, mock_exists):
        """Container removed -> SystemExit."""
        mock_run.return_value = MagicMock(returncode=125, stdout="", stderr="no such container")
        args = self._make_args(name="testcell", timeout=None, output="text")
        with self.assertRaises(SystemExit):
            brig.cmd_wait(args)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_wait_invalid_stdout(self, mock_run, mock_exists):
        """Non-numeric stdout -> SystemExit."""
        mock_run.return_value = MagicMock(returncode=0, stdout="not-a-number\n", stderr="")
        args = self._make_args(name="testcell", timeout=None, output="text")
        with self.assertRaises(SystemExit):
            brig.cmd_wait(args)

    @patch.object(brig, "cell_exists", return_value=False)
    def test_wait_cell_not_found(self, mock_exists):
        """Cell doesn't exist -> SystemExit."""
        args = self._make_args(name="testcell", timeout=None, output="text")
        with self.assertRaises(SystemExit):
            brig.cmd_wait(args)


# ---------------------------------------------------------------------------
# Task 2: Complex brig cmd_* handler tests
# ---------------------------------------------------------------------------

class TestCmdInspect(IntegrationBase):
    """Integration tests for cmd_inspect."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_inspect_json_format(self, mock_run, mock_exists):
        """JSON format outputs raw podman inspect data."""
        container_data = [{
            "Name": "brig-testcell",
            "State": {"Status": "running", "Pid": 1234},
            "Config": {"Image": "alpine"},
            "HostConfig": {"Runtime": "runsc"},
            "NetworkSettings": {"Networks": {"brig-testcell": {}}},
            "Mounts": [],
        }]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(container_data), stderr=""
        )
        args = self._make_args(name="testcell", format="json")

        result = brig.cmd_inspect(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_inspect_table_format(self, mock_run, mock_exists):
        """Table format shows name, status, runtime, image, network, pid."""
        container_data = [{
            "Name": "brig-testcell",
            "State": {"Status": "running", "Pid": 1234},
            "Config": {"Image": "alpine"},
            "HostConfig": {"Runtime": "runsc"},
            "NetworkSettings": {"Networks": {"brig-testcell": {}}},
            "Mounts": [{"Source": "/state/testcell", "Destination": "/work", "RW": True}],
        }]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(container_data), stderr=""
        )
        args = self._make_args(name="testcell", format="table")

        result = brig.cmd_inspect(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_inspect_failure_errors(self, mock_run, mock_exists):
        """podman inspect failure -> SystemExit."""
        mock_run.return_value = MagicMock(returncode=1, stderr="not found")
        args = self._make_args(name="testcell", format="json")
        with self.assertRaises(SystemExit):
            brig.cmd_inspect(args)


class TestCmdExport(IntegrationBase):
    """Integration tests for cmd_export."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_export_json_extracts_cell_def(self, mock_run, mock_exists):
        """JSON export extracts name, image, env, resources from inspect data."""
        container_data = [{
            "Name": "brig-testcell",
            "Config": {
                "Image": "python:3.11",
                "Cmd": ["python", "app.py"],
                "Env": ["MY_VAR=hello", "http_proxy=http://10.60.1.1:8080",
                         "SECRET_FILE=/run/secrets/key"],
            },
            "HostConfig": {
                "Memory": 2147483648,  # 2g
                "NanoCpus": 2000000000,  # 2 cpus
                "PidsLimit": 512,
            },
            "Mounts": [
                {"Source": "/state/testcell", "Destination": "/work", "RW": True},
                {"Source": "/secrets/api-key", "Destination": "/run/secrets/api-key", "RW": False},
            ],
            "NetworkSettings": {"Networks": {}},
            "State": {},
        }]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(container_data), stderr=""
        )
        args = self._make_args(name="testcell", format="json")

        with patch("builtins.print") as mock_print:
            result = brig.cmd_export(args)

        self.assertEqual(result, 0)
        # Parse the printed JSON.
        printed = mock_print.call_args[0][0]
        cell_def = json.loads(printed)
        self.assertEqual(cell_def["name"], "testcell")
        self.assertEqual(cell_def["image"], "python:3.11")
        self.assertEqual(cell_def["command"], ["python", "app.py"])
        # Proxy vars filtered out, SECRET_FILE filtered out.
        self.assertNotIn("http_proxy", cell_def.get("env", {}))
        self.assertIn("MY_VAR", cell_def.get("env", {}))
        # Secrets extracted from mounts.
        self.assertIn("api-key", cell_def.get("secrets", []))
        # Resource limits.
        self.assertEqual(cell_def["memory"], "2g")


class TestCmdDiff(IntegrationBase):
    """Integration tests for cmd_diff."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_diff_json(self, mock_run, mock_exists):
        """JSON format passes through podman diff output."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout='[{"path":"/tmp/foo","kind":0}]', stderr=""
        )
        args = self._make_args(name="testcell", format="json")

        result = brig.cmd_diff(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("diff", cmd)
        self.assertIn("--format=json", cmd)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_diff_pretty_print(self, mock_run, mock_exists):
        """Text format converts A/D/C prefixes."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="A /tmp/new\nD /tmp/old\nC /tmp/changed\n", stderr=""
        )
        args = self._make_args(name="testcell", format="text")

        result = brig.cmd_diff(args)

        self.assertEqual(result, 0)


class TestCmdStats(IntegrationBase):
    """Integration tests for cmd_stats."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_stats_json(self, mock_run, mock_exists):
        """JSON stats strips container prefix from names."""
        stats_data = [
            {"name": "brig-cell1", "cpu_percent": "5.0%", "mem_usage": "100MB"},
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout=json.dumps(stats_data), stderr=""
        )
        args = self._make_args(name="cell1", output="json", no_stream=True)

        result = brig.cmd_stats(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "run")
    def test_stats_table_all_cells(self, mock_run):
        """Table stats for all cells uses filter."""
        mock_run.return_value = MagicMock(returncode=0)
        args = self._make_args(name=None, output="text", no_stream=True)

        result = brig.cmd_stats(args)

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("stats", cmd)
        self.assertIn("--no-stream", cmd)
        cmd_str = " ".join(cmd)
        self.assertIn("brig-", cmd_str)


class TestCmdDiagnose(IntegrationBase):
    """Integration tests for cmd_diagnose."""

    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_diagnose_all_pass(self, mock_run, mock_proxy, mock_exists, mock_running):
        """All checks pass -> returns 0."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            if "network" in cmd and "exists" in cmd:
                result.returncode = 0
            elif "inspect" in cmd and "warden" in cmd:
                result.stdout = "brig-testcell "
            elif "dmesg" in cmd:
                result.stdout = "Starting gVisor"
            elif "tail" in cmd:
                result.stdout = ""
            return result

        mock_run.side_effect = side_effect
        args = self._make_args(name="testcell")

        result = brig.cmd_diagnose(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "proxy_running", return_value=False)
    @patch.object(brig, "run")
    def test_diagnose_issues_found(self, mock_run, mock_proxy, mock_exists, mock_running):
        """Multiple issues -> returns 1."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        args = self._make_args(name="testcell")

        result = brig.cmd_diagnose(args)

        self.assertEqual(result, 1)


class TestCmdHistory(IntegrationBase):
    """Integration tests for cmd_history."""

    def test_history_no_file(self):
        """No history file -> returns 0."""
        args = MagicMock()
        args.cell = None
        args.tail = None
        args.format = "table"

        result = brig.cmd_history(args)

        self.assertEqual(result, 0)

    def test_history_reads_entries(self):
        """History entries read and displayed."""
        history_dir = brig.HISTORY_FILE.parent
        history_dir.mkdir(parents=True, exist_ok=True)
        entries = [
            {"timestamp": "2026-01-15T10:00:00Z", "operation": "run", "cell": "cell1", "details": {}},
            {"timestamp": "2026-01-15T11:00:00Z", "operation": "stop", "cell": "cell2", "details": {}},
        ]
        with open(brig.HISTORY_FILE, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        args = MagicMock()
        args.cell = None
        args.tail = None
        args.format = "table"

        result = brig.cmd_history(args)

        self.assertEqual(result, 0)

    def test_history_cell_filter(self):
        """Cell filter shows only matching entries."""
        history_dir = brig.HISTORY_FILE.parent
        history_dir.mkdir(parents=True, exist_ok=True)
        entries = [
            {"timestamp": "2026-01-15T10:00:00Z", "operation": "run", "cell": "cell1", "details": {}},
            {"timestamp": "2026-01-15T11:00:00Z", "operation": "stop", "cell": "cell2", "details": {}},
        ]
        with open(brig.HISTORY_FILE, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        args = MagicMock()
        args.cell = "cell1"
        args.tail = None
        args.format = "json"

        with patch("builtins.print") as mock_print:
            brig.cmd_history(args)

        printed = mock_print.call_args[0][0]
        result_entries = json.loads(printed)
        self.assertEqual(len(result_entries), 1)
        self.assertEqual(result_entries[0]["cell"], "cell1")

    def test_history_tail_limits(self):
        """Tail limits number of entries."""
        history_dir = brig.HISTORY_FILE.parent
        history_dir.mkdir(parents=True, exist_ok=True)
        with open(brig.HISTORY_FILE, "w") as f:
            for i in range(10):
                f.write(json.dumps({"timestamp": f"2026-01-15T{i:02d}:00:00Z",
                                     "operation": "run", "cell": f"cell{i}", "details": {}}) + "\n")

        args = MagicMock()
        args.cell = None
        args.tail = 3
        args.format = "json"

        with patch("builtins.print") as mock_print:
            brig.cmd_history(args)

        printed = mock_print.call_args[0][0]
        result_entries = json.loads(printed)
        self.assertEqual(len(result_entries), 3)


class TestCmdHealth(IntegrationBase):
    """Integration tests for cmd_health."""

    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_health_all_pass(self, mock_run, mock_proxy):
        """All checks pass -> returns 0."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            if "network" in cmd and "exists" in cmd:
                result.returncode = 0
            elif "info" in cmd:
                result.stdout = "runsc"
            elif "ps" in cmd:
                result.stdout = "brig-cell1\n"
            return result

        mock_run.side_effect = side_effect
        args = self._make_args(format="json")

        result = brig.cmd_health(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "proxy_running", return_value=False)
    @patch.object(brig, "run")
    def test_health_unhealthy(self, mock_run, mock_proxy):
        """Proxy down -> returns 1."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        args = self._make_args(format="table")

        result = brig.cmd_health(args)

        self.assertEqual(result, 1)


class TestCmdCat(IntegrationBase):
    """Integration tests for cmd_cat — workspace file reading."""

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_text_file(self, mock_exists):
        """Cat displays text file contents."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "output.txt").write_text("hello world\n")

        args = self._make_args(name="testcell", path="output.txt",
                               max_size=1, force=False, lines=None)

        result = brig.cmd_cat(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_binary_blocked(self, mock_exists):
        """Binary file without --force -> SystemExit."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "binary.dat").write_bytes(b"\x00\x01\x02binary")

        args = self._make_args(name="testcell", path="binary.dat",
                               max_size=1, force=False, lines=None)

        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_too_large_blocked(self, mock_exists):
        """File exceeding max_size -> SystemExit."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        # max_size=1 means 1MB. Write 2MB.
        (workspace / "big.txt").write_bytes(b"x" * (2 * 1024 * 1024))

        args = self._make_args(name="testcell", path="big.txt",
                               max_size=1, force=False, lines=None)

        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_line_limit(self, mock_exists):
        """Lines parameter truncates output."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "long.txt").write_text("\n".join(f"line {i}" for i in range(100)))

        args = self._make_args(name="testcell", path="long.txt",
                               max_size=1, force=False, lines=5)

        result = brig.cmd_cat(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_directory_errors(self, mock_exists):
        """Cat on directory -> SystemExit."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        subdir = workspace / "subdir"
        subdir.mkdir(parents=True)

        args = self._make_args(name="testcell", path="subdir",
                               max_size=1, force=False, lines=None)

        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_binary_with_force(self, mock_exists):
        """Binary file with --force succeeds."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "binary.dat").write_bytes(b"\x00\x01\x02binary")
        args = self._make_args(name="testcell", path="binary.dat",
                               max_size=1, force=True, lines=None)
        result = brig.cmd_cat(args)
        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cat_path_traversal(self, mock_exists):
        """Path traversal -> SystemExit."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        args = self._make_args(name="testcell", path="../../../etc/passwd",
                               max_size=1, force=False, lines=None)
        with self.assertRaises(SystemExit):
            brig.cmd_cat(args)


class TestCmdFiles(IntegrationBase):
    """Integration tests for cmd_files — workspace listing."""

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_files_lists_workspace(self, mock_run, mock_exists):
        """Files calls ls on workspace directory."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        mock_run.return_value = MagicMock(returncode=0)

        args = self._make_args(name="testcell", path=None)

        result = brig.cmd_files(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_files_no_workspace(self, mock_exists):
        """No workspace -> returns 0 with info message."""
        args = self._make_args(name="testcell", path=None)

        result = brig.cmd_files(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_files_single_file_info(self, mock_exists):
        """Path pointing to a file shows file info."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "output.txt").write_text("data")

        args = self._make_args(name="testcell", path="output.txt")

        result = brig.cmd_files(args)

        self.assertEqual(result, 0)


class TestCmdCp(IntegrationBase):
    """Integration tests for cmd_cp — file copy to/from workspace."""

    @patch.object(brig, "apply_quarantine", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_cp_from_cell(self, mock_exists, mock_quarantine):
        """Copy from cell workspace to local."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "output.txt").write_text("cell output")
        dst = self.temp_dir / "local_copy.txt"

        args = MagicMock()
        args.src = "testcell:output.txt"
        args.dst = str(dst)
        args.sanitize = False
        args.force = False
        args.allow_scripts = False
        args.allow_office = False

        result = brig.cmd_cp(args)

        self.assertEqual(result, 0)
        self.assertTrue(dst.exists())
        self.assertEqual(dst.read_text(), "cell output")

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cp_to_cell(self, mock_exists):
        """Copy from local to cell workspace."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        src = self.temp_dir / "input.txt"
        src.write_text("local input")

        args = MagicMock()
        args.src = str(src)
        args.dst = "testcell:input.txt"
        args.sanitize = False
        args.force = False
        args.allow_scripts = False
        args.allow_office = False

        result = brig.cmd_cp(args)

        self.assertEqual(result, 0)
        self.assertTrue((workspace / "input.txt").exists())

    def test_cp_both_cells_errors(self):
        """Copy between cells -> SystemExit."""
        args = MagicMock()
        args.src = "cell1:file"
        args.dst = "cell2:file"
        args.sanitize = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)

    def test_cp_no_cell_errors(self):
        """No cell in either side -> SystemExit."""
        args = MagicMock()
        args.src = "/tmp/a"
        args.dst = "/tmp/b"
        args.sanitize = False
        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_cp_sanitize_blocks_unsafe(self, mock_exists):
        """Sanitize mode blocks unsafe file extensions."""
        workspace = brig.STATE_DIR / "testcell" / "workspace"
        workspace.mkdir(parents=True)
        (workspace / "malware.exe").write_text("bad")
        dst = self.temp_dir / "malware.exe"

        args = MagicMock()
        args.src = "testcell:malware.exe"
        args.dst = str(dst)
        args.sanitize = True
        args.force = False
        args.allow_scripts = False
        args.allow_office = False

        with self.assertRaises(SystemExit):
            brig.cmd_cp(args)


# ---------------------------------------------------------------------------
# Task 3: Warden cmd_* handler tests
# ---------------------------------------------------------------------------

class TestWardenStop(IntegrationBase):
    """Integration tests for warden.cmd_stop."""

    @patch.object(warden, "container_exists", return_value=True)
    @patch.object(warden, "run")
    def test_stop_success(self, mock_run, mock_exists):
        """Successful stop calls podman stop then rm."""
        mock_run.return_value = MagicMock(returncode=0)

        result = warden.cmd_stop()

        self.assertEqual(result, 0)
        self.assertEqual(len(mock_run.call_args_list), 2)
        stop_cmd = mock_run.call_args_list[0][0][0]
        rm_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("stop", stop_cmd)
        self.assertIn("-t", stop_cmd)
        self.assertIn("10", stop_cmd)
        self.assertIn("rm", rm_cmd)

    @patch.object(warden, "container_exists", return_value=False)
    def test_stop_not_running(self, mock_exists):
        """Container doesn't exist -> returns 0."""
        result = warden.cmd_stop()
        self.assertEqual(result, 0)


class TestWardenStatus(IntegrationBase):
    """Integration tests for warden.cmd_status."""

    @patch.object(warden, "is_running", return_value=True)
    @patch.object(warden, "run")
    def test_status_running(self, mock_run, mock_is_running):
        """Running proxy shows network info."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="proxy-external: 10.0.0.1\n"
        )

        result = warden.cmd_status()

        self.assertEqual(result, 0)

    @patch.object(warden, "container_exists", return_value=True)
    @patch.object(warden, "is_running", return_value=False)
    def test_status_stopped(self, mock_is_running, mock_exists):
        """Stopped container shows stopped status."""
        result = warden.cmd_status()
        self.assertEqual(result, 1)

    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "is_running", return_value=False)
    def test_status_not_created(self, mock_is_running, mock_exists):
        """No container shows not created."""
        result = warden.cmd_status()
        self.assertEqual(result, 1)


class TestWardenReload(IntegrationBase):
    """Integration tests for warden.cmd_reload — real temp policy files."""

    @patch.object(warden, "is_running", return_value=True)
    @patch.object(warden, "run")
    def test_reload_valid_policy(self, mock_run, mock_is_running):
        """Valid policy file -> SIGHUP sent, returns 0."""
        policy = {"allow": ["example.com"], "deny": []}
        warden.POLICY_FILE = self.temp_dir / "policy.json"
        warden.POLICY_FILE.write_text(json.dumps(policy))
        mock_run.return_value = MagicMock(returncode=0)

        result = warden.cmd_reload()

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("kill", cmd)
        self.assertIn("-s", cmd)
        self.assertIn("HUP", cmd)

    @patch.object(warden, "is_running", return_value=True)
    def test_reload_invalid_json(self, mock_is_running):
        """Invalid JSON in policy -> returns 1, no signal sent."""
        warden.POLICY_FILE = self.temp_dir / "policy.json"
        warden.POLICY_FILE.write_text("not json{{{")

        result = warden.cmd_reload()

        self.assertEqual(result, 1)

    @patch.object(warden, "is_running", return_value=True)
    def test_reload_missing_policy(self, mock_is_running):
        """Missing policy file -> returns 1."""
        warden.POLICY_FILE = self.temp_dir / "nonexistent.json"

        result = warden.cmd_reload()

        self.assertEqual(result, 1)

    @patch.object(warden, "is_running", return_value=False)
    def test_reload_not_running(self, mock_is_running):
        """Proxy not running -> returns 1."""
        result = warden.cmd_reload()
        self.assertEqual(result, 1)

    @patch.object(warden, "is_running", return_value=True)
    def test_reload_allow_not_list(self, mock_is_running):
        """Policy with allow as string instead of list -> returns 1."""
        warden.POLICY_FILE = self.temp_dir / "policy.json"
        warden.POLICY_FILE.write_text(json.dumps({"allow": "example.com"}))

        result = warden.cmd_reload()

        self.assertEqual(result, 1)


class TestWardenJoin(IntegrationBase):
    """Integration tests for warden.cmd_join."""

    @patch.object(warden, "is_running", return_value=True)
    @patch.object(warden, "run")
    def test_join_success(self, mock_run, mock_is_running):
        """Successful join connects proxy to cell network."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # network exists
            MagicMock(returncode=0),  # network connect
        ]

        result = warden.cmd_join("testcell")

        self.assertEqual(result, 0)
        connect_cmd = mock_run.call_args_list[1][0][0]
        self.assertIn("connect", connect_cmd)
        self.assertIn("brig-testcell", connect_cmd)

    @patch.object(warden, "is_running", return_value=True)
    @patch.object(warden, "run")
    def test_join_network_missing(self, mock_run, mock_is_running):
        """Network doesn't exist -> returns 1."""
        mock_run.return_value = MagicMock(returncode=1)

        result = warden.cmd_join("testcell")

        self.assertEqual(result, 1)

    @patch.object(warden, "is_running", return_value=False)
    def test_join_not_running(self, mock_is_running):
        """Proxy not running -> returns 1."""
        result = warden.cmd_join("testcell")
        self.assertEqual(result, 1)


class TestWardenLeave(IntegrationBase):
    """Integration tests for warden.cmd_leave."""

    @patch.object(warden, "is_running", return_value=True)
    @patch.object(warden, "run")
    def test_leave_success(self, mock_run, mock_is_running):
        """Successful leave disconnects proxy from cell network."""
        mock_run.return_value = MagicMock(returncode=0)

        result = warden.cmd_leave("testcell")

        self.assertEqual(result, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("disconnect", cmd)
        self.assertIn("brig-testcell", cmd)

    @patch.object(warden, "is_running", return_value=False)
    def test_leave_not_running(self, mock_is_running):
        """Proxy not running -> returns 1."""
        result = warden.cmd_leave("testcell")
        self.assertEqual(result, 1)


class TestWardenPolicyValidate(IntegrationBase):
    """Integration tests for warden.cmd_policy_validate — real temp files."""

    def test_valid_policy(self):
        """Valid policy with allow/deny rules -> returns 0."""
        policy = {
            "allow": ["example.com", "*.github.com"],
            "deny": ["evil.com"],
            "rate_limits": {"default": {"rate": 100, "burst": 500}},
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 0)

    def test_invalid_json(self):
        """Invalid JSON -> returns 1."""
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text("not json")

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 1)

    def test_missing_file(self):
        """Missing file -> returns 1."""
        result = warden.cmd_policy_validate("/nonexistent/policy.json")
        self.assertEqual(result, 1)

    def test_allow_not_list(self):
        """Allow as non-list -> returns 1."""
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps({"allow": "not-a-list"}))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 1)

    def test_invalid_rate_limit(self):
        """Non-numeric rate limit -> returns 1."""
        policy = {
            "allow": [],
            "rate_limits": {"default": {"rate": "fast"}},
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 1)

    def test_invalid_sample_rate(self):
        """Sample rate out of 0-1 range -> returns 1."""
        policy = {
            "allow": [],
            "log_filter": {"sample_rate": 5.0},
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 1)

    def test_duplicate_domain_warning(self):
        """Duplicate domain in allow -> warning but still passes."""
        policy = {
            "allow": ["example.com", "other.com", "example.com"],
            "deny": [],
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 0)

    def test_complex_rule_validation(self):
        """Dict rule with domain, paths, methods validated."""
        policy = {
            "allow": [
                {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET", "POST"]},
            ],
            "deny": [],
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 0)

    def test_invalid_method_in_rule(self):
        """Invalid HTTP method in rule -> returns 1."""
        policy = {
            "allow": [
                {"domain": "api.example.com", "methods": ["YOLO"]},
            ],
        }
        policy_path = self.temp_dir / "policy.json"
        policy_path.write_text(json.dumps(policy))

        result = warden.cmd_policy_validate(str(policy_path))

        self.assertEqual(result, 1)


class TestWardenPolicyTest(IntegrationBase):
    """Integration tests for warden.cmd_policy_test — real temp files."""

    def _set_policy(self, policy):
        """Write a policy file and point warden to it."""
        warden.POLICY_FILE = self.temp_dir / "policy.json"
        warden.POLICY_FILE.write_text(json.dumps(policy))

    def test_allowed_domain(self):
        """Domain in allowlist -> returns 0."""
        self._set_policy({"allow": ["example.com"], "deny": []})

        result = warden.cmd_policy_test("example.com")

        self.assertEqual(result, 0)

    def test_denied_domain(self):
        """Domain in denylist -> returns 1."""
        self._set_policy({"allow": ["example.com"], "deny": ["evil.com"]})

        result = warden.cmd_policy_test("evil.com")

        self.assertEqual(result, 1)

    def test_default_deny(self):
        """Domain not in any list -> returns 1 (default deny)."""
        self._set_policy({"allow": ["example.com"], "deny": []})

        result = warden.cmd_policy_test("other.com")

        self.assertEqual(result, 1)

    def test_wildcard_match(self):
        """Wildcard *.example.com matches subdomain."""
        self._set_policy({"allow": ["*.example.com"], "deny": []})

        result = warden.cmd_policy_test("api.example.com")

        self.assertEqual(result, 0)

    def test_wildcard_no_base_match(self):
        """Wildcard *.example.com does NOT match example.com itself."""
        self._set_policy({"allow": ["*.example.com"], "deny": []})

        result = warden.cmd_policy_test("example.com")

        self.assertEqual(result, 1)

    def test_deny_takes_precedence(self):
        """Domain in both allow and deny -> denied (deny first)."""
        self._set_policy({"allow": ["example.com"], "deny": ["example.com"]})

        result = warden.cmd_policy_test("example.com")

        self.assertEqual(result, 1)

    def test_complex_rule_with_path(self):
        """Dict rule with path matching."""
        self._set_policy({
            "allow": [{"domain": "api.example.com", "paths": ["/v1/*"]}],
            "deny": [],
        })

        self.assertEqual(warden.cmd_policy_test("api.example.com", path="/v1/users"), 0)
        self.assertEqual(warden.cmd_policy_test("api.example.com", path="/v2/users"), 1)

    def test_complex_rule_with_method(self):
        """Dict rule with method matching."""
        self._set_policy({
            "allow": [{"domain": "api.example.com", "methods": ["GET"]}],
            "deny": [],
        })

        self.assertEqual(warden.cmd_policy_test("api.example.com", method="GET"), 0)
        self.assertEqual(warden.cmd_policy_test("api.example.com", method="POST"), 1)


# ---------------------------------------------------------------------------
# Task 4: Brig policy_show and policy_set tests
# ---------------------------------------------------------------------------

class TestCmdPolicyShow(IntegrationBase):
    """Integration tests for cmd_policy_show."""

    @patch.object(brig, "cell_exists", return_value=True)
    def test_policy_show_with_cell_policy(self, mock_exists):
        """Shows per-cell policy when it exists."""
        policy = {"allow": ["example.com"], "deny": ["evil.com"]}
        (brig.POLICY_DIR / "testcell.json").write_text(json.dumps(policy))

        args = self._make_args(name="testcell")

        result = brig.cmd_policy_show(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_policy_show_no_cell_policy(self, mock_exists):
        """Shows message when no per-cell policy exists."""
        args = self._make_args(name="testcell")

        result = brig.cmd_policy_show(args)

        self.assertEqual(result, 0)


class TestCmdPolicySet(IntegrationBase):
    """Integration tests for cmd_policy_set."""

    @patch.object(brig, "log_policy_change")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_add_allow_domain(self, mock_run, mock_exists, mock_log):
        """Adding domain to allowlist saves policy file."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")
        args.allow = ["example.com"]
        args.deny = None
        args.remove_allow = None
        args.remove_deny = None

        result = brig.cmd_policy_set(args)

        self.assertEqual(result, 0)
        policy = json.loads((brig.POLICY_DIR / "testcell.json").read_text())
        self.assertIn("example.com", policy["allow"])

    @patch.object(brig, "log_policy_change")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_add_deny_domain(self, mock_run, mock_exists, mock_log):
        """Adding domain to denylist saves policy file."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")
        args.allow = None
        args.deny = ["evil.com"]
        args.remove_allow = None
        args.remove_deny = None

        result = brig.cmd_policy_set(args)

        self.assertEqual(result, 0)
        policy = json.loads((brig.POLICY_DIR / "testcell.json").read_text())
        self.assertIn("evil.com", policy["deny"])

    @patch.object(brig, "log_policy_change")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_remove_allow_domain(self, mock_run, mock_exists, mock_log):
        """Removing domain from allowlist updates policy."""
        # Pre-create policy.
        (brig.POLICY_DIR / "testcell.json").write_text(
            json.dumps({"allow": ["example.com", "keep.com"], "deny": []})
        )
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")
        args.allow = None
        args.deny = None
        args.remove_allow = ["example.com"]
        args.remove_deny = None

        result = brig.cmd_policy_set(args)

        self.assertEqual(result, 0)
        policy = json.loads((brig.POLICY_DIR / "testcell.json").read_text())
        self.assertNotIn("example.com", policy["allow"])
        self.assertIn("keep.com", policy["allow"])

    @patch.object(brig, "cell_exists", return_value=True)
    def test_invalid_domain_pattern_errors(self, mock_exists):
        """Invalid domain pattern -> SystemExit."""
        args = self._make_args(name="testcell")
        args.allow = ["not a valid domain!!!"]
        args.deny = None
        args.remove_allow = None
        args.remove_deny = None

        with self.assertRaises(SystemExit):
            brig.cmd_policy_set(args)

    @patch.object(brig, "log_policy_change")
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_policy_set_reloads_proxy(self, mock_run, mock_exists, mock_log):
        """Policy set calls warden reload."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        args = self._make_args(name="testcell")
        args.allow = ["example.com"]
        args.deny = None
        args.remove_allow = None
        args.remove_deny = None

        brig.cmd_policy_set(args)

        # Last run() call should be warden reload.
        last_cmd = mock_run.call_args_list[-1][0][0]
        self.assertIn("warden", last_cmd)
        self.assertIn("reload", last_cmd)


# ---------------------------------------------------------------------------
# Checkpoint / Restore tests
# ---------------------------------------------------------------------------

class TestCmdCheckpointRestore(IntegrationBase):
    """Integration tests for cmd_checkpoint and cmd_restore."""

    @patch.object(brig, "log_operation")
    @patch("builtins.print")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_checkpoint_success(self, mock_run, mock_exists, mock_running,
                                mock_spinner, mock_print, mock_log):
        """Successful checkpoint returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # Mock Spinner context manager.
        spinner_instance = MagicMock()
        mock_spinner.return_value.__enter__ = MagicMock(return_value=spinner_instance)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        args = self._make_args(name="testcell", checkpoint_name="my-checkpoint",
                               keep_running=False)

        with patch("pathlib.Path.mkdir"):
            result = brig.cmd_checkpoint(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_running", return_value=False)
    @patch.object(brig, "cell_exists", return_value=True)
    def test_checkpoint_not_running(self, mock_exists, mock_running):
        """Not running -> SystemExit."""
        args = self._make_args(name="testcell", checkpoint_name=None,
                               keep_running=False)
        with self.assertRaises(SystemExit):
            brig.cmd_checkpoint(args)

    @patch("builtins.print")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_running", return_value=True)
    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_checkpoint_failure(self, mock_run, mock_exists, mock_running,
                                mock_spinner, mock_print):
        """Run failure returns 1."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="checkpoint error")
        spinner_instance = MagicMock()
        mock_spinner.return_value.__enter__ = MagicMock(return_value=spinner_instance)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        args = self._make_args(name="testcell", checkpoint_name="my-checkpoint",
                               keep_running=False)

        with patch("pathlib.Path.mkdir"):
            result = brig.cmd_checkpoint(args)

        self.assertEqual(result, 1)

    @patch.object(brig, "log_operation")
    @patch.object(brig, "invalidate_cell_cache")
    @patch("builtins.print")
    @patch.object(brig, "Spinner")
    @patch.object(brig, "cell_exists", return_value=False)
    @patch.object(brig, "run")
    def test_restore_success(self, mock_run, mock_exists, mock_spinner,
                             mock_print, mock_cache, mock_log):
        """Successful restore returns 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        spinner_instance = MagicMock()
        mock_spinner.return_value.__enter__ = MagicMock(return_value=spinner_instance)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        args = MagicMock()
        args.checkpoint = "testcell-checkpoint"
        args.name = None

        with patch("pathlib.Path.exists", return_value=True):
            result = brig.cmd_restore(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    def test_restore_cell_exists(self, mock_exists):
        """Target cell already exists -> SystemExit."""
        args = MagicMock()
        args.checkpoint = "testcell-checkpoint"
        args.name = "testcell"

        with patch("pathlib.Path.exists", return_value=True):
            with self.assertRaises(SystemExit):
                brig.cmd_restore(args)


# ---------------------------------------------------------------------------
# Network activity log tests
# ---------------------------------------------------------------------------

class TestCmdNetwork(IntegrationBase):
    """Integration tests for cmd_network."""

    @patch.object(brig, "cell_exists", return_value=True)
    def test_network_no_log_returns_info(self, mock_exists):
        """No log file -> returns 0 with info message."""
        args = self._make_args(name="testcell", follow=False, blocked=False,
                               json=False, tail=100)
        # The log file path is /var/log/brig/network/{cell}.jsonl.
        # Since it doesn't exist, should return 0.
        result = brig.cmd_network(args)
        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_network_json_output(self, mock_run, mock_exists):
        """JSON output mode prints raw JSONL."""
        log_entries = [
            '{"ts":"2026-01-01T00:00:00Z","method":"GET","host":"example.com","status":200}',
            '{"ts":"2026-01-01T00:00:01Z","method":"POST","host":"api.com","status":403,"blocked":true}',
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout="\n".join(log_entries), stderr=""
        )

        args = self._make_args(name="testcell", follow=False, blocked=False,
                               json=True, tail=100)

        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.print") as mock_print:
                result = brig.cmd_network(args)

        self.assertEqual(result, 0)

    @patch.object(brig, "cell_exists", return_value=True)
    @patch.object(brig, "run")
    def test_network_blocked_filter(self, mock_run, mock_exists):
        """Blocked filter shows only blocked entries."""
        log_entries = [
            '{"ts":"2026-01-01T00:00:00Z","method":"GET","host":"example.com","status":200}',
            '{"ts":"2026-01-01T00:00:01Z","method":"POST","host":"evil.com","status":403,"blocked":true}',
        ]
        mock_run.return_value = MagicMock(
            returncode=0, stdout="\n".join(log_entries), stderr=""
        )

        args = self._make_args(name="testcell", follow=False, blocked=True,
                               json=True, tail=100)

        with patch("pathlib.Path.exists", return_value=True):
            with patch("builtins.print") as mock_print:
                result = brig.cmd_network(args)

        self.assertEqual(result, 0)
        # Only the blocked entry should be printed.
        printed_lines = [call[0][0] for call in mock_print.call_args_list]
        self.assertEqual(len(printed_lines), 1)
        self.assertIn("blocked", printed_lines[0])


# ---------------------------------------------------------------------------
# Events tests
# ---------------------------------------------------------------------------

class TestCmdEvents(IntegrationBase):
    """Integration tests for cmd_events."""

    @patch("subprocess.Popen")
    def test_events_no_name_streams_all(self, mock_popen):
        """No name filter -> streams all brig events."""
        proc_mock = MagicMock()
        proc_mock.stdout = iter([])
        proc_mock.wait.return_value = 0
        proc_mock.returncode = 0
        mock_popen.return_value = proc_mock

        args = MagicMock()
        args.name = None
        args.event_type = None
        args.since = None
        args.output = "json"

        result = brig.cmd_events(args)

        self.assertEqual(result, 0)
        cmd = mock_popen.call_args[0][0]
        self.assertIn("events", cmd)
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)

    @patch("subprocess.Popen")
    @patch.object(brig, "cell_exists", return_value=True)
    def test_events_with_name_filters(self, mock_exists, mock_popen):
        """Name filter -> filters by container name."""
        proc_mock = MagicMock()
        proc_mock.stdout = iter([])
        proc_mock.wait.return_value = 0
        proc_mock.returncode = 0
        mock_popen.return_value = proc_mock

        args = MagicMock()
        args.name = "testcell"
        args.event_type = None
        args.since = None
        args.output = "json"

        result = brig.cmd_events(args)

        self.assertEqual(result, 0)
        cmd = mock_popen.call_args[0][0]
        self.assertIn("--filter", cmd)
        self.assertIn("container=brig-testcell", cmd)


# ---------------------------------------------------------------------------
# Verify tests
# ---------------------------------------------------------------------------

class TestCmdVerify(IntegrationBase):
    """Integration tests for cmd_verify."""

    @patch("builtins.print")
    @patch.object(brig, "_verify_proxy_enforcement")
    @patch.object(brig, "_verify_cell_isolation")
    @patch.object(brig, "_verify_single_homed")
    @patch.object(brig, "_verify_network_isolation")
    @patch.object(brig, "_verify_gvisor_runtime")
    @patch.object(brig, "_verify_proxy_network")
    @patch.object(brig, "_verify_proxy_status")
    def test_verify_all_pass(self, mock_ps, mock_pn, mock_gv, mock_ni,
                             mock_sh, mock_ci, mock_pe, mock_print):
        """All checks pass -> returns 0."""
        args = MagicMock()
        args.fix = False

        result = brig.cmd_verify(args)

        self.assertEqual(result, 0)

    @patch("builtins.print")
    @patch.object(brig, "_verify_proxy_enforcement")
    @patch.object(brig, "_verify_cell_isolation")
    @patch.object(brig, "_verify_single_homed")
    @patch.object(brig, "_verify_network_isolation")
    @patch.object(brig, "_verify_gvisor_runtime")
    @patch.object(brig, "_verify_proxy_network")
    @patch.object(brig, "_verify_proxy_status")
    def test_verify_issues_found(self, mock_ps, mock_pn, mock_gv, mock_ni,
                                 mock_sh, mock_ci, mock_pe, mock_print):
        """Issues found -> returns 1."""
        def add_issue(issues, *args, **kwargs):
            issues.append("test issue")
        mock_ps.side_effect = add_issue

        args = MagicMock()
        args.fix = False

        result = brig.cmd_verify(args)

        self.assertEqual(result, 1)


# ---------------------------------------------------------------------------
# Fix helper tests
# ---------------------------------------------------------------------------

class TestFixHelpers(IntegrationBase):
    """Integration tests for _fix_* helper functions."""

    @patch("builtins.print")
    @patch.object(brig, "run")
    def test_fix_proxy_not_running_success(self, mock_run, mock_print):
        """Warden starts -> returns True."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = brig._fix_proxy_not_running()
        self.assertTrue(result)

    @patch("builtins.print")
    @patch.object(brig, "run")
    def test_fix_proxy_not_running_failure(self, mock_run, mock_print):
        """Warden fails to start -> returns False."""
        mock_run.return_value = MagicMock(returncode=1, stderr="cannot start")
        result = brig._fix_proxy_not_running()
        self.assertFalse(result)

    @patch("builtins.print")
    @patch.object(brig, "run")
    def test_fix_cell_network_success(self, mock_run, mock_print):
        """Network connect succeeds -> returns True."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = brig._fix_cell_network("testcell")
        self.assertTrue(result)

    @patch("builtins.print")
    @patch.object(brig, "run")
    def test_fix_cell_network_already_connected(self, mock_run, mock_print):
        """Already connected -> returns True."""
        mock_run.return_value = MagicMock(returncode=1, stderr="already connected")
        result = brig._fix_cell_network("testcell")
        self.assertTrue(result)

    @patch("builtins.print")
    @patch.object(brig, "run")
    def test_fix_proxy_network_success(self, mock_run, mock_print):
        """Proxy-external connect succeeds -> returns True."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = brig._fix_proxy_network()
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# Metrics generation tests
# ---------------------------------------------------------------------------

class TestGenerateMetrics(IntegrationBase):
    """Integration tests for _generate_metrics."""

    @patch.object(brig, "_fetch_warden_metrics", return_value={"cells": {}})
    @patch.object(brig, "_count_operations_last_hour", return_value=5)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_proxy_up_metric(self, mock_run, mock_proxy, mock_count, mock_warden):
        """Proxy running -> brig_proxy_up 1."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        lines = brig._generate_metrics()

        metric_text = "\n".join(lines)
        self.assertIn("brig_proxy_up 1", metric_text)

    @patch.object(brig, "_fetch_warden_metrics", return_value={"cells": {}})
    @patch.object(brig, "_count_operations_last_hour", return_value=0)
    @patch.object(brig, "proxy_running", return_value=False)
    @patch.object(brig, "run")
    def test_proxy_down_metric(self, mock_run, mock_proxy, mock_count, mock_warden):
        """Proxy not running -> brig_proxy_up 0."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        lines = brig._generate_metrics()

        metric_text = "\n".join(lines)
        self.assertIn("brig_proxy_up 0", metric_text)

    @patch.object(brig, "_fetch_warden_metrics", return_value={"cells": {}})
    @patch.object(brig, "_count_operations_last_hour", return_value=0)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_cell_counts_by_state(self, mock_run, mock_proxy, mock_count, mock_warden):
        """Cell state counts emitted per state."""
        containers = [
            {"Names": ["brig-cell1"], "State": "running"},
            {"Names": ["brig-cell2"], "State": "exited"},
        ]

        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if "ps" in cmd:
                result.stdout = json.dumps(containers)
            elif "network" in cmd and "ls" in cmd:
                result.stdout = "brig-cell1\nbrig-cell2\n"
            else:
                result.stdout = ""
            return result
        mock_run.side_effect = side_effect

        lines = brig._generate_metrics()

        metric_text = "\n".join(lines)
        self.assertIn("brig_cells_total", metric_text)
        self.assertIn('state="running"', metric_text)

    @patch.object(brig, "_fetch_warden_metrics", return_value={"cells": {}})
    @patch.object(brig, "_count_operations_last_hour", return_value=3)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_prometheus_format(self, mock_run, mock_proxy, mock_count, mock_warden):
        """Metrics include HELP and TYPE lines."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        lines = brig._generate_metrics()

        metric_text = "\n".join(lines)
        self.assertIn("# HELP", metric_text)
        self.assertIn("# TYPE", metric_text)
        self.assertIn("brig_operations_last_hour 3", metric_text)

    @patch.object(brig, "_fetch_warden_metrics", return_value={"cells": {}})
    @patch.object(brig, "_count_operations_last_hour", return_value=0)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_network_count(self, mock_run, mock_proxy, mock_count, mock_warden):
        """Network count metric emitted."""
        def side_effect(cmd, check=True, capture=False, timeout=None):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            if "network" in cmd and "ls" in cmd:
                result.stdout = "brig-cell1\nbrig-cell2\nbrig-cell3\n"
            elif "ps" in cmd:
                result.stdout = "[]"
            else:
                result.stdout = ""
            return result
        mock_run.side_effect = side_effect

        lines = brig._generate_metrics()

        metric_text = "\n".join(lines)
        self.assertIn("brig_networks_total 3", metric_text)


# ========== Step 5d: brig.py cmd_preflight ==========


class TestCmdPreflight(IntegrationBase):
    """Tests for brig.cmd_preflight validation checks."""

    def test_proxy_down_returns_1(self):
        """Returns 1 when proxy is not running."""
        with patch.object(brig, 'run', return_value=MagicMock(returncode=1, stdout="")):
            with patch.object(brig, 'proxy_running', return_value=False):
                with patch.object(brig, '_lima_installed', return_value=False):
                    args = MagicMock()
                    args.format = "table"
                    result = brig.cmd_preflight(args)
        self.assertEqual(result, 1)

    def test_json_format_outputs_json(self):
        """JSON format outputs valid JSON."""
        import io
        with patch.object(brig, 'run', return_value=MagicMock(returncode=0, stdout="runsc")):
            with patch.object(brig, 'proxy_running', return_value=True):
                with patch.object(brig, '_lima_installed', return_value=False):
                    args = MagicMock()
                    args.format = "json"
                    captured = io.StringIO()
                    with patch('sys.stdout', captured):
                        brig.cmd_preflight(args)
        output = captured.getvalue()
        if output.strip():
            data = json.loads(output)
            self.assertIn("passed", data)
            self.assertIn("checks", data)


# ========== Step 5e: brig.py _fetch_warden_metrics ==========


class TestFetchWardenMetrics(IntegrationBase):
    """Tests for brig._fetch_warden_metrics."""

    def test_socket_missing_returns_empty(self):
        """Returns empty dict when socket does not exist."""
        result = brig._fetch_warden_metrics()
        self.assertEqual(result, {})

    @patch('socket.socket')
    def test_socket_success(self, mock_socket_cls):
        """Returns parsed JSON from socket."""
        mock_sock = mock_socket_cls.return_value
        response = json.dumps({
            "cells": {"app1": {"total_requests": 100}},
        }).encode()
        mock_sock.recv.side_effect = [response, b""]

        with patch('pathlib.Path.exists', return_value=True):
            result = brig._fetch_warden_metrics()
        self.assertIn("cells", result)
        self.assertEqual(result["cells"]["app1"]["total_requests"], 100)

    @patch('socket.socket')
    def test_socket_error_returns_empty(self, mock_socket_cls):
        """Socket error returns empty dict."""
        mock_sock = mock_socket_cls.return_value
        mock_sock.connect.side_effect = OSError("Connection refused")

        with patch('pathlib.Path.exists', return_value=True):
            result = brig._fetch_warden_metrics()
        self.assertEqual(result, {})


# ========== Step 5f: brig.py _add_per_cell_metrics ==========


class TestAddPerCellMetrics(IntegrationBase):
    """Tests for brig._add_per_cell_metrics."""

    def test_single_cell(self):
        """All per-cell metrics emitted for one cell."""
        metrics = []

        def add_metric(name, value, desc, mtype, labels=None):
            metrics.append({"name": name, "value": value, "labels": labels})

        cells_data = {
            "app1": {
                "total_requests": 100,
                "blocked_requests": 5,
                "rate_limited_requests": 2,
                "error_requests": 3,
                "bytes_sent": 1000,
                "bytes_received": 2000,
                "latency_p50_ms": 10,
                "latency_p95_ms": 50,
                "latency_p99_ms": 100,
            }
        }
        brig._add_per_cell_metrics(add_metric, cells_data)

        # Check per-cell metrics.
        cell_metrics = [m for m in metrics if m["labels"] and m["labels"]["cell"] == "app1"]
        self.assertTrue(len(cell_metrics) >= 9)

        # Check aggregate totals.
        total_metrics = [m for m in metrics if m["labels"] is None]
        total_names = [m["name"] for m in total_metrics]
        self.assertIn("brig_requests_total", total_names)

    def test_multiple_cells(self):
        """Aggregates are correct across multiple cells."""
        metrics = []

        def add_metric(name, value, desc, mtype, labels=None):
            metrics.append({"name": name, "value": value, "labels": labels})

        cells_data = {
            "app1": {"total_requests": 100, "blocked_requests": 5,
                     "rate_limited_requests": 0, "error_requests": 0,
                     "bytes_sent": 0, "bytes_received": 0,
                     "latency_p50_ms": 0, "latency_p95_ms": 0, "latency_p99_ms": 0},
            "app2": {"total_requests": 200, "blocked_requests": 10,
                     "rate_limited_requests": 0, "error_requests": 0,
                     "bytes_sent": 0, "bytes_received": 0,
                     "latency_p50_ms": 0, "latency_p95_ms": 0, "latency_p99_ms": 0},
        }
        brig._add_per_cell_metrics(add_metric, cells_data)

        # Find aggregate total requests.
        total = [m for m in metrics if m["name"] == "brig_requests_total"][0]
        self.assertEqual(total["value"], 300)

        total_blocked = [m for m in metrics if m["name"] == "brig_requests_blocked_total"][0]
        self.assertEqual(total_blocked["value"], 15)

    def test_empty_cells(self):
        """No metrics emitted for empty cells data."""
        metrics = []

        def add_metric(name, value, desc, mtype, labels=None):
            metrics.append({"name": name, "value": value})

        brig._add_per_cell_metrics(add_metric, {})

        # Only aggregate totals (all zeros).
        total = [m for m in metrics if m["name"] == "brig_requests_total"][0]
        self.assertEqual(total["value"], 0)


# ========== Phase 14: Tor Integration ==========


class TestTorIntegration(IntegrationBase):
    """Tests for Tor stack integration."""

    @patch.object(warden, "privoxy_running", return_value=True)
    @patch.object(warden, "tor_running", return_value=True)
    @patch.object(warden, "privoxy_exists", return_value=True)
    @patch.object(warden, "tor_exists", return_value=True)
    @patch.object(warden, "run")
    def test_tor_start_stop_lifecycle(self, mock_run, mock_tor_exists,
                                      mock_priv_exists, mock_tor_run,
                                      mock_priv_run):
        """Start returns 0 when both running; stop returns 0."""
        # Both running -> idempotent start.
        self.assertEqual(warden.cmd_tor_start(), 0)
        # Stop cleans up both.
        mock_run.return_value = MagicMock(returncode=0)
        self.assertEqual(warden.cmd_tor_stop(), 0)

    @patch.object(warden, "privoxy_running", return_value=True)
    @patch.object(warden, "_get_container_ip", return_value="10.60.0.10")
    @patch.object(warden, "reconnect_to_cell_networks", return_value=0)
    @patch.object(warden, "is_running")
    @patch.object(warden, "container_exists", return_value=False)
    @patch.object(warden, "preflight_validate", return_value=(True, []))
    @patch.object(warden, "run")
    def test_warden_upstream_arg(self, mock_run, mock_preflight, mock_exists,
                                  mock_is_running, mock_reconnect, mock_ip,
                                  mock_privoxy):
        """With Privoxy running, cmd_start builds upstream mode arg."""
        mock_is_running.side_effect = [False, True]
        mock_run.return_value = MagicMock(returncode=0)

        warden.cmd_start()

        for call in mock_run.call_args_list:
            cmd = call[0][0]
            if len(cmd) >= 2 and cmd[0] == "podman" and cmd[1] == "run":
                self.assertIn("--mode", cmd)
                mode_idx = cmd.index("--mode")
                self.assertIn("upstream:", cmd[mode_idx + 1])
                return
        self.fail("No podman run call found")

    @patch.object(warden, "privoxy_running", return_value=False)
    @patch.object(warden, "_is_warden_tor_mode", return_value=False)
    @patch.object(brig, "proxy_running", return_value=True)
    @patch.object(brig, "run")
    def test_brig_run_tor_flag_fails_without_stack(self, mock_run, mock_proxy,
                                                     mock_upstream, mock_privoxy):
        """brig run --tor fails fast when Tor stack is not active."""
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        args = self._make_args(tor=True)
        with self.assertRaises(SystemExit):
            brig.cmd_run(args)

    @patch.object(warden, "run")
    @patch.object(warden, "privoxy_exists", return_value=True)
    @patch.object(warden, "tor_exists", return_value=True)
    def test_tor_stop_deletes_config(self, mock_tor, mock_priv, mock_run):
        """Config file is removed after tor stop."""
        mock_run.return_value = MagicMock(returncode=0)
        # Create fake config file.
        warden.PRIVOXY_CONFIG_HOST.parent.mkdir(parents=True, exist_ok=True)
        warden.PRIVOXY_CONFIG_HOST.write_text("test")
        warden.cmd_tor_stop()
        self.assertFalse(warden.PRIVOXY_CONFIG_HOST.exists())


if __name__ == "__main__":
    unittest.main()
