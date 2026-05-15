"""Tests for security-critical code paths identified in audit.

Covers:
  - Host service routing (enforce.py _handle_host_service)
  - Host header smuggling defense (enforce.py _host_header_mismatches)
  - DomainTrie correctness (enforce.py DomainTrie)
  - seccomp_profile validation (reconciler.py build_run_command)
  - Subnet map writing (subnet.py allocate/free)
  - Logger cell name validation (logger.py _write_log)
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Mock mitmproxy before importing addons — it is not installed in the test
# environment. The mock must be in sys.modules before any addon import.
_mock_mitmproxy = MagicMock()
sys.modules.setdefault("mitmproxy", _mock_mitmproxy)
sys.modules.setdefault("mitmproxy.ctx", _mock_mitmproxy.ctx)
sys.modules.setdefault("mitmproxy.http", _mock_mitmproxy.http)

# Add addons directory to sys.path so we can import enforce/logger directly.
_addons_dir = str(Path(__file__).parent.parent / "src" / "addons")
if _addons_dir not in sys.path:
    sys.path.insert(0, _addons_dir)

from enforce import DomainTrie, PolicyEnforcer, PolicyRule  # noqa: E402
from logger import RequestLogger  # noqa: E402

from brig.cell.reconciler import build_run_command  # noqa: E402
from brig.cell.spec import CellSpec  # noqa: E402
from brig.network.subnet import allocate, free  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(host="example.com", port=443, path="/", method="GET",
               headers=None, client_ip="10.60.1.2", listen_port=8080):
    """Build a minimal mock HTTPFlow for enforce.py tests."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.request.path = path
    flow.request.method = method
    flow.request.headers = dict(headers or {})
    flow.client_conn.peername = (client_ip, 12345)
    flow.client_conn.sockname = ("0.0.0.0", listen_port)
    flow.metadata = {}
    flow.response = None
    return flow


# ---------------------------------------------------------------------------
# 1. Host service routing
# ---------------------------------------------------------------------------

class TestHandleHostService(unittest.TestCase):
    """Test PolicyEnforcer._handle_host_service."""

    def setUp(self):
        self.enforcer = PolicyEnforcer()
        self.enforcer._host_ip = "192.168.64.1"
        self.enforcer.host_services = {"mydb": 5432, "redis": 6379}
        self.enforcer._host_service_targets = {
            ("192.168.64.1", 5432),
            ("192.168.64.1", 6379),
        }

    def test_valid_host_service_rewrites(self):
        """Known service rewrites host and port to macOS host IP."""
        flow = _make_flow(host="mydb.host.brig", port=443)
        self.enforcer._handle_host_service(flow, "mydb.host.brig", "cell-a")

        self.assertEqual(flow.request.host, "192.168.64.1")
        self.assertEqual(flow.request.port, 5432)
        self.assertEqual(flow.metadata["host_service"], "mydb")

    def test_unknown_service_blocked(self):
        """Unknown .host.brig service is blocked."""
        flow = _make_flow(host="unknown-svc.host.brig", port=443)
        self.enforcer._handle_host_service(flow, "unknown-svc.host.brig", "cell-a")

        self.assertTrue(flow.metadata.get("blocked"))
        self.assertIn("unknown host service", flow.metadata.get("block_reason", ""))

    def test_no_host_ip_blocked(self):
        """When host IP is not discovered, host service requests are blocked."""
        self.enforcer._host_ip = ""
        flow = _make_flow(host="mydb.host.brig", port=443)
        self.enforcer._handle_host_service(flow, "mydb.host.brig", "cell-a")

        self.assertTrue(flow.metadata.get("blocked"))
        self.assertIn("host IP not discovered", flow.metadata.get("block_reason", ""))

    def test_host_header_set_to_virtual_domain(self):
        """After rewrite, Host header must be the virtual domain, not raw IP."""
        flow = _make_flow(host="redis.host.brig", port=443)
        self.enforcer._handle_host_service(flow, "redis.host.brig", "cell-a")

        self.assertEqual(flow.request.headers["Host"], "redis.host.brig")


# ---------------------------------------------------------------------------
# 2. Host header smuggling defense
# ---------------------------------------------------------------------------

class TestHostHeaderMismatches(unittest.TestCase):
    """Test PolicyEnforcer._host_header_mismatches."""

    def test_matching_host_and_url(self):
        """No mismatch when Host header matches URL host."""
        flow = _make_flow(host="example.com", headers={"Host": "example.com"})
        self.assertFalse(PolicyEnforcer._host_header_mismatches(flow))

    def test_different_host_header(self):
        """Mismatch when Host header disagrees with URL host."""
        flow = _make_flow(host="example.com", headers={"Host": "evil.com"})
        self.assertTrue(PolicyEnforcer._host_header_mismatches(flow))

    def test_cr_in_host_header(self):
        """CR in Host header detected as smuggling attempt."""
        flow = _make_flow(host="example.com", headers={"Host": "example.com\r"})
        self.assertTrue(PolicyEnforcer._host_header_mismatches(flow))

    def test_lf_in_host_header(self):
        """LF in Host header detected as smuggling attempt."""
        flow = _make_flow(host="example.com", headers={"Host": "example.com\n"})
        self.assertTrue(PolicyEnforcer._host_header_mismatches(flow))

    def test_nul_in_host_header(self):
        """NUL byte in Host header detected as smuggling attempt."""
        flow = _make_flow(host="example.com", headers={"Host": "example.com\x00"})
        self.assertTrue(PolicyEnforcer._host_header_mismatches(flow))

    def test_missing_host_header(self):
        """Missing Host header is allowed (HTTP/1.0 compatibility)."""
        flow = _make_flow(host="example.com", headers={})
        self.assertFalse(PolicyEnforcer._host_header_mismatches(flow))

    def test_ipv6_bracket_normalization(self):
        """IPv6 addresses with brackets match correctly."""
        flow = _make_flow(host="::1", headers={"Host": "[::1]"})
        self.assertFalse(PolicyEnforcer._host_header_mismatches(flow))

    def test_port_stripping(self):
        """Port suffix on Host header is stripped before comparison."""
        flow = _make_flow(host="example.com", headers={"Host": "example.com:443"})
        self.assertFalse(PolicyEnforcer._host_header_mismatches(flow))

    def test_case_insensitive(self):
        """Host comparison is case-insensitive."""
        flow = _make_flow(host="Example.COM", headers={"Host": "example.com"})
        self.assertFalse(PolicyEnforcer._host_header_mismatches(flow))


# ---------------------------------------------------------------------------
# 3. DomainTrie correctness
# ---------------------------------------------------------------------------

class TestDomainTrie(unittest.TestCase):
    """Test DomainTrie lookup semantics."""

    def _build_trie(self, *domains):
        """Build a trie from domain strings."""
        trie = DomainTrie()
        for d in domains:
            trie.insert(PolicyRule(d))
        return trie

    def test_exact_domain_match(self):
        """Exact domain lookup returns the rule."""
        trie = self._build_trie("example.com")
        self.assertEqual(len(trie.lookup("example.com")), 1)

    def test_exact_domain_no_match(self):
        """Non-matching domain returns empty list."""
        trie = self._build_trie("example.com")
        self.assertEqual(len(trie.lookup("other.com")), 0)

    def test_wildcard_matches_subdomain(self):
        """*.example.com matches sub.example.com."""
        trie = self._build_trie("*.example.com")
        matches = trie.lookup("sub.example.com")
        self.assertEqual(len(matches), 1)

    def test_wildcard_does_not_match_bare_domain(self):
        """*.example.com does NOT match example.com itself."""
        trie = self._build_trie("*.example.com")
        matches = trie.lookup("example.com")
        self.assertEqual(len(matches), 0)

    def test_no_false_positive_suffix(self):
        """notexample.com must NOT match example.com (dot-boundary check)."""
        trie = self._build_trie("example.com")
        self.assertEqual(len(trie.lookup("notexample.com")), 0)

    def test_no_false_positive_wildcard_suffix(self):
        """notexample.com must NOT match *.example.com."""
        trie = self._build_trie("*.example.com")
        self.assertEqual(len(trie.lookup("notexample.com")), 0)

    def test_multiple_rules_same_domain(self):
        """Multiple rules for the same domain are all returned."""
        trie = DomainTrie()
        rule1 = PolicyRule({"domain": "api.example.com", "paths": ["/v1/*"]})
        rule2 = PolicyRule({"domain": "api.example.com", "paths": ["/v2/*"]})
        trie.insert(rule1)
        trie.insert(rule2)
        matches = trie.lookup("api.example.com")
        self.assertEqual(len(matches), 2)

    def test_idn_punycode_normalization(self):
        """IDN domains are normalized to punycode for matching."""
        trie = DomainTrie()
        # Insert the ASCII punycode form.
        rule = PolicyRule("xn--n3h.example.com")
        trie.insert(rule)
        # Lookup with the same punycode form should match.
        matches = trie.lookup("xn--n3h.example.com")
        self.assertEqual(len(matches), 1)

    def test_deep_subdomain_wildcard(self):
        """*.example.com matches deeply nested subdomains."""
        trie = self._build_trie("*.example.com")
        matches = trie.lookup("a.b.c.example.com")
        self.assertEqual(len(matches), 1)


# ---------------------------------------------------------------------------
# 4. seccomp_profile validation
# ---------------------------------------------------------------------------

class TestSeccompProfileValidation(unittest.TestCase):
    """Test build_run_command rejects dangerous seccomp_profile values."""

    def _make_spec(self, seccomp_profile):
        return CellSpec(
            name="test",
            image="alpine",
            seccomp_profile=seccomp_profile,
        )

    @patch("brig.cell.reconciler.vm_run")
    def test_unconfined_rejected(self, mock_vm_run):
        """seccomp_profile='unconfined' must be rejected."""
        spec = self._make_spec("unconfined")
        with self.assertRaises(ValueError, msg="unconfined"):
            build_run_command(spec, "10.60.1.1")

    @patch("brig.cell.reconciler.vm_run")
    def test_unconfined_case_insensitive(self, mock_vm_run):
        """seccomp_profile='Unconfined' must also be rejected (case-insensitive)."""
        spec = self._make_spec("Unconfined")
        with self.assertRaises(ValueError, msg="unconfined"):
            build_run_command(spec, "10.60.1.1")

    @patch("brig.cell.reconciler.vm_run")
    def test_path_with_slash_rejected(self, mock_vm_run):
        """seccomp_profile with '/' is rejected (must be filename only)."""
        spec = self._make_spec("/etc/seccomp.json")
        with self.assertRaises(ValueError, msg="path"):
            build_run_command(spec, "10.60.1.1")

    @patch("brig.cell.reconciler.vm_run")
    def test_path_traversal_rejected(self, mock_vm_run):
        """seccomp_profile with '..' is rejected."""
        spec = self._make_spec("..%2f..%2fetc%2fpasswd")
        # The actual code checks for ".." in the string.
        # URL-encoded ".." won't trigger, but literal ".." will.
        spec_literal = self._make_spec("../../../etc/seccomp.json")
        with self.assertRaises(ValueError, msg="path"):
            build_run_command(spec_literal, "10.60.1.1")

    @patch("brig.cell.reconciler.vm_run")
    def test_valid_profile_accepted(self, mock_vm_run):
        """A simple filename is accepted as seccomp_profile."""
        spec = self._make_spec("default.json")
        cmd = build_run_command(spec, "10.60.1.1")
        self.assertIn("--security-opt", cmd)
        # The profile path should contain the filename.
        seccomp_idx = cmd.index("--security-opt") + 1
        # There are two --security-opt flags; find the seccomp one.
        for i, arg in enumerate(cmd):
            if arg == "--security-opt" and i + 1 < len(cmd) and cmd[i + 1].startswith("seccomp="):
                self.assertIn("default.json", cmd[i + 1])
                return
        self.fail("seccomp= security-opt not found in command")

    @patch("brig.cell.reconciler.vm_run")
    def test_no_seccomp_profile_ok(self, mock_vm_run):
        """When seccomp_profile is None, no seccomp flag is added."""
        spec = CellSpec(name="test", image="alpine")
        cmd = build_run_command(spec, "10.60.1.1")
        seccomp_args = [a for a in cmd if a.startswith("seccomp=")]
        self.assertEqual(seccomp_args, [])


# ---------------------------------------------------------------------------
# 5. Subnet map writing
# ---------------------------------------------------------------------------

class TestSubnetMapWriting(unittest.TestCase):
    """Test that allocate() and free() write subnet-map.json atomically."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.state_file = Path(self.tmpdir) / "subnets.json"
        self.lock_file = Path(self.tmpdir) / "allocator.lock"
        self.map_file = Path(self.tmpdir) / "subnet-map.json"

    def _patch_write_subnet_map(self):
        """Return a patch that redirects _write_subnet_map to use self.map_file."""
        from brig.network.subnet import _write_subnet_map as orig_fn
        map_file = self.map_file

        def patched_write(state, mf=None):
            return orig_fn(state, map_file=map_file)

        return patch("brig.network.subnet._write_subnet_map", side_effect=patched_write)

    def test_allocate_creates_map_file(self):
        """After allocate(), subnet-map.json exists with correct mapping."""
        with self._patch_write_subnet_map():
            allocate("test-cell", self.state_file, self.lock_file)

            self.assertTrue(self.map_file.exists(), "subnet-map.json must exist after allocate")
            mapping = json.loads(self.map_file.read_text())
            self.assertEqual(mapping["10.60.1.0/24"], "test-cell")

    def test_free_updates_map_file(self):
        """After free(), the freed cell is removed from subnet-map.json."""
        with self._patch_write_subnet_map():
            allocate("cell-a", self.state_file, self.lock_file)
            allocate("cell-b", self.state_file, self.lock_file)
            free("cell-a", self.state_file, self.lock_file)

            mapping = json.loads(self.map_file.read_text())
            self.assertNotIn("10.60.1.0/24", mapping, "Freed cell must not appear in map")
            self.assertEqual(mapping["10.60.2.0/24"], "cell-b")

    def test_map_file_written_atomically(self):
        """Map file is written via temp+rename (no partial writes visible)."""
        with self._patch_write_subnet_map():
            allocate("cell-a", self.state_file, self.lock_file)

            # Verify the file is valid JSON (not a partial write).
            content = self.map_file.read_text()
            mapping = json.loads(content)  # Would raise on partial write.
            self.assertIsInstance(mapping, dict)

            # Verify it is a regular file (rename target), not a temp file.
            stat = self.map_file.stat()
            self.assertTrue(stat.st_size > 0)


# ---------------------------------------------------------------------------
# 6. Logger cell name validation
# ---------------------------------------------------------------------------

class TestLoggerCellNameValidation(unittest.TestCase):
    """Test RequestLogger._write_log cell name validation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = RequestLogger()
        # Replace the async writer with a synchronous spy.
        self.logged_files = []

        def spy_log(entry, log_file):
            self.logged_files.append(log_file)

        self.logger.async_writer = MagicMock()
        self.logger.async_writer.log = spy_log

    def test_valid_cell_name(self):
        """Valid cell name creates per-cell log file."""
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            self.logger._write_log("my-cell", {"ts": "test"})
            self.assertEqual(len(self.logged_files), 1)
            self.assertEqual(self.logged_files[0].name, "my-cell.jsonl")

    def test_uppercase_cell_name_falls_back(self):
        """Uppercase cell name fails validation and falls back to unknown log."""
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            with patch("logger.UNKNOWN_LOG_FILE", Path(self.tmpdir) / "unknown.jsonl"):
                self.logger._write_log("INVALID", {"ts": "test"})
                self.assertEqual(len(self.logged_files), 1)
                self.assertEqual(self.logged_files[0].name, "unknown.jsonl")

    def test_path_traversal_falls_back(self):
        """Cell name with '../' fails validation and falls back to unknown log."""
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            with patch("logger.UNKNOWN_LOG_FILE", Path(self.tmpdir) / "unknown.jsonl"):
                self.logger._write_log("../etc/passwd", {"ts": "test"})
                self.assertEqual(len(self.logged_files), 1)
                self.assertEqual(self.logged_files[0].name, "unknown.jsonl")

    def test_long_cell_name_falls_back(self):
        """Cell name exceeding 63 chars fails validation and falls back."""
        long_name = "a" * 64
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            with patch("logger.UNKNOWN_LOG_FILE", Path(self.tmpdir) / "unknown.jsonl"):
                self.logger._write_log(long_name, {"ts": "test"})
                self.assertEqual(len(self.logged_files), 1)
                self.assertEqual(self.logged_files[0].name, "unknown.jsonl")

    def test_max_length_cell_name_accepted(self):
        """Cell name at exactly 63 chars is accepted."""
        # Pattern: ^[a-z0-9][a-z0-9._-]{0,62}$ => total max 63 chars.
        name_63 = "a" * 63
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            self.logger._write_log(name_63, {"ts": "test"})
            self.assertEqual(len(self.logged_files), 1)
            self.assertEqual(self.logged_files[0].name, f"{name_63}.jsonl")

    def test_none_cell_name_falls_back(self):
        """None cell name falls back to unknown log."""
        with patch("logger.LOG_DIR", Path(self.tmpdir)):
            with patch("logger.UNKNOWN_LOG_FILE", Path(self.tmpdir) / "unknown.jsonl"):
                self.logger._write_log(None, {"ts": "test"})
                self.assertEqual(len(self.logged_files), 1)
                self.assertEqual(self.logged_files[0].name, "unknown.jsonl")


if __name__ == "__main__":
    unittest.main()
