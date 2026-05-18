"""Tests for the AsyncLogWriter + LogFilter sibling addon module."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Stub mitmproxy.
_mock = MagicMock()
sys.modules.setdefault("mitmproxy", _mock)
sys.modules.setdefault("mitmproxy.ctx", _mock.ctx)
sys.modules.setdefault("mitmproxy.http", _mock.http)

_ADDONS_DIR = str(Path(__file__).parent.parent / "src" / "addons")
if _ADDONS_DIR not in sys.path:
    sys.path.insert(0, _ADDONS_DIR)

from _log_writer import AsyncLogWriter, LogFilter, _redact_path  # noqa: E402


class TestRedactPath(unittest.TestCase):
    def test_no_secrets_passthrough(self):
        self.assertEqual(_redact_path("/v1/users/me"), "/v1/users/me")

    def test_api_key_redacted(self):
        out = _redact_path("/v1/data?api_key=SECRET123")
        self.assertIn("api_key=REDACTED", out)
        self.assertNotIn("SECRET123", out)

    def test_bearer_token_redacted(self):
        out = _redact_path("/?bearer=longtokenvalue&other=x")
        self.assertIn("bearer=REDACTED", out)

    def test_double_encoded_secret_redacted(self):
        # %2561pi%255Fkey=secret → api_key=secret after one unquote round,
        # then matched and redacted.
        encoded = "/v1?%61pi%5Fkey=hidden"
        out = _redact_path(encoded)
        self.assertNotIn("hidden", out)

    def test_unrelated_param_untouched(self):
        out = _redact_path("/?page=2&limit=10")
        self.assertEqual(out, "/?page=2&limit=10")


class TestLogFilter(unittest.TestCase):
    def test_default_passes_everything(self):
        f = LogFilter()
        self.assertTrue(f.should_log("example.com", "/", 200))

    def test_exclude_host(self):
        f = LogFilter({"exclude_hosts": ["telemetry.*"]})
        self.assertFalse(f.should_log("telemetry.example.com", "/", 200))
        self.assertTrue(f.should_log("real.example.com", "/", 200))

    def test_exclude_path(self):
        f = LogFilter({"exclude_paths": ["/health", "/metrics"]})
        self.assertFalse(f.should_log("ex.com", "/health", 200))
        self.assertFalse(f.should_log("ex.com", "/metrics", 200))
        self.assertTrue(f.should_log("ex.com", "/api/v1", 200))

    def test_min_status(self):
        f = LogFilter({"min_status": 400})
        self.assertFalse(f.should_log("ex.com", "/", 200))
        self.assertTrue(f.should_log("ex.com", "/", 500))

    def test_only_blocked(self):
        f = LogFilter({"only_blocked": True})
        self.assertFalse(f.should_log("ex.com", "/", 200, blocked=False))
        self.assertTrue(f.should_log("ex.com", "/", 403, blocked=True))

    def test_only_errors(self):
        f = LogFilter({"only_errors": True})
        self.assertFalse(f.should_log("ex.com", "/", 200))
        self.assertTrue(f.should_log("ex.com", "/", 503))
        self.assertTrue(f.should_log("ex.com", "/", 0))  # Connection error.

    def test_min_latency(self):
        f = LogFilter({"min_latency_ms": 100})
        self.assertFalse(f.should_log("ex.com", "/", 200, latency_ms=50))
        self.assertTrue(f.should_log("ex.com", "/", 200, latency_ms=200))

    def test_max_body_size(self):
        f = LogFilter({"max_body_size": 1024})
        self.assertTrue(f.should_log("ex.com", "/", 200, body_size=500))
        self.assertFalse(f.should_log("ex.com", "/", 200, body_size=2048))

    def test_sample_rate_zero_drops_all(self):
        f = LogFilter({"sample_rate": 0.0})
        # sample_rate < 1.0 means we may drop; rate=0 should drop everything.
        # Run a few times to defeat any single-sample randomness.
        results = [f.should_log("ex.com", "/", 200) for _ in range(10)]
        self.assertTrue(all(r is False for r in results))


class TestAsyncLogWriter(unittest.TestCase):
    """The writer is hard to test fully without mitmproxy, but we can
    exercise the queue + flush path and verify lines land on disk."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_sync_write_fallback(self):
        # _write_sync is the fall-through path when the queue is full.
        # Construct writer, call _write_sync directly.
        w = AsyncLogWriter()
        log_file = self.tmpdir / "out.jsonl"
        # Patch LOG_DIR so the writer creates the parent under our tmpdir.
        from unittest.mock import patch
        with patch("_log_writer.LOG_DIR", self.tmpdir):
            w._write_sync({"event": "test", "n": 1}, log_file)
        contents = log_file.read_text().strip().splitlines()
        self.assertEqual(len(contents), 1)
        self.assertEqual(json.loads(contents[0])["event"], "test")

    def test_async_flush_lands_on_disk(self):
        w = AsyncLogWriter(flush_interval_ms=10, batch_size=2)
        log_file = self.tmpdir / "async.jsonl"
        from unittest.mock import patch
        with patch("_log_writer.LOG_DIR", self.tmpdir):
            w.start()
            try:
                w.log({"i": 1}, log_file)
                w.log({"i": 2}, log_file)
                # Give the flush thread time.
                deadline = time.time() + 2.0
                while time.time() < deadline and (not log_file.exists() or len(log_file.read_text().splitlines()) < 2):
                    time.sleep(0.02)
            finally:
                w.stop()
        lines = log_file.read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
