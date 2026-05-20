"""brig system stats — Prometheus parsing + aggregation."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


SAMPLE_METRICS = """
# HELP brig_warden_requests_total Number of HTTP requests through warden
# TYPE brig_warden_requests_total counter
brig_warden_requests_total{cell="alice",decision="allowed",method="GET"} 12 1779242167119
brig_warden_requests_total{cell="alice",decision="blocked",method="POST"} 3 1779242167119
brig_warden_requests_total{cell="bob",decision="allowed",method="GET"} 5 1779242167119
# HELP brig_warden_blocked_total Number of HTTP requests blocked by warden
# TYPE brig_warden_blocked_total counter
brig_warden_blocked_total{cell="alice",reason="cell policy: not allowlisted"} 3 1779242167119
# HELP brig_warden_bytes_in_total bytes
# TYPE brig_warden_bytes_in_total counter
brig_warden_bytes_in_total{cell="alice"} 4096 1779242167119
brig_warden_bytes_in_total{cell="bob"} 256 1779242167119
# HELP brig_warden_bytes_out_total bytes
# TYPE brig_warden_bytes_out_total counter
brig_warden_bytes_out_total{cell="alice"} 32768 1779242167119
brig_warden_bytes_out_total{cell="bob"} 1024 1779242167119
# HELP brig_warden_request_duration_ms_milliseconds duration
# TYPE brig_warden_request_duration_ms_milliseconds histogram
brig_warden_request_duration_ms_milliseconds_bucket{cell="alice",le="5"} 5 1779242167119
brig_warden_request_duration_ms_milliseconds_bucket{cell="alice",le="10"} 10 1779242167119
brig_warden_request_duration_ms_milliseconds_bucket{cell="alice",le="25"} 14 1779242167119
brig_warden_request_duration_ms_milliseconds_bucket{cell="alice",le="50"} 15 1779242167119
brig_warden_request_duration_ms_milliseconds_bucket{cell="alice",le="+Inf"} 15 1779242167119
brig_warden_request_duration_ms_milliseconds_sum{cell="alice"} 180.5 1779242167119
brig_warden_request_duration_ms_milliseconds_count{cell="alice"} 15 1779242167119
"""


class TestPromQLParser(unittest.TestCase):
    def test_parses_counter_with_labels(self):
        from brig.observability.promql import parse
        scalars, _ = parse(SAMPLE_METRICS)
        requests = scalars.get("brig_warden_requests_total", [])
        self.assertEqual(len(requests), 3)
        alice_blocked = next(
            s for s in requests
            if s.labels.get("cell") == "alice"
            and s.labels.get("decision") == "blocked"
        )
        self.assertEqual(alice_blocked.value, 3.0)
        self.assertEqual(alice_blocked.labels["method"], "POST")

    def test_histogram_grouped_by_labels(self):
        from brig.observability.promql import parse
        _, histos = parse(SAMPLE_METRICS)
        durations = histos.get("brig_warden_request_duration_ms_milliseconds", [])
        self.assertEqual(len(durations), 1)
        h = durations[0]
        self.assertEqual(h.count, 15.0)
        self.assertEqual(h.sum, 180.5)
        # Buckets sorted ascending by le.
        self.assertEqual([b[0] for b in h.buckets], [5.0, 10.0, 25.0, 50.0, float("inf")])

    def test_histogram_quantile_interpolates(self):
        from brig.observability.promql import parse
        _, histos = parse(SAMPLE_METRICS)
        h = histos["brig_warden_request_duration_ms_milliseconds"][0]
        # 15 observations; p50 target = 7.5 → in (5, 10] bucket, where
        # cum goes 5→10 (5 obs in bucket). Interpolation: 5 + (7.5-5)/(10-5) * (10-5) = 7.5
        self.assertAlmostEqual(h.quantile(0.50), 7.5, places=1)

    def test_quantile_zero_for_empty_histogram(self):
        from brig.observability.promql import Histogram
        h = Histogram(labels={})
        self.assertEqual(h.quantile(0.99), 0.0)


class TestAggregate(unittest.TestCase):
    def test_pivots_to_per_cell(self):
        from brig.observability.promql import parse
        from brig.observability.stats import aggregate
        scalars, histos = parse(SAMPLE_METRICS)
        by_cell = aggregate(scalars, histos)
        self.assertIn("alice", by_cell)
        self.assertIn("bob", by_cell)
        alice = by_cell["alice"]
        # 12 allowed + 3 blocked = 15 total requests
        self.assertEqual(alice.requests, 15)
        self.assertEqual(alice.blocked, 3)
        self.assertEqual(alice.bytes_in, 4096)
        self.assertEqual(alice.bytes_out, 32768)
        # Histogram populated.
        self.assertGreater(alice.p50_ms, 0)


class TestRenderText(unittest.TestCase):
    def test_no_cells_message(self):
        from brig.observability.stats import render_text
        out = render_text({})
        self.assertIn("no metrics yet", out)

    def test_renders_per_cell_row(self):
        from brig.observability.stats import CellStats, render_text
        out = render_text({"alice": CellStats(
            cell="alice", requests=15, blocked=3,
            bytes_in=4096, bytes_out=32768,
            p50_ms=7.5, p95_ms=22.0, p99_ms=48.0,
        )})
        self.assertIn("alice", out)
        self.assertIn("15", out)
        self.assertIn("3 (20.0%)", out)
        self.assertIn("4K", out)
        self.assertIn("32K", out)

    def test_passthrough_columns_only_called_out_when_present(self):
        """The PT/* explainer line only appears when a cell actually had
        passthrough connections — otherwise it'd noise the common case."""
        from brig.observability.stats import CellStats, render_text
        out_no_pt = render_text({"alice": CellStats(
            cell="alice", requests=10,
        )})
        self.assertNotIn("PT/* =", out_no_pt)

        out_with_pt = render_text({"codex": CellStats(
            cell="codex", requests=5, passthrough_conns=2,
            passthrough_bytes_in=4096,
            passthrough_bytes_out=8192,
        )})
        self.assertIn("PT/* =", out_with_pt)
        self.assertIn("invariant 11", out_with_pt)
        self.assertIn("4K", out_with_pt)
        self.assertIn("8K", out_with_pt)


class TestCmdStats(unittest.TestCase):
    def test_fetch_failure_raises(self):
        from brig.observability.stats import fetch_metrics
        from brig.errors import BrigError
        with patch("brig.observability.stats.vm_run",
                   return_value=MagicMock(returncode=1, stdout="")):
            with self.assertRaises(BrigError) as ctx:
                fetch_metrics()
        self.assertIn("collector", str(ctx.exception).lower())

    def test_end_to_end_with_mocked_scrape(self):
        from brig.observability.stats import cmd_stats
        captured: list[str] = []
        with patch("brig.observability.stats.vm_run",
                   return_value=MagicMock(returncode=0, stdout=SAMPLE_METRICS)), \
             patch("brig.observability.stats.output",
                   side_effect=captured.append):
            rc = cmd_stats(None)
        self.assertEqual(rc, 0)
        text = "\n".join(captured)
        self.assertIn("alice", text)
        self.assertIn("bob", text)


if __name__ == "__main__":
    unittest.main()
