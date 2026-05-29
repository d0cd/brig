"""brig cell trace — OTLP JSONL parsing + render."""

from __future__ import annotations

import json
import types
import unittest
from unittest.mock import MagicMock, patch


def _otlp_batch(spans):
    """Wrap a list of spans into one OTLP ResourceSpans batch."""
    return {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "warden"}},
            ]},
            "scopeSpans": [{
                "scope": {"name": "brig.warden"},
                "spans": spans,
            }],
        }],
    }


def _span(span_id, name, parent="", trace="abc123",
          start=1000, end=2000, attrs=None, status=0):
    return {
        "traceId": trace,
        "spanId": span_id,
        "parentSpanId": parent,
        "name": name,
        "startTimeUnixNano": start,
        "endTimeUnixNano": end,
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)}}
            for k, v in (attrs or {}).items()
        ],
        "status": {"code": status},
    }


class TestParseSpans(unittest.TestCase):
    def test_flattens_nested_otlp(self):
        from brig.observability.traces import parse_spans
        body = json.dumps(_otlp_batch([
            _span("s1", "request", attrs={"cell": "alice"}),
            _span("s2", "policy_check", parent="s1", attrs={"cell": "alice"}),
        ]))
        spans = parse_spans(body)
        self.assertEqual(len(spans), 2)
        self.assertEqual({s.name for s in spans}, {"request", "policy_check"})
        self.assertEqual(spans[0].cell, "alice")

    def test_multiple_batches_one_per_line(self):
        from brig.observability.traces import parse_spans
        body = "\n".join([
            json.dumps(_otlp_batch([_span("s1", "request", trace="t1")])),
            json.dumps(_otlp_batch([_span("s2", "request", trace="t2")])),
        ])
        spans = parse_spans(body)
        self.assertEqual({s.trace_id for s in spans}, {"t1", "t2"})

    def test_malformed_line_skipped(self):
        from brig.observability.traces import parse_spans
        body = "not json\n" + json.dumps(_otlp_batch([_span("s1", "ok")]))
        spans = parse_spans(body)
        self.assertEqual(len(spans), 1)

    def test_duration_ms_computed(self):
        from brig.observability.traces import parse_spans
        body = json.dumps(_otlp_batch([
            _span("s1", "request", start=1_000_000, end=1_500_000),
        ]))
        spans = parse_spans(body)
        self.assertAlmostEqual(spans[0].duration_ms, 0.5)


class TestRender(unittest.TestCase):
    def test_no_spans(self):
        from brig.observability.traces import render_trace
        self.assertIn("no spans", render_trace([]))

    def test_tree_indents_children(self):
        from brig.observability.traces import parse_spans, render_trace
        body = json.dumps(_otlp_batch([
            _span("root", "request"),
            _span("child", "policy_check", parent="root"),
            _span("grandchild", "rule_match", parent="child"),
        ]))
        spans = parse_spans(body)
        out = render_trace(spans)
        # child indented under root; grandchild deeper still.
        self.assertIn("request", out)
        self.assertIn("policy_check", out)
        self.assertIn("rule_match", out)
        idx_req = out.index("request")
        idx_pol = out.index("policy_check")
        idx_rm = out.index("rule_match")
        self.assertLess(idx_req, idx_pol)
        self.assertLess(idx_pol, idx_rm)

    def test_error_status_marker(self):
        from brig.observability.traces import parse_spans, render_trace
        body = json.dumps(_otlp_batch([
            _span("s1", "request", status=2),
        ]))
        out = render_trace(parse_spans(body))
        self.assertIn("[error]", out)


class TestCmdTrace(unittest.TestCase):
    def _args(self, trace_id):
        return types.SimpleNamespace(trace_id=trace_id)

    def test_exact_match(self):
        from brig.observability.traces import cmd_trace
        body = json.dumps(_otlp_batch([
            _span("s1", "request", trace="exact-id-xyz"),
        ]))
        with patch("brig.observability.traces.vm_run",
                   return_value=MagicMock(returncode=0, stdout=body)):
            captured = []
            with patch("brig.observability.traces.output",
                       side_effect=captured.append):
                rc = cmd_trace(self._args("exact-id-xyz"))
        self.assertEqual(rc, 0)
        self.assertIn("exact-id-xyz", "\n".join(captured))

    def test_prefix_match(self):
        from brig.observability.traces import cmd_trace
        body = json.dumps(_otlp_batch([
            _span("s1", "request", trace="abcdef1234567890"),
        ]))
        with patch("brig.observability.traces.vm_run",
                   return_value=MagicMock(returncode=0, stdout=body)):
            captured = []
            with patch("brig.observability.traces.output",
                       side_effect=captured.append):
                rc = cmd_trace(self._args("abcdef"))
        self.assertEqual(rc, 0)

    def test_no_match_returns_1(self):
        from brig.observability.traces import cmd_trace
        body = json.dumps(_otlp_batch([_span("s1", "request", trace="aaa")]))
        with patch("brig.observability.traces.vm_run",
                   return_value=MagicMock(returncode=0, stdout=body)):
            with patch("brig.observability.traces.output"):
                rc = cmd_trace(self._args("zzz"))
        self.assertEqual(rc, 1)

    def test_collector_unreachable_raises(self):
        from brig.observability.traces import cmd_trace
        from brig.errors import BrigError
        with patch("brig.observability.traces.vm_run",
                   return_value=MagicMock(returncode=1, stdout="")):
            with self.assertRaises(BrigError):
                cmd_trace(self._args("any"))


if __name__ == "__main__":
    unittest.main()
