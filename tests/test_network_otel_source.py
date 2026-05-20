"""`brig cell network --otel` reads from the collector's logs file
and emits the same line shape as the JSONL path.
"""

from __future__ import annotations

import json
import types
import unittest
from unittest.mock import MagicMock, patch


def _otlp_log_batch(records):
    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "warden"}},
            ]},
            "scopeLogs": [{
                "scope": {"name": "brig.warden"},
                "logRecords": records,
            }],
        }],
    }


def _rec(cell, method="GET", host="api.x", path="/v1/models",
         status=200, decision="allowed", reason="", ingress_route=""):
    attrs = {
        "cell": cell, "method": method, "host": host, "path": path,
        "status": status, "decision": decision, "block_reason": reason,
        "ingress_route": ingress_route,
    }
    return {
        "observedTimeUnixNano": "1779242000000000000",
        "severityText": "WARN" if decision == "blocked" else "INFO",
        "body": {"stringValue": f"{method} {host}{path}"},
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)} if isinstance(v, str)
             else {"intValue": v}}
            for k, v in attrs.items()
        ],
    }


def _args(name, blocked=False, tail=20, otel=True):
    return types.SimpleNamespace(
        name=name, blocked=blocked, tail=tail, otel=otel,
    )


class TestOtelSource(unittest.TestCase):
    def _run(self, body, **kw):
        from brig.commands.network_cmd import cmd_network
        captured: list[str] = []
        with patch("brig.commands.network_cmd.vm_run",
                   return_value=MagicMock(returncode=0, stdout=body)), \
             patch("brig.commands.network_cmd.output",
                   side_effect=captured.append):
            cmd_network(_args(**kw))
        return captured

    def test_filters_by_cell(self):
        body = json.dumps(_otlp_log_batch([
            _rec("alice"),
            _rec("bob"),
            _rec("alice", host="api.y"),
        ]))
        lines = self._run(body, name="alice")
        joined = "\n".join(lines)
        self.assertIn("api.x", joined)
        self.assertIn("api.y", joined)
        self.assertNotIn("bob", joined)

    def test_blocked_filter(self):
        body = json.dumps(_otlp_log_batch([
            _rec("alice"),
            _rec("alice", decision="blocked", reason="cell policy: denied"),
        ]))
        lines = self._run(body, name="alice", blocked=True)
        joined = "\n".join(lines)
        # Only the blocked one survives. The formatter still tags egress
        # as "OUT:" but with " [BLOCKED]" appended — one line total.
        self.assertIn("[BLOCKED]", joined)
        self.assertEqual(joined.count("OUT:"), 1)
        self.assertIn("cell policy: denied", joined)

    def test_ingress_tagged(self):
        body = json.dumps(_otlp_log_batch([
            _rec("alice", ingress_route="api"),
        ]))
        lines = self._run(body, name="alice")
        self.assertIn("INGRESS:", "\n".join(lines))
        self.assertIn("route=api", "\n".join(lines))

    def test_no_collector_data(self):
        from brig.commands.network_cmd import cmd_network
        captured: list[str] = []
        with patch("brig.commands.network_cmd.vm_run",
                   return_value=MagicMock(returncode=1, stdout="")), \
             patch("brig.commands.network_cmd.output",
                   side_effect=captured.append):
            cmd_network(_args(name="alice"))
        self.assertIn("No collector logs", "\n".join(captured))


if __name__ == "__main__":
    unittest.main()
