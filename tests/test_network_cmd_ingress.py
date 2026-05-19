"""`brig cell network` shows ingress hits tagged distinctly so the
operator can grep INGRESS: vs OUT: cleanly. Feedback #5 from aitelier.
"""

from __future__ import annotations

import json
import types
import unittest
from unittest.mock import MagicMock, patch


def _entry(**kw):
    base = {
        "ts": "2026-05-18T10:00:00Z", "method": "GET",
        "host": "api.example.com", "path": "/health", "status": 200,
        "blocked": False, "src_ip": "10.60.1.5",
    }
    base.update(kw)
    return base


class TestIngressTaggedInNetworkOutput(unittest.TestCase):
    def _run(self, entries):
        from brig.commands.network_cmd import cmd_network
        stdout_text = "\n".join(json.dumps(e) for e in entries)
        result = MagicMock(returncode=0, stdout=stdout_text)
        captured: list[str] = []
        with patch("brig.commands.network_cmd.vm_run", return_value=result), \
             patch("brig.commands.network_cmd.output",
                   side_effect=captured.append):
            cmd_network(types.SimpleNamespace(name="alice", tail=20, blocked=False))
        return "\n".join(captured)

    def test_ingress_entry_tagged_distinctly(self):
        text = self._run([_entry(
            ingress_route="api", ingress_src_ip="192.168.0.5",
        )])
        self.assertIn("INGRESS:", text)
        self.assertIn("route=api", text)
        self.assertIn("192.168.0.5", text)

    def test_egress_entry_tagged_OUT(self):
        text = self._run([_entry()])
        self.assertIn("OUT:", text)
        self.assertNotIn("INGRESS:", text)

    def test_mixed_entries(self):
        text = self._run([
            _entry(),
            _entry(ingress_route="api", ingress_src_ip="1.2.3.4"),
        ])
        self.assertIn("OUT:", text)
        self.assertIn("INGRESS:", text)


if __name__ == "__main__":
    unittest.main()
