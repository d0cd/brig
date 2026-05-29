"""`brig cell export` emits a self-contained yaml: spec from podman
inspect plus per-cell policy (allow/deny/host_services), ingress
routes, and host_sockets. `brig run --file <output>` reproduces the
cell.
"""

from __future__ import annotations

import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


def _args(name="alice"):
    return types.SimpleNamespace(name=name)


class TestExportResolved(unittest.TestCase):
    def _inspect(self, image="alpine"):
        return {
            "Config": {"Image": image, "Cmd": ["sh"], "Env": []},
            "HostConfig": {"Memory": 2 * 1024**3, "NanoCpus": 1_000_000_000,
                           "PidsLimit": 256},
        }

    def _captured_output(self, args, inspect_data, cell_policy=None,
                         ingress_routes=None, host_sockets=None):
        from brig.commands.lifecycle_cmd import cmd_export
        lines: list[str] = []
        result = MagicMock(returncode=0, stdout=json.dumps(inspect_data))
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            routes_file = td / "routes.json"
            if ingress_routes is not None:
                routes_file.write_text(json.dumps({"routes": ingress_routes}))
            meta_file = td / "alice-meta.json"
            if host_sockets is not None:
                meta_file.write_text(json.dumps({"host_sockets": host_sockets}))
            policies_dir = td / "policies"
            policies_dir.mkdir()
            if cell_policy is not None:
                (policies_dir / "alice.json").write_text(json.dumps(cell_policy))
            with patch("brig.commands.lifecycle_cmd.vm_run", return_value=result), \
                 patch("brig.commands.lifecycle_cmd.output",
                       side_effect=lines.append), \
                 patch("brig.config.HostPaths.INGRESS_ROUTES_FILE", routes_file), \
                 patch("brig.cell.metadata._host_metadata_path",
                       return_value=meta_file), \
                 patch("brig.policy.policy.get_cell_policy_path",
                       side_effect=lambda n, *a, **kw: policies_dir / f"{n}.json"):
                cmd_export(args)
        return "\n".join(lines)

    def test_minimal_emits_image_and_resources(self):
        text = self._captured_output(_args(), self._inspect())
        # Strings are JSON-quoted in output for yaml-safety.
        self.assertIn('name: "alice"', text)
        self.assertIn('image: "alpine"', text)
        self.assertIn('memory: "2g"', text)

    def test_includes_allow_and_deny(self):
        text = self._captured_output(_args(), self._inspect(), cell_policy={
            "allow": ["api.github.com"], "deny": ["evil.com"],
        })
        self.assertIn("policy:", text)
        self.assertIn("api.github.com", text)
        self.assertIn("evil.com", text)

    def test_includes_host_services(self):
        text = self._captured_output(_args(), self._inspect(), cell_policy={
            "allow": [], "deny": [],
            "host_services": [{"name": "db", "port": 5432}],
        })
        self.assertIn("host_services:", text)
        self.assertIn('"db"', text)
        self.assertIn("5432", text)

    def test_includes_ingress_routes(self):
        text = self._captured_output(_args(), self._inspect(),
            ingress_routes=[
                {"cell": "alice", "name": "api", "port": 8080,
                 "path_prefix": "/api"},
                {"cell": "other", "name": "x", "port": 1, "path_prefix": "/"},
            ],
        )
        self.assertIn("ingress:", text)
        self.assertIn('"api"', text)
        self.assertNotIn("port: 1\n", text)  # other cell's route not included

    def test_includes_host_sockets_without_host_path(self):
        text = self._captured_output(_args(), self._inspect(),
            host_sockets=[
                {"name": "pg", "mount_point": "/run/host/pg.sock",
                 "host_path": "/tmp/SHOULD-NOT-LEAK.sock"},
            ],
        )
        self.assertIn("host_sockets:", text)
        self.assertIn("/run/host/pg.sock", text)
        self.assertNotIn("SHOULD-NOT-LEAK", text)

    def test_export_wildcard_round_trips(self):
        """Regression: bare `*.example.com` would emit unquoted and
        pyyaml would parse it as an alias. JSON-quoted strings keep
        round-trip working."""
        text = self._captured_output(_args(), self._inspect(), cell_policy={
            "allow": ["*.example.com", "api.x"], "deny": [],
        })
        # Each wildcard must be quoted in the output.
        self.assertIn('"*.example.com"', text)
        # And the resulting yaml block must parse cleanly.
        try:
            import yaml
            yaml.safe_load(text)
        except (ImportError, ModuleNotFoundError):
            self.skipTest("pyyaml not installed")
        except Exception as e:
            self.fail(f"emitted yaml does not parse: {e}\n{text}")


if __name__ == "__main__":
    unittest.main()
