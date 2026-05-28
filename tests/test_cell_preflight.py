"""`brig cell preflight <yaml>` reads a cell yaml and verifies every
host-side requirement it implies. No mutations; fails (exit 1) with a
checklist if any requirement is missing.
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from conftest import make_unix_socket as _real_socket


def _args(file):
    return types.SimpleNamespace(file=file)


def _write_yaml(p: Path, body: str) -> Path:
    yaml_path = p / "cell.yaml"
    yaml_path.write_text(body)
    return yaml_path


class TestPreflight(unittest.TestCase):
    def test_valid_minimal_passes(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            yaml = _write_yaml(Path(td), "name: hello\nimage: alpine\n")
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 0)

    def test_missing_secret_fails(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            yaml = _write_yaml(Path(td),
                "name: hello\nimage: alpine\nsecrets:\n  - api-key\n")
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 1)

    def test_present_secret_passes(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "api-key").write_text("secret")
            yaml = _write_yaml(Path(td),
                "name: hello\nimage: alpine\nsecrets:\n  - api-key\n")
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 0)

    def test_ingress_without_token_fails(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            yaml = _write_yaml(Path(td),
                "name: hello\nimage: alpine\n"
                "ingress:\n  - name: api\n    port: 8080\n"
                "    path_prefix: /api\n    auth: token\n")
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 1)

    def test_host_socket_target_missing_fails(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            yaml = _write_yaml(Path(td),
                "name: hello\nimage: alpine\n"
                "host_sockets:\n  - name: pg\n"
                "    host_path: /tmp/no-such-zzz.sock\n"
                "    mount_point: /run/host/pg.sock\n")
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 1)

    def test_host_socket_target_present_passes(self):
        from brig.commands.lifecycle_cmd import cmd_preflight
        with tempfile.TemporaryDirectory() as td:
            target = _real_socket(Path(td), "pg.sock")
            yaml = _write_yaml(Path(td),
                f"name: hello\nimage: alpine\n"
                f"host_sockets:\n  - name: pg\n"
                f"    host_path: {target}\n"
                f"    mount_point: /run/host/pg.sock\n")
            # socat isn't installed on Linux CI runners; pretend it is so
            # the host_socket dependency check doesn't fail this test on
            # the missing-binary, not the path-validation logic under test.
            with patch("brig.config.HostPaths.SECRETS_DIR", Path(td)), \
                 patch("shutil.which",
                       lambda name: "/usr/bin/socat" if name == "socat" else None):
                rc = cmd_preflight(_args(str(yaml)))
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
