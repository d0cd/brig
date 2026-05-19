"""host_sockets cell-yaml spec + validation.

Each entry binds a macOS-side unix socket into the cell at a path under
/run/host/. Bypasses Warden by design — validation is the entire
security boundary on the path from cell yaml to host file.

Threats the validators defend against (one test class per family):
  - Name pattern abuse (injection via name)
  - Path traversal in host_path (.. or non-absolute)
  - Symlink at host_path resolving outside intended root
  - host_path not actually a unix socket (S_ISSOCK)
  - mount_point escape (must start with /run/host/)
  - Container-engine socket denylist (docker.sock, podman.sock, ...)
  - Profile policy (untrusted profile rejects host_sockets entirely)
  - Duplicate names within one cell
  - Cap on count per cell
"""

from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path


def _base() -> dict:
    return {"name": "test-cell", "image": "alpine"}


def _sock(td: Path, name: str = "svc.sock") -> Path:
    """Create a real unix socket at td/name and return the path."""
    p = td / name
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(p))
    s.close()
    return p


class TestHostSocketAccepted(unittest.TestCase):
    """Valid declarations parse and validate without errors."""

    def test_minimal_valid_entry(self):
        from brig.cell.spec import validate_cell_definition
        with tempfile.TemporaryDirectory() as td:
            p = _sock(Path(td))
            d = {**_base(), "host_sockets": [{
                "name": "pg",
                "host_path": str(p),
                "mount_point": "/run/host/pg.sock",
            }]}
            self.assertEqual(validate_cell_definition(d), [])

    def test_mode_ro_and_rw_accepted(self):
        from brig.cell.spec import validate_cell_definition
        with tempfile.TemporaryDirectory() as td:
            p = _sock(Path(td))
            for mode in ("ro", "rw"):
                d = {**_base(), "host_sockets": [{
                    "name": "pg", "host_path": str(p),
                    "mount_point": "/run/host/pg.sock", "mode": mode,
                }]}
                self.assertEqual(validate_cell_definition(d), [], f"mode={mode}")

    def test_construction_into_cellspec(self):
        from brig.cell.spec import CellSpec
        spec = CellSpec(name="t", image="alpine", host_sockets=[
            {"name": "pg", "host_path": "/tmp/x.sock",
             "mount_point": "/run/host/pg.sock", "mode": "rw"},
        ])
        self.assertEqual(len(spec.host_sockets), 1)
        self.assertEqual(spec.host_sockets[0]["name"], "pg")


class TestHostSocketNameValidation(unittest.TestCase):
    def test_missing_name_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "host_path": "/tmp/x.sock", "mount_point": "/run/host/x.sock",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any("name" in e for e in errs), errs)

    def test_uppercase_name_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "Postgres", "host_path": "/tmp/x.sock",
            "mount_point": "/run/host/x.sock",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any("lowercase" in e or "pattern" in e for e in errs), errs)

    def test_injection_chars_rejected(self):
        from brig.cell.spec import validate_cell_definition
        for bad in ("pg;rm", "pg sock", "pg/x", "pg\nx", "pg$(x)"):
            d = {**_base(), "host_sockets": [{
                "name": bad, "host_path": "/tmp/x.sock",
                "mount_point": "/run/host/x.sock",
            }]}
            errs = validate_cell_definition(d)
            self.assertTrue(errs, f"expected rejection for name={bad!r}")

    def test_duplicate_names_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [
            {"name": "pg", "host_path": "/tmp/a.sock",
             "mount_point": "/run/host/a.sock"},
            {"name": "pg", "host_path": "/tmp/b.sock",
             "mount_point": "/run/host/b.sock"},
        ]}
        errs = validate_cell_definition(d)
        self.assertTrue(any("Duplicate" in e or "duplicate" in e for e in errs), errs)


class TestHostPathValidation(unittest.TestCase):
    def test_non_absolute_path_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "pg", "host_path": "tmp/x.sock",
            "mount_point": "/run/host/x.sock",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any("absolute" in e for e in errs), errs)

    def test_dotdot_in_host_path_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "pg", "host_path": "/tmp/../etc/passwd",
            "mount_point": "/run/host/x.sock",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any(".." in e or "traversal" in e for e in errs), errs)

    def test_engine_socket_denied(self):
        from brig.cell.spec import validate_cell_definition
        for bad in ("/var/run/docker.sock", "/run/podman.sock",
                    "/var/run/containerd.sock"):
            d = {**_base(), "host_sockets": [{
                "name": "x", "host_path": bad,
                "mount_point": "/run/host/x.sock",
            }]}
            errs = validate_cell_definition(d)
            self.assertTrue(
                any("engine" in e.lower() for e in errs),
                f"engine-socket {bad!r} not denied: {errs}",
            )


class TestMountPointValidation(unittest.TestCase):
    def test_must_start_with_run_host(self):
        from brig.cell.spec import validate_cell_definition
        for bad in ("/etc/passwd.sock", "/run/passwd.sock",
                    "/tmp/x.sock", "/work/x.sock"):
            d = {**_base(), "host_sockets": [{
                "name": "x", "host_path": "/tmp/x.sock",
                "mount_point": bad,
            }]}
            errs = validate_cell_definition(d)
            self.assertTrue(
                any("/run/host/" in e for e in errs),
                f"mount_point {bad!r} accepted: {errs}",
            )

    def test_dotdot_in_mount_point_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "x", "host_path": "/tmp/x.sock",
            "mount_point": "/run/host/../etc/passwd",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any(".." in e or "traversal" in e for e in errs), errs)

    def test_root_mount_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "x", "host_path": "/tmp/x.sock",
            "mount_point": "/",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(errs)


class TestModeValidation(unittest.TestCase):
    def test_unknown_mode_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": [{
            "name": "x", "host_path": "/tmp/x.sock",
            "mount_point": "/run/host/x.sock", "mode": "exec",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(any("mode" in e for e in errs), errs)


class TestCountLimit(unittest.TestCase):
    def test_too_many_rejected(self):
        from brig.cell.spec import validate_cell_definition
        entries = [
            {"name": f"s{i}", "host_path": f"/tmp/s{i}.sock",
             "mount_point": f"/run/host/s{i}.sock"}
            for i in range(20)
        ]
        d = {**_base(), "host_sockets": entries}
        errs = validate_cell_definition(d)
        self.assertTrue(any("Too many" in e or "max" in e for e in errs), errs)


class TestUntrustedProfileRejection(unittest.TestCase):
    """The untrusted profile must not be allowed to declare host_sockets —
    that's the whole point of the profile."""

    def test_untrusted_profile_with_host_sockets_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "profile": "untrusted", "host_sockets": [{
            "name": "pg", "host_path": "/tmp/x.sock",
            "mount_point": "/run/host/pg.sock",
        }]}
        errs = validate_cell_definition(d)
        self.assertTrue(
            any("untrusted" in e.lower() for e in errs),
            f"untrusted profile + host_sockets not rejected: {errs}",
        )

    def test_supervised_profile_with_host_sockets_ok(self):
        from brig.cell.spec import validate_cell_definition
        with tempfile.TemporaryDirectory() as td:
            p = _sock(Path(td))
            d = {**_base(), "profile": "supervised", "host_sockets": [{
                "name": "pg", "host_path": str(p),
                "mount_point": "/run/host/pg.sock",
            }]}
            errs = validate_cell_definition(d)
            self.assertEqual(errs, [])


class TestNotAListRejected(unittest.TestCase):
    def test_string_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": "postgres"}
        errs = validate_cell_definition(d)
        self.assertTrue(errs)

    def test_dict_rejected(self):
        from brig.cell.spec import validate_cell_definition
        d = {**_base(), "host_sockets": {"name": "pg"}}
        errs = validate_cell_definition(d)
        self.assertTrue(errs)


if __name__ == "__main__":
    unittest.main()
