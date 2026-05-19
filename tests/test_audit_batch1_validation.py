"""Audit fixes (batch 1) — validation gaps in host_sockets.

C1 — SDK invokes validate_cell_definition
C2 — untrusted profile check looks at content, not just name
H1 — cell names with '.' rejected when host_sockets are declared
M2 — engine denylist re-applied after realpath in the bridge
M3 — mount_point normalized before duplicate check
"""

from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _real_socket(td: Path, name: str) -> Path:
    p = td / name
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(p))
    s.close()
    return p


# ----- C1: SDK validation -----

class TestSDKValidation(unittest.TestCase):
    def test_sdk_rejects_engine_socket(self):
        from brig.sdk import Brig
        from brig.errors import BrigError
        with self.assertRaises(BrigError) as ctx:
            Brig().run_sync(
                name="alice", image="alpine",
                host_sockets=[{
                    "name": "x",
                    "host_path": "/var/run/docker.sock",
                    "mount_point": "/run/host/x.sock",
                }],
            )
        self.assertIn("engine", str(ctx.exception).lower())

    def test_sdk_rejects_path_traversal(self):
        from brig.sdk import Brig
        from brig.errors import BrigError
        with self.assertRaises(BrigError):
            Brig().run_sync(
                name="alice", image="alpine",
                host_sockets=[{
                    "name": "x",
                    "host_path": "/tmp/../etc/passwd",
                    "mount_point": "/run/host/x.sock",
                }],
            )

    def test_sdk_rejects_bad_mount_point(self):
        from brig.sdk import Brig
        from brig.errors import BrigError
        with self.assertRaises(BrigError):
            Brig().run_sync(
                name="alice", image="alpine",
                host_sockets=[{
                    "name": "x",
                    "host_path": "/tmp/x.sock",
                    "mount_point": "/etc/passwd",
                }],
            )


# ----- C2: profile-content check -----

class TestProfileContentCheck(unittest.TestCase):
    def test_user_profile_named_untrusted_still_rejected(self):
        """User profile file shadowing the builtin 'untrusted' name
        must still trigger rejection — defense doesn't rely on the
        name string being unique to the builtin."""
        from brig.cell.spec import validate_cell_definition
        with tempfile.TemporaryDirectory() as td:
            profiles_dir = Path(td)
            # Shadow builtin with a "relaxed" untrusted profile.
            (profiles_dir / "untrusted.yaml").write_text(
                "memory: 8g\ncpus: '8'\nlabels:\n"
                "  brig.profile: relaxed\n"  # different label!
            )
            with patch("brig.cell.profiles.PROFILES_DIR", profiles_dir):
                errs = validate_cell_definition({
                    "name": "alice", "image": "alpine",
                    "profile": "untrusted",
                    "host_sockets": [{
                        "name": "x", "host_path": "/tmp/x.sock",
                        "mount_point": "/run/host/x.sock",
                    }],
                })
        # Name string matches → still rejected.
        self.assertTrue(any("untrusted" in e.lower() for e in errs))

    def test_profile_labelled_untrusted_rejected_even_with_other_name(self):
        """A user profile under a different name but labelled as
        untrusted should also be rejected — the label is the signal."""
        from brig.cell.spec import validate_cell_definition
        # PROFILES_DIR is captured as a default arg at import time, so
        # patch load_profile directly to return our content.
        with patch("brig.cell.profiles.load_profile",
                   return_value={"labels": {"brig.profile": "untrusted"}}):
            errs = validate_cell_definition({
                "name": "alice", "image": "alpine",
                "profile": "myrole",
                "host_sockets": [{
                    "name": "x", "host_path": "/tmp/x.sock",
                    "mount_point": "/run/host/x.sock",
                }],
            })
        self.assertTrue(any("untrusted" in e.lower() for e in errs))

    def test_supervised_profile_unaffected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "profile": "supervised",
            "host_sockets": [{
                "name": "x", "host_path": "/tmp/x.sock",
                "mount_point": "/run/host/x.sock",
            }],
        })
        self.assertEqual(errs, [])


# ----- H1: cell name with dot -----

class TestCellNameDotRejection(unittest.TestCase):
    def test_dotted_name_with_host_sockets_rejected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "my.cell",  # CELL_NAME_PATTERN allows this
            "image": "alpine",
            "host_sockets": [{
                "name": "pg", "host_path": "/tmp/x.sock",
                "mount_point": "/run/host/pg.sock",
            }],
        })
        self.assertTrue(any("." in e and "host_sockets" in e for e in errs), errs)

    def test_dotted_name_without_host_sockets_ok(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "my.cell", "image": "alpine",
        })
        self.assertEqual(errs, [])


# ----- M2: engine denylist after realpath -----

class TestEngineDenylistAfterRealpath(unittest.TestCase):
    def test_symlink_to_docker_sock_blocked(self):
        """Symlink at /tmp/pg.sock → /var/run/docker.sock must be
        rejected even though basename is 'pg.sock' (not on denylist)."""
        from brig.cell.host_sockets_bridge import _validate_target
        from brig.errors import BrigError
        with tempfile.TemporaryDirectory() as td:
            # Use a fake "docker.sock" target so we don't depend on
            # /var/run/docker.sock existing. Realpath only cares about
            # the resolved basename matching the denylist.
            fake_docker = Path(td) / "docker.sock"
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(fake_docker))
            s.close()
            link = Path(td) / "pg.sock"
            os.symlink(fake_docker, link)
            with self.assertRaises(BrigError) as ctx:
                _validate_target(str(link))
        self.assertIn("engine", str(ctx.exception).lower())


# ----- M3: mount_point normalization -----

class TestMountPointNormalization(unittest.TestCase):
    def test_double_slash_caught_as_duplicate(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "host_sockets": [
                {"name": "a", "host_path": "/tmp/a.sock",
                 "mount_point": "/run/host/x.sock"},
                {"name": "b", "host_path": "/tmp/b.sock",
                 "mount_point": "/run/host//x.sock"},
            ],
        })
        self.assertTrue(any("Duplicate" in e or "duplicate" in e for e in errs), errs)

    def test_dot_segment_caught_as_duplicate(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "host_sockets": [
                {"name": "a", "host_path": "/tmp/a.sock",
                 "mount_point": "/run/host/x.sock"},
                {"name": "b", "host_path": "/tmp/b.sock",
                 "mount_point": "/run/host/./x.sock"},
            ],
        })
        self.assertTrue(any("Duplicate" in e or "duplicate" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
