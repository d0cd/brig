"""Profile-content untrusted check — a user profile that shadows the builtin
`untrusted` name, or is labelled `brig.profile: untrusted` under a different
name, must still trigger the untrusted-profile field rejections. The defense
keys off profile *content*, not just the name string matching the builtin.

Exercised here via `host_services` (an untrusted-gated field); the same
`_profile_is_untrusted` path gates tls_passthrough and mounts.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_SVC = [{"name": "db", "port": 5432, "protocol": "tcp"}]


class TestProfileContentCheck(unittest.TestCase):
    def test_user_profile_named_untrusted_still_rejected(self):
        """A user profile file shadowing the builtin 'untrusted' name must
        still trigger rejection — the defense doesn't rely on the name string
        being unique to the builtin."""
        from brig.cell.spec import validate_cell_definition
        with tempfile.TemporaryDirectory() as td:
            profiles_dir = Path(td)
            # Shadow builtin with a "relaxed" untrusted profile (different label).
            (profiles_dir / "untrusted.yaml").write_text(
                "memory: 8g\ncpus: '8'\nlabels:\n  brig.profile: relaxed\n"
            )
            with patch("brig.cell.profiles.PROFILES_DIR", profiles_dir):
                errs = validate_cell_definition({
                    "name": "alice", "image": "alpine",
                    "profile": "untrusted",
                    "host_services": _SVC,
                })
        # Name string matches → still rejected.
        self.assertTrue(any("untrusted" in e.lower() for e in errs))

    def test_profile_labelled_untrusted_rejected_even_with_other_name(self):
        """A user profile under a different name but labelled untrusted should
        also be rejected — the label is the signal."""
        from brig.cell.spec import validate_cell_definition
        with patch("brig.cell.profiles.load_profile",
                   return_value={"labels": {"brig.profile": "untrusted"}}):
            errs = validate_cell_definition({
                "name": "alice", "image": "alpine",
                "profile": "myrole",
                "host_services": _SVC,
            })
        self.assertTrue(any("untrusted" in e.lower() for e in errs))

    def test_supervised_profile_unaffected(self):
        from brig.cell.spec import validate_cell_definition
        errs = validate_cell_definition({
            "name": "alice", "image": "alpine",
            "profile": "supervised",
            "host_services": _SVC,
        })
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
