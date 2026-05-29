"""`brig system doctor` verifies each cell's staged ca-bundle.crt
matches the current Warden CA. Aitelier diagnosed the foot-gun: a cell
entrypoint that ALSO sets SSL_CERT_FILE clobbers brig's auto-mount;
on the next warden restart, mitmproxy rotates its CA, brig re-stages,
but the cell-cached bundle goes stale → silent TLS hangs.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestDoctorCaConsistency(unittest.TestCase):
    def _calls(self, state_dir, vm_run_result):
        from brig.commands.system_cmd import _check_warden_ca_consistency
        calls = []
        def check(label, ok, **kw): calls.append((label, ok))
        with patch("brig.commands.system_cmd.vm_run", return_value=vm_run_result), \
             patch("brig.config.HostPaths.STATE_DIR", state_dir):
            _check_warden_ca_consistency(check)
        return calls

    def test_no_warden_ca_silently_skips(self):
        """vm_run returning non-zero means warden hasn't started yet;
        the 'warden running' doctor check handles that separately."""
        with tempfile.TemporaryDirectory() as td:
            calls = self._calls(
                Path(td),
                subprocess.CompletedProcess([], 1, "", "no such file"),
            )
        self.assertEqual(calls, [])

    def test_empty_warden_ca_silently_skips(self):
        """A degenerate case (warden running but cert empty) shouldn't
        emit a false [OK] — skip entirely until the cert is populated."""
        with tempfile.TemporaryDirectory() as td:
            calls = self._calls(
                Path(td),
                subprocess.CompletedProcess([], 0, "   ", ""),
            )
        self.assertEqual(calls, [])

    def test_matching_bundle_passes(self):
        # Use a realistic PEM block — proves substring containment
        # works against PEM-headered certs (the production shape),
        # not just bare placeholders.
        ca = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBkTCB+wIJAKzWFwzG2c1FMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMM\n"
            "CXdhcmRlbi1jYTAeFw0yNjA1MjAwMDAwMDBaFw0zNjA1MjAwMDAwMDBaMBQx\n"
            "EjAQBgNVBAMMCXdhcmRlbi1jYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC9\n"
            "WARDEN_TEST_CERT_NOT_REAL_KEY_MATERIAL_FOR_TESTS_ONLY_xxxxxx\n"
            "-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / "alice").mkdir()
            (state / "alice" / "ca-bundle.crt").write_text(
                "<system roots>\n" + ca + "\n"
            )
            calls = self._calls(
                state,
                subprocess.CompletedProcess([], 0, ca, ""),
            )
        self.assertEqual(len(calls), 1)
        label, ok = calls[0]
        self.assertIn("alice", label)
        self.assertTrue(ok)

    def test_stale_bundle_fails(self):
        """A cell whose staged bundle was last written against a prior
        Warden CA reports FAIL with a `brig cell restart` suggestion."""
        current_ca = (
            "-----BEGIN CERTIFICATE-----\n"
            "NEW_CA_TEST_FINGERPRINT_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "-----END CERTIFICATE-----\n"
        )
        old_ca = (
            "-----BEGIN CERTIFICATE-----\n"
            "OLD_CA_TEST_FINGERPRINT_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
            "-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / "alice").mkdir()
            (state / "alice" / "ca-bundle.crt").write_text(
                "<system roots>\n" + old_ca + "\n"
            )
            calls = self._calls(
                state,
                subprocess.CompletedProcess([], 0, current_ca, ""),
            )
        self.assertEqual(len(calls), 1)
        label, ok = calls[0]
        self.assertFalse(ok)

    def test_system_dir_skipped(self):
        """`~/.brig/state/system/` is brig's coordination dir, not a
        cell — must not appear in the check output."""
        ca = "WARDEN_CA"
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / "system").mkdir()
            calls = self._calls(
                state,
                subprocess.CompletedProcess([], 0, ca, ""),
            )
        self.assertEqual(calls, [])

    def test_cell_without_staged_bundle_skipped(self):
        """A cell that opted out (trust_warden_ca: false) has no
        ca-bundle.crt — silently skip, not [FAIL]."""
        ca = "WARDEN_CA"
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / "opted-out").mkdir()
            calls = self._calls(
                state,
                subprocess.CompletedProcess([], 0, ca, ""),
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
