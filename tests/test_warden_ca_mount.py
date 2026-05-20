"""Auto-mount of Warden's MITM CA into cells (aitelier wishlist #1).

Surfaces:
  - default_env adds SSL_CERT_FILE et al. only when the cell didn't set them
  - trust_warden_ca: false opts out
  - Airgapped cells skip the mount
  - build_run_command produces the right --volume and -e args
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from brig.cell.ca_bundle import IN_CELL_PATH, default_env, vm_bundle_path
from brig.cell.reconciler import build_run_command
from brig.cell.spec import CellSpec


class TestDefaultEnv(unittest.TestCase):
    def test_sets_all_four_when_cell_set_none(self):
        env = default_env([])
        joined = ",".join(env)
        for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                    "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            self.assertIn(var, joined)
        self.assertTrue(all(IN_CELL_PATH in e for e in env))

    def test_skips_vars_cell_already_set(self):
        """Cell image / yaml wins. Setting SSL_CERT_FILE means we don't
        clobber — surprising override is the worst outcome."""
        env = default_env(["SSL_CERT_FILE=/etc/custom.pem", "FOO=bar"])
        self.assertFalse(any(e.startswith("SSL_CERT_FILE=") for e in env))
        # The other three still get set.
        self.assertTrue(any(e.startswith("REQUESTS_CA_BUNDLE=") for e in env))

    def test_skips_all_when_cell_set_all(self):
        env = default_env([
            "SSL_CERT_FILE=/a", "REQUESTS_CA_BUNDLE=/b",
            "CURL_CA_BUNDLE=/c", "NODE_EXTRA_CA_CERTS=/d",
        ])
        self.assertEqual(env, [])


class TestBuildRunCommandCAMount(unittest.TestCase):
    def test_default_cell_gets_ca_mount_and_env(self):
        spec = CellSpec(name="alice", image="alpine", command=["echo", "hi"])
        cmd = " ".join(build_run_command(spec, proxy_ip="10.60.1.1"))
        self.assertIn(f"{vm_bundle_path('alice')}:{IN_CELL_PATH}:ro", cmd)
        self.assertIn(f"SSL_CERT_FILE={IN_CELL_PATH}", cmd)

    def test_trust_false_omits_mount(self):
        spec = CellSpec(
            name="alice", image="alpine", command=["echo", "hi"],
            trust_warden_ca=False,
        )
        cmd = " ".join(build_run_command(spec, proxy_ip="10.60.1.1"))
        self.assertNotIn(IN_CELL_PATH, cmd)
        self.assertNotIn("SSL_CERT_FILE=", cmd)

    def test_airgapped_cell_omits_mount(self):
        """Airgapped cells have no egress; no CA to validate."""
        spec = CellSpec(
            name="alice", image="alpine", command=["echo", "hi"],
            network="none",
        )
        cmd = " ".join(build_run_command(spec, proxy_ip=None))
        self.assertNotIn("ca-bundle.crt", cmd)

    def test_user_env_wins_over_default(self):
        """A cell setting SSL_CERT_FILE in spec.env should not see brig
        re-set it. Both forms appear once (the user's), not twice."""
        spec = CellSpec(
            name="alice", image="alpine", command=["echo", "hi"],
            env=["SSL_CERT_FILE=/etc/mycorp/ca.pem"],
        )
        cmd_list = build_run_command(spec, proxy_ip="10.60.1.1")
        ssl_args = [c for c in cmd_list if c.startswith("SSL_CERT_FILE=")]
        self.assertEqual(ssl_args, ["SSL_CERT_FILE=/etc/mycorp/ca.pem"])


class TestStageBundleErrorPath(unittest.TestCase):
    """stage_bundle pre-checks that warden's CA file exists on the VM
    before attempting the concat. A missing CA cert means `brig system up`
    didn't run (or warden's eager-CA-gen failed at start), so we raise
    a BrigError pointing at the recovery command instead of bubbling up
    a raw shell-stderr from the concat step.

    The CA file is now read directly from a VM-side bind-mounted dir
    (see warden/proxy.py:VM_WARDEN_STATE_DIR), not via `podman exec`,
    so the prior chain of failure modes aitelier reported — sh-c
    skipping auto-sudo, lazy CA generation, root-owned tmpfs — is
    eliminated by structure, not patched."""

    def test_raises_brigerror_when_ca_file_missing(self):
        from brig.cell import ca_bundle
        from brig.errors import BrigError
        # Simulate `test -f` returning non-zero (file missing).
        missing = MagicMock(returncode=1, stderr="", stdout="")
        with patch.object(ca_bundle, "vm_run", return_value=missing):
            with self.assertRaises(BrigError) as ctx:
                ca_bundle.stage_bundle("alice")
        msg = str(ctx.exception)
        self.assertIn("Warden CA cert is missing", msg)
        self.assertIn("brig up", ctx.exception.suggestion or "")

    def test_raises_runtime_error_when_concat_fails(self):
        """If the CA file IS there but the concat step itself fails
        (disk full, perms), surface the raw stderr so operators can grep."""
        from brig.cell import ca_bundle
        # First call (test -f) succeeds; second call (sudo sh -c concat) fails.
        calls = [
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(
                returncode=1,
                stderr="mv: /state/alice/ca-bundle.crt: Read-only file system\n",
                stdout="",
            ),
        ]
        with patch.object(ca_bundle, "vm_run", side_effect=calls):
            with self.assertRaises(RuntimeError) as ctx:
                ca_bundle.stage_bundle("alice")
        self.assertIn("Failed to stage CA bundle", str(ctx.exception))
        self.assertIn("alice", str(ctx.exception))
        self.assertIn("Read-only file system", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
