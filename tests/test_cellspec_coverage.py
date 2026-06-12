"""Guardrail against the "feature half-wired" bug class.

Adding a CellSpec field means touching several surfaces (validator, reconciler,
SDK, export, metadata, docs). These introspection tests fail when a new field
is added without a conscious decision about the SDK and export surfaces — so a
field can't be silently unreachable from the SDK or silently dropped by export.
"""

import dataclasses
import inspect
import unittest

from brig.cell.spec import CellSpec
from brig.sdk import Brig

_FIELDS = {f.name for f in dataclasses.fields(CellSpec)}


class TestSdkReachability(unittest.TestCase):
    """Every CellSpec field is settable via the SDK, or explicitly exempt."""

    # Fields intentionally NOT exposed as SDK params, with the reason.
    _EXEMPT = {
        "rm",  # podman --rm auto-removes on exit; the SDK returns a managed
               # Cell handle (detach defaults True), so auto-remove is out of band.
    }

    def test_every_field_reachable_or_exempt(self):
        params = set(inspect.signature(Brig.run_sync).parameters) - {"self"}
        missing = _FIELDS - params - self._EXEMPT
        self.assertEqual(
            missing, set(),
            f"CellSpec fields not reachable via Brig.run_sync (add a param or "
            f"document in _EXEMPT): {sorted(missing)}",
        )

    def test_run_matches_run_sync(self):
        # run() must forward the same surface as run_sync(), or they drift.
        run = set(inspect.signature(Brig.run).parameters) - {"self"}
        run_sync = set(inspect.signature(Brig.run_sync).parameters) - {"self"}
        self.assertEqual(run, run_sync,
                         f"run/run_sync param drift: {run ^ run_sync}")


class TestExportClassified(unittest.TestCase):
    """Every CellSpec field is classified for `brig cell export`, so a new field
    can't be silently un-round-trippable."""

    # Emitted by cmd_export (reconstructed from `podman inspect`).
    _EXPORTED = {
        "name", "image", "command", "env", "memory", "cpus", "pids_limit",
        "ingress", "host_services", "host_sockets", "mounts", "restart", "user",
        "policy_allow", "policy_deny", "policy_passthrough_tls",
    }
    # Intentionally not exported.
    _NOT_EXPORTED_BY_DESIGN = {
        "secrets",   # secret VALUES never leave ~/.brig/secrets; re-add by name
        "detach", "rm",  # run-time lifecycle flags, not cell identity
        "profile",   # flattened into concrete fields at run; not one inspect field
    }
    # Recoverable from `podman inspect` but not yet emitted — a known lossy gap
    # in cmd_export, tracked here rather than left invisible.
    _NOT_EXPORTED_GAP = {
        "image_digest", "labels", "network", "timeout", "workdir",
        "workspace_mount", "workspace_quota", "writable_rootfs",
        "trust_warden_ca", "seccomp_profile",
    }

    def test_every_field_classified(self):
        classified = (
            self._EXPORTED | self._NOT_EXPORTED_BY_DESIGN | self._NOT_EXPORTED_GAP
        )
        self.assertEqual(
            classified, _FIELDS,
            f"unclassified CellSpec fields for export "
            f"(classify in test_cellspec_coverage): {sorted(_FIELDS ^ classified)}",
        )


if __name__ == "__main__":
    unittest.main()
