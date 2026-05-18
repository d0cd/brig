"""Cell metadata file — `/run/brig/cell.json` (downward API).

A cell at startup needs to know its own identity to drive use cases
like agent-delegation flows: the cell hands its `workspace.host_path`
to a host-side worker that needs to open the same files the cell sees.

Modeled on Kubernetes' downward API / cloud instance metadata: brig
writes a small JSON file on the host, podman bind-mounts it read-only
into the cell at `/run/brig/cell.json`. The cell can read but not
modify it.

Schema (v1):
    {
      "version": 1,
      "name": "<cell-name>",
      "started_at": "<RFC 3339 UTC>",
      "workspace": {
        "mount_point": "/work",
        "host_path":   "/Users/<user>/.brig/state/<name>/workspace"
      },
      "policy": {
        "host_services": ["<svc-name>", ...]   // per-cell ACL (may be empty)
      }
    }

Security note: `workspace.host_path` is published to the cell so it can
hand the path to a host-side consumer. The path is derivable from the
cell name + the brig install convention, so this leaks little.
Consumers that *read* the workspace on the host MUST use the race-free
`brig.workspace.validation.safe_open` primitive. The mount itself is
not yet `nosymfollow`-protected (podman 4.x limitation; tracked in
ROADMAP).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from brig.config import HostPaths, VMPaths
from brig.ops.atomic import atomic_write_json
from brig.policy.policy import load_cell_policy

SCHEMA_VERSION = 1
IN_CELL_PATH = "/run/brig/cell.json"


def _host_metadata_path(cell_name: str) -> Path:
    """Where brig writes the metadata file on the host. The cell sees this
    bind-mounted read-only at IN_CELL_PATH."""
    return HostPaths.STATE_DIR / cell_name / "cell-metadata.json"


def _vm_metadata_path(cell_name: str) -> Path:
    """The same file inside the Lima VM (after the /state virtiofs mount).
    Used by podman as the source side of the bind mount."""
    return VMPaths.STATE_DIR / cell_name / "cell-metadata.json"


def _host_workspace_path(cell_name: str) -> str:
    """Absolute host path of the per-cell workspace, expanded for the
    current user. This is what `workspace.host_path` publishes."""
    return str((HostPaths.STATE_DIR / cell_name / "workspace").expanduser())


def build_metadata(
    cell_name: str,
    workspace_mount: str,
    started_at: datetime | None = None,
) -> dict[str, Any]:
    """Compose the cell metadata payload. Pure function for testability."""
    ts = started_at or datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "version": SCHEMA_VERSION,
        "name": cell_name,
        "started_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": {
            "mount_point": workspace_mount,
            "host_path": _host_workspace_path(cell_name),
        },
        "policy": {
            "host_services": _per_cell_host_services(cell_name),
        },
    }
    return payload


def _per_cell_host_services(cell_name: str) -> list[str]:
    """Read the cell's per-cell policy and return its host_services ACL.

    Returns an empty list if no per-cell policy exists (the default —
    cells have no host-service access until granted).
    """
    policy = load_cell_policy(cell_name)
    if not policy:
        return []
    services = policy.get("host_services", [])
    # The per-cell shape stores bare names (strings). Defensively filter to
    # strings only in case someone hand-edited the file with the global
    # shape (dicts with name+port).
    return [s for s in services if isinstance(s, str)]


def write_metadata(cell_name: str, workspace_mount: str) -> Path:
    """Write the cell's metadata JSON to the host path. Returns the path.

    Called from reconciler.PODMAN_RUN before launching the cell, so the
    file is in place when podman creates the bind mount.

    Mode 0o644: world-readable inside the cell so any uid the container
    runs as can read it. The mode is set on the open fd before the
    atomic rename (audit L3) — previously chmod-after-rename inside a
    `try: ... except OSError: pass` could silently leave the file at
    mkstemp's default 0600 and the cell couldn't read its own metadata.
    """
    payload = build_metadata(cell_name, workspace_mount)
    target = _host_metadata_path(cell_name)
    atomic_write_json(target, payload, mode=0o644)
    return target


def vm_source_path(cell_name: str) -> str:
    """Source path for the podman bind mount (VM-internal)."""
    return str(_vm_metadata_path(cell_name))
