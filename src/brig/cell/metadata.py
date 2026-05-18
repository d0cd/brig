"""Cell metadata file — `/run/brig/cell.json` (downward API).

A cell at startup needs to know its own identity to drive use cases
like agent-delegation flows: the cell hands `(cell-name, relpath)` to
a host-side worker that needs to open the same files the cell sees,
and the worker uses one of brig's safe primitives to do the read.

Modeled on Kubernetes' downward API / cloud instance metadata: brig
writes a small JSON file on the host, podman bind-mounts it read-only
into the cell at `/run/brig/cell.json`. The cell can read but not
modify it.

Schema (v2):
    {
      "version": 2,
      "name": "<cell-name>",
      "started_at": "<RFC 3339 UTC>",
      "workspace": {
        "mount_point": "/work"
      },
      "policy": {
        "host_services": ["<svc-name>", ...]   // per-cell ACL (may be empty)
      }
    }

Why v2 dropped `workspace.host_path`: publishing the absolute host
path made it trivial for a consumer to do plain `open(host_path)`,
which follows any symlink the cell planted in its workspace — letting
the cell exfiltrate arbitrary host files by tricking the consumer
into reading. There is no mount-side fix available on macOS (no
`MS_NOSYMFOLLOW` equivalent). The principled answer is to make the
host path inaccessible from the metadata and route all host-side
workspace reads through brig's safe primitives — which derive the
path from the cell name and walk it with `O_NOFOLLOW`.

Safe consumer primitives:
  - Python in-process:  `brig.workspace.validation.safe_open(cell, relpath)`
  - Any language:       `brig cell read <cell> <relpath>` (streams to stdout)
                        `brig cell cp <cell>:<relpath> <local>`
                        `brig cell exec <cell> -- <cmd>` (runs in gVisor)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from brig.config import HostPaths, VMPaths
from brig.ops.atomic import atomic_write_json
from brig.policy.policy import load_cell_policy

SCHEMA_VERSION = 2
IN_CELL_PATH = "/run/brig/cell.json"


def _host_metadata_path(cell_name: str) -> Path:
    """Where brig writes the metadata file on the host. The cell sees this
    bind-mounted read-only at IN_CELL_PATH."""
    return HostPaths.STATE_DIR / cell_name / "cell-metadata.json"


def _vm_metadata_path(cell_name: str) -> Path:
    """The same file inside the Lima VM (after the /state virtiofs mount).
    Used by podman as the source side of the bind mount."""
    return VMPaths.STATE_DIR / cell_name / "cell-metadata.json"


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


def refresh_metadata_if_present(cell_name: str) -> Path | None:
    """Rewrite the metadata file for `cell_name` if one already exists,
    preserving the original `workspace_mount` value.

    Called after per-cell policy changes so `policy.host_services` in
    /run/brig/cell.json reflects the latest ACL. No-op if the cell has
    no metadata file (cell was never started, or was removed).

    Bind mounts are fixed at podman-create time, so the cell's running
    container can't pick up a new workspace_mount — we preserve whatever
    was originally set. The policy field is the only one that can drift
    out of sync; that's what this fixes.
    """
    import json as _json
    existing = _host_metadata_path(cell_name)
    try:
        prior = _json.loads(existing.read_text())
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return None
    workspace_mount = prior.get("workspace", {}).get("mount_point", "/work")
    return write_metadata(cell_name, workspace_mount)


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
