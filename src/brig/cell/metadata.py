"""Cell metadata file — `/run/brig/cell.json` (downward API).

A cell at startup needs to know its own identity to drive use cases
like agent-delegation flows: the cell hands `(cell-name, relpath)` to
a host-side worker that needs to open the same files the cell sees,
and the worker uses one of brig's safe primitives to do the read.

Modeled on Kubernetes' downward API / cloud instance metadata: brig
writes a small JSON file on the host, podman bind-mounts it read-only
into the cell at `/run/brig/cell.json`. The cell can read but not
modify it.

Schema (v4):
    {
      "version": 4,
      "name": "<cell-name>",
      "started_at": "<RFC 3339 UTC>",
      "workspace": {
        "mount_point": "/work",
        "quota": "500m"               // optional; only when set
      },
      "ingress":      [{"name": ..., "port": int,
                        "path_prefix": ..., "auth": "token"}, ...],
      "image_digest": "sha256:...",  // optional; only when pinned
      "policy": {
        "host_services": ["<svc-name>", ...]   // per-cell ACL
      }
    }

What changed since v3:
  - `profile` REMOVED. A cell's trust profile must not be read from this file
    (invariant 4 names it untrusted), so the ingress-replay auth:none gate now
    reads it from the trusted podman container label (`brig.profile`) instead.
    A v3 file on disk still carries the key; nothing reads it.
  - `workspace.quota` documented. The v3 writer already emitted it — quota
    enforcement (the `brig system watchdog` sweep and the `brig cp` guard) needs
    the limit for EVERY cell, and the restart-only cell-spec.json is absent for
    a default cell — but the v3 schema never listed it.

What changed in v3:
  - `ingress` added so `brig cell start` can replay route registration
    without the original yaml. No secrets land here.
  - `image_digest` added so `brig cell start` can re-verify the pinned
    digest before letting the container start.

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

SCHEMA_VERSION = 4
IN_CELL_PATH = "/run/brig/cell.json"


def _host_metadata_path(cell_name: str) -> Path:
    """Where brig writes the metadata file on the host. The cell sees this
    bind-mounted read-only at IN_CELL_PATH."""
    return HostPaths.STATE_DIR / cell_name / "cell-metadata.json"


def _vm_metadata_path(cell_name: str) -> Path:
    """The same file inside the Lima VM (after the /state virtiofs mount).
    Used by podman as the source side of the bind mount."""
    return VMPaths.STATE_DIR / cell_name / "cell-metadata.json"


def _host_spec_path(cell_name: str) -> Path:
    """Where brig persists a `restart: always` cell's full spec, so
    `brig system up` can replay it after a VM restart drops the container."""
    return HostPaths.STATE_DIR / cell_name / "cell-spec.json"


def write_cell_spec(spec: Any) -> None:
    """Persist a cell's full spec when restart == "always" (else remove any
    stale copy). Mode 0600 since env values may carry sensitive data."""
    import dataclasses
    if getattr(spec, "restart", "no") != "always":
        remove_cell_spec(spec.name)
        return
    atomic_write_json(_host_spec_path(spec.name), dataclasses.asdict(spec), mode=0o600)


def remove_cell_spec(cell_name: str) -> None:
    """Delete a cell's persisted restart spec so it can't be resurrected by
    restart:always on the next `brig system up`."""
    try:
        _host_spec_path(cell_name).unlink()
    except FileNotFoundError:
        pass


def read_cell_spec(cell_name: str) -> dict[str, Any] | None:
    """Read a persisted cell spec, or None if absent/unreadable."""
    import json as _json
    try:
        data = _json.loads(_host_spec_path(cell_name).read_text())
    except (FileNotFoundError, ValueError, OSError):
        return None
    return data if isinstance(data, dict) else None


def restorable_cell_specs() -> list[dict[str, Any]]:
    """All persisted specs whose restart policy is "always"."""
    out: list[dict[str, Any]] = []
    base = HostPaths.STATE_DIR
    if not base.is_dir():
        return out
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        spec = read_cell_spec(entry.name)
        if spec and spec.get("restart") == "always":
            out.append(spec)
    return out


# --- Desired-state marker -------------------------------------------------
# brig can't tell a crash (container exited-present) from an operator stop by
# container state alone, so an explicit `brig cell stop`/`kill` records this
# sentinel. `restart: always` recovery respects it (leaves the cell down until
# an explicit start), while an unmarked down cell — crashed or dropped by a VM
# restart — auto-recovers. This is the systemd `Restart=always` / Docker
# `unless-stopped` distinction between "I stopped it" and "it failed".


def _host_stopped_marker_path(cell_name: str) -> Path:
    return HostPaths.STATE_DIR / cell_name / "stopped"


def mark_cell_stopped(cell_name: str) -> None:
    """Record that the operator intentionally stopped this cell so recovery
    leaves it down until an explicit start."""
    path = _host_stopped_marker_path(cell_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")


def clear_cell_stopped(cell_name: str) -> None:
    """Clear the intentional-stop marker (on start/run) — desired state is
    running again, so recovery restores the cell if it later goes down."""
    _host_stopped_marker_path(cell_name).unlink(missing_ok=True)


def cell_marked_stopped(cell_name: str) -> bool:
    """True when the cell was intentionally stopped and not since started."""
    return _host_stopped_marker_path(cell_name).exists()


def build_metadata(
    cell_name: str,
    workspace_mount: str,
    started_at: datetime | None = None,
    ingress: list[dict[str, Any]] | None = None,
    image_digest: str | None = None,
    workspace_quota: str | None = None,
) -> dict[str, Any]:
    """Compose the cell metadata payload. Pure function for testability.

    ingress entries are stored in full ({name, port, path_prefix, auth})
    so `brig cell start` can replay registration without the original
    yaml. No secrets land here — the bearer token lives in the secrets
    dir and is re-read at registration time.

    workspace_quota is persisted here (for EVERY cell, unlike the
    restart-only cell-spec.json) so the reactive/preventive quota
    enforcement can find it regardless of restart policy.
    """
    ts = started_at or datetime.now(timezone.utc)
    ingress_published = [
        {
            "name": entry["name"],
            "port": entry["port"],
            "path_prefix": entry["path_prefix"],
            "auth": entry["auth"],
        }
        for entry in (ingress or [])
        if isinstance(entry, dict)
        and {"name", "port", "path_prefix", "auth"} <= entry.keys()
    ]
    workspace: dict[str, Any] = {"mount_point": workspace_mount}
    if workspace_quota:
        workspace["quota"] = workspace_quota
    payload: dict[str, Any] = {
        "version": SCHEMA_VERSION,
        "name": cell_name,
        "started_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": workspace,
        "ingress": ingress_published,
        "policy": {
            "host_services": _per_cell_host_services(cell_name),
        },
    }
    if image_digest:
        payload["image_digest"] = image_digest
    return payload


def _per_cell_host_services(cell_name: str) -> list[str]:
    """Read the cell's per-cell policy and return its host_services ACL
    as a list of names.

    The on-disk shape is `[{name, port, protocol}, ...]` — the in-cell
    metadata only exposes the names (no port leak into the cell's view
    of its own ACL). Returns empty list if no per-cell policy exists.
    """
    policy = load_cell_policy(cell_name)
    if not policy:
        return []
    names: list[str] = []
    for s in policy.get("host_services", []):
        if isinstance(s, dict) and isinstance(s.get("name"), str):
            names.append(s["name"])
        elif isinstance(s, str):
            names.append(s)
    return names


def refresh_metadata_if_present(cell_name: str) -> Path | None:
    """Rewrite the metadata file for `cell_name` if one already exists,
    preserving the original `workspace_mount` value.

    Called after per-cell policy changes to keep the HOST-side
    `policy.host_services` in cell-metadata.json current. No-op if the cell has
    no metadata file (cell was never started, or was removed).

    IMPORTANT: this does NOT update a running cell's in-cell view. cell.json is
    bind-mounted as a single file, and the atomic temp+rename write swaps the
    inode the mount is pinned to — the running container keeps seeing the old
    inode. The refreshed value takes effect on the cell's next start (or via
    `brig cell export`/`inspect`, which read the host copy). Warden enforces the
    ACL independently of this file, so egress policy is not affected either way.
    Bind mounts are fixed at create time, so the original workspace_mount is
    preserved.
    """
    import json as _json
    existing = _host_metadata_path(cell_name)
    try:
        prior = _json.loads(existing.read_text())
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return None
    if not isinstance(prior, dict):
        return None  # Tampered non-dict metadata (invariant 4).
    workspace = prior.get("workspace", {})
    if not isinstance(workspace, dict):
        workspace = {}
    workspace_mount = workspace.get("mount_point", "/work")
    # Preserve ingress across refresh — ingress configuration is fixed at
    # cell-create time, so it can't change without a `brig run`.
    prior_ingress = read_ingress(cell_name)
    return write_metadata(
        cell_name, workspace_mount,
        ingress=prior_ingress,
        image_digest=read_image_digest(cell_name),
        workspace_quota=workspace.get("quota"),
    )


def read_ingress(cell_name: str) -> list[dict[str, Any]]:
    """Return the cell's stored ingress entries from cell-metadata.json.

    Empty list when the cell has no metadata file, the file is corrupt,
    or the cell predates the `ingress` field. Each entry has the public
    shape (name, port, path_prefix, auth) — no secrets.
    """
    import json as _json
    try:
        payload = _json.loads(_host_metadata_path(cell_name).read_text())
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return []
    if not isinstance(payload, dict):
        return []  # Tampered non-dict metadata (invariant 4).
    entries = payload.get("ingress", []) or []
    return [
        e for e in entries
        if isinstance(e, dict)
        and {"name", "port", "path_prefix", "auth"} <= e.keys()
    ]


def read_image_digest(cell_name: str) -> str | None:
    """Return the cell's stored image_digest from cell-metadata.json.

    None when the cell was created without a pinned digest, the file
    predates the field, or is unreadable.
    """
    import json as _json
    try:
        payload = _json.loads(_host_metadata_path(cell_name).read_text())
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return None
    if not isinstance(payload, dict):
        return None  # Tampered non-dict metadata (invariant 4).
    val = payload.get("image_digest")
    return val if isinstance(val, str) and val else None


def read_workspace_quota(cell_name: str) -> str | None:
    """Return the cell's stored workspace_quota from cell-metadata.json.

    Written for EVERY cell (unlike the restart-only cell-spec.json), so this
    is the source of truth for quota enforcement regardless of restart policy.
    None when the cell has no quota, predates the field, or is unreadable.
    """
    import json as _json
    try:
        payload = _json.loads(_host_metadata_path(cell_name).read_text())
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return None
    if not isinstance(payload, dict):
        return None  # Tampered non-dict metadata (invariant 4).
    workspace = payload.get("workspace", {})
    val = workspace.get("quota") if isinstance(workspace, dict) else None
    return val if isinstance(val, str) and val else None


def write_metadata(
    cell_name: str,
    workspace_mount: str,
    ingress: list[dict[str, Any]] | None = None,
    image_digest: str | None = None,
    workspace_quota: str | None = None,
) -> Path:
    """Write the cell's metadata JSON to the host path. Returns the path.

    Called from reconciler.PODMAN_RUN before launching the cell, so the
    file is in place when podman creates the bind mount.

    Mode 0o644: world-readable inside the cell so any uid the container
    runs as can read it. The mode is set on the open fd before the
    atomic rename so a chmod failure can't silently leave the file at
    mkstemp's default 0600 (which would make it unreadable to the cell).
    """
    payload = build_metadata(
        cell_name, workspace_mount,
        ingress=ingress,
        image_digest=image_digest,
        workspace_quota=workspace_quota,
    )
    target = _host_metadata_path(cell_name)
    atomic_write_json(target, payload, mode=0o644)
    return target


def vm_source_path(cell_name: str) -> str:
    """Source path for the podman bind mount (VM-internal)."""
    return str(_vm_metadata_path(cell_name))
