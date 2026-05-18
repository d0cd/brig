# Cell Metadata Reference

Every cell brig runs gets a read-only metadata file mounted at
`/run/brig/cell.json`. The cell uses it to learn its own identity —
particularly the **host path** of its workspace, which it needs to
publish to host-side consumers (e.g. an agent invoked via aitelier
that needs to see the same files the cell sees).

The pattern mirrors Kubernetes' downward API and cloud instance
metadata: brig writes a small JSON file on the host, podman bind-mounts
it read-only into the cell. The cell can read but cannot modify it.

## Schema (v1)

```json
{
  "version": 1,
  "name": "hermes",
  "started_at": "2026-05-18T17:30:00Z",
  "workspace": {
    "mount_point": "/work",
    "host_path":   "/Users/d0c/.brig/state/hermes/workspace"
  },
  "policy": {
    "host_services": ["aitelier"]
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `version` | int | Schema version. Currently `1`. Bumps on breaking shape changes. |
| `name` | string | Cell name, matches `--name` / yaml `name:`. |
| `started_at` | string | RFC 3339 UTC timestamp of cell creation. |
| `workspace.mount_point` | string | Path inside the cell, default `/work`, overridable via `workspace_mount` in the cell spec. |
| `workspace.host_path` | string | Absolute path on the host. Cells pass this to host-side consumers; consumers MUST validate (see below). |
| `policy.host_services` | string[] | Per-cell host-service ACL (bare names; the global declares ports). |

## Reading from a cell

Any language, no library required:

```bash
# Inside the cell
cat /run/brig/cell.json | jq -r .workspace.host_path
# → /Users/d0c/.brig/state/hermes/workspace
```

```python
# Inside the cell
import json
with open("/run/brig/cell.json") as f:
    meta = json.load(f)
print(meta["workspace"]["host_path"])
```

The file is bind-mounted read-only; writes fail with `EACCES`.

## Security model — workspace passthrough

The cell metadata file enables a class of features where a host-side
process reads the cell's workspace (e.g. a Sandbox Agent that opens
files the cell wrote). That pattern has a known attack surface and
brig publishes the validation primitive consumers must use.

### Threat: symlink escape

A cell running untrusted code can drop a symlink inside its workspace
that points outside it:

```bash
ln -s /Users/d0c/.ssh/id_rsa /work/innocuous.txt
```

The cell itself can't read the SSH key (gVisor blocks the syscall),
but when the host-side consumer reads `/work/innocuous.txt` the kernel
follows the symlink and returns the key — the cell just exfiltrated a
secret it could never reach on its own.

### Required guardrails (host-side consumer responsibility)

**Every** host-side process that reads files from a cell's workspace
MUST go through `brig.workspace.validation.safe_open` — a race-free,
file-descriptor-based primitive that walks each path component with
`O_NOFOLLOW`. A path-returning variant is intentionally NOT provided:
between any path-returning validator and the consumer's subsequent
`open()`, the cell can swap the inode for a symlink to a host secret.

```python
from brig.workspace.validation import safe_open, WorkspaceEscape

def read_cell_file(cell_name: str, requested: str) -> bytes:
    try:
        with safe_open(cell_name, requested, "rb") as f:
            return f.read()
    except WorkspaceEscape:
        # Treat as adversarial — refuse.
        raise
```

`safe_open`:
1. Opens the workspace root with `O_NOFOLLOW | O_DIRECTORY` — refuses
   if the root itself is a symlink.
2. Walks each intermediate component with `openat(parent, name,
   O_NOFOLLOW | O_DIRECTORY)`.
3. Opens the final component with `openat(parent, name, O_NOFOLLOW)`.
4. Yields the opened file as a context manager. The consumer never
   touches a path string; the cell cannot swap the inode after the
   fd is bound.

For advanced uses (e.g. listing the workspace), `safe_dirfd(cell)`
returns the workspace dirfd — the caller owns it and is responsible
for closing.

### Defenses brig does NOT yet provide

| Defense | Status | Why |
|---|---|---|
| Mount workspace with `nosymfollow` | **Roadmap** | podman 4.x doesn't expose this flag on bind mounts. Converting to a podman volume would break the host-side-access requirement that makes workspace passthrough useful at all. Tracked in `docs/ROADMAP.md`. |
| Sandbox Agent permissions default to `ask` | **Hermes/aitelier side** | Belongs in the consumer that invokes the agent, not in brig. Documented in `cells/hermes/hermes-src/plans/brig-image-build-feedback.md` guardrail #2. |
| Aitelier validates `workspace` value against an allowlist | **Aitelier side** | Documented in the same feedback, guardrail #3. |

### Implications

- The brig-provided guardrail is **necessary but not sufficient** —
  every consumer of cell workspaces independently has to call
  `assert_inside_workspace`. The blast radius of one consumer
  forgetting it is one consumer's reads.
- Until `nosymfollow` lands at the mount layer, treat symlinks in cell
  workspaces as adversarial input. Don't open files inside a
  workspace from the host without going through the validator.

## See also

- `brig.cell.metadata` — source for the writer
- `brig.workspace.validation` — source for the validator
- `cells/hermes/hermes-src/plans/brig-image-build-feedback.md` —
  the design conversation that motivated this feature
