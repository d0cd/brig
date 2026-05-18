# Cell Metadata Reference

Every cell brig runs gets a read-only metadata file mounted at
`/run/brig/cell.json`. The cell uses it to learn its own identity —
particularly the **host path** of its workspace, which it needs to
publish to host-side consumers (e.g. an agent-delegation API that
runs a worker on the host and needs to see the same files the cell
sees).

The pattern mirrors Kubernetes' downward API and cloud instance
metadata: brig writes a small JSON file on the host, podman bind-mounts
it read-only into the cell. The cell can read but cannot modify it.

## Schema (v1)

```json
{
  "version": 1,
  "name": "my-cell",
  "started_at": "2026-05-18T17:30:00Z",
  "workspace": {
    "mount_point": "/work",
    "host_path":   "/Users/d0c/.brig/state/my-cell/workspace"
  },
  "policy": {
    "host_services": ["model"]
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `version` | int | Schema version. Currently `1`. Bumps on breaking shape changes. |
| `name` | string | Cell name, matches `--name` / yaml `name:`. |
| `started_at` | string | RFC 3339 UTC timestamp of cell creation. |
| `workspace.mount_point` | string | Path inside the cell, default `/work`, overridable via `workspace_mount` in the cell spec. |
| `workspace.host_path` | string | Absolute path on the host. Cells pass this to host-side consumers; consumers MUST read via one of the [safe primitives below](#consuming-workspacehost_path-safely). |
| `policy.host_services` | string[] | Per-cell host-service ACL (bare names; the global declares ports). |

## Reading the metadata file from inside a cell

Any language, no library required:

```bash
# Inside the cell
cat /run/brig/cell.json | jq -r .workspace.host_path
# → /Users/d0c/.brig/state/my-cell/workspace
```

```python
# Inside the cell
import json
with open("/run/brig/cell.json") as f:
    meta = json.load(f)
print(meta["workspace"]["host_path"])
```

The file is bind-mounted read-only; writes fail with `EACCES`.

---

## Consuming `workspace.host_path` safely

This section is **load-bearing**: any host-side process that opens
files inside a cell's workspace using the published `host_path` MUST
go through one of the primitives below. A direct `open()` on the
path string is a known exploit (a cell drops a symlink → the host's
open follows it → cell exfiltrates host secrets). See [the threat
model](#threat-model-symlink-escape) below for why.

Pick the variant that fits your language / context:

### Python (preferred — brig ships the primitive)

```python
from brig.workspace.validation import safe_open, WorkspaceEscape

def read_cell_file(cell_name: str, relpath: str) -> bytes:
    try:
        with safe_open(cell_name, relpath, "rb") as f:
            return f.read()
    except WorkspaceEscape:
        # Cell-controlled input asked for a path that escapes the
        # workspace, or any path component was a symlink. Refuse.
        raise
```

`safe_open` walks each path component with `O_NOFOLLOW`, so a
symlink anywhere along the path raises `WorkspaceEscape`. The
caller gets an open file descriptor — there is no window where the
cell can swap the inode after validation.

For advanced uses (e.g. listing the workspace), `safe_dirfd(cell)`
returns the workspace root as an os-level dirfd that the caller can
walk with their own `openat` chain.

### Any language (via the cell itself)

If your consumer isn't Python, the simplest race-free option is to
read the file *from inside the cell*, where gVisor enforces the
sandbox. Brig's existing primitives go through podman, which uses
the cell's namespaced filesystem view — not the host's view of the
bind mount — so symlinks resolve relative to the cell, not the host.

```bash
# Stream the file to stdout via brig cell exec — runs `cat` inside the
# cell, in the gVisor sandbox. A cell-side symlink to /etc/passwd
# reads the CELL's /etc/passwd (sandboxed), not the host's.
brig cell exec my-cell -- cat relpath > /tmp/out

# Or copy out via brig cell cp (also goes through podman's view).
brig cell cp my-cell:/work/relpath /tmp/out
```

Use this when the consumer doesn't link against `brig.workspace`.
Cost: one extra subprocess invocation per read.

### What NOT to do

```python
# UNSAFE — do not do this.
import json
with open("/run/brig/cell.json") as m:
    host_path = json.load(m)["workspace"]["host_path"]
with open(f"{host_path}/relpath", "rb") as f:   # ← follows symlinks
    data = f.read()
```

```bash
# UNSAFE — do not do this.
cat "$HOST_PATH/relpath"
```

The kernel follows any symlink the cell planted in its workspace,
including symlinks to files outside the workspace that the cell
itself cannot read.

---

## Threat model: symlink escape

A cell running untrusted code can drop a symlink inside its
workspace pointing outside it:

```bash
ln -s /Users/d0c/.ssh/id_rsa /work/innocuous.txt
```

The cell itself can't read the SSH key (gVisor blocks the syscall),
but when a host-side consumer reads `/work/innocuous.txt` using its
published `host_path`, the kernel follows the symlink and returns
the key. The cell got an arbitrary-host-file-read primitive that
bypasses its gVisor sandbox — by asking the host to read on its
behalf.

> **Live exploit** (reproducer shape — works against any consumer
> that uses plain `open()` on `workspace.host_path`):
>
> ```bash
> # 1. Cell drops a symlink into its workspace pointing at a host file.
> brig cell exec my-cell -- ln -sf /etc/passwd /work/foo.txt
>
> # 2. Cell asks a host-side worker (via whichever delegation API
> #    consumes workspace.host_path) to read that filename.
> #    A plain open() in the worker follows the symlink → returns
> #    the host's /etc/passwd to the cell.
> ```
>
> Substitute `~/.ssh/id_rsa`, `~/.aws/credentials`,
> `~/.config/gh/hosts.yml`, etc. The class of host files the cell
> can exfiltrate is exactly the set the host worker process can
> read.

### Defenses brig does NOT yet provide

| Defense | Status | Why |
|---|---|---|
| Mount workspace with `nosymfollow` | **Roadmap** | podman 4.x doesn't expose this flag on bind mounts (verified empirically: both `-v src:dst:nosymfollow` and `--mount type=bind,...,nosymfollow` are rejected). Converting to a podman volume would break the host-side-access property that makes workspace passthrough useful at all. Tracked in `docs/ROADMAP.md`. |
| Worker-side default of "prompt before code execution" | **consumer side** | Belongs in the agent-delegation API that invokes the worker, not in brig. |
| Worker-side allowlist of permitted `workspace` values | **consumer side** | The API that accepts `workspace.host_path` from a caller decides what it'll do with it. |

### Implications

- The brig-provided guardrail is **necessary but not sufficient** —
  every consumer that opens files via `workspace.host_path`
  independently has to use one of the safe primitives. The blast
  radius of one consumer forgetting is one consumer's reads.
- Until `nosymfollow` lands at the mount layer, treat symlinks in
  cell workspaces as adversarial input. The safe primitives above
  are the contract.

## See also

- `brig.cell.metadata` — source for the writer
- `brig.workspace.validation` — source for `safe_open` / `safe_dirfd`
- `brig cell exec --help`, `brig cell cp --help` — language-agnostic
  alternatives that go through the cell's gVisor view
