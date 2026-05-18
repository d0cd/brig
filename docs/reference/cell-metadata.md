# Cell Metadata Reference

Every cell brig runs gets a read-only metadata file mounted at
`/run/brig/cell.json`. The cell uses it to learn its own identity
(name, workspace mount point, policy ACL) so it can hand
`(cell, relpath)` to a host-side worker for any agent-delegation
flow.

The pattern mirrors Kubernetes' downward API and cloud instance
metadata: brig writes a small JSON file on the host, podman bind-mounts
it read-only into the cell. The cell can read but cannot modify it.

## Schema (v2)

```json
{
  "version": 2,
  "name": "my-cell",
  "started_at": "2026-05-18T17:30:00Z",
  "workspace": {
    "mount_point": "/work"
  },
  "policy": {
    "host_services": ["model"]
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `version` | int | Schema version. Currently `2`. Bumps on breaking shape changes. |
| `name` | string | Cell name, matches `--name` / yaml `name:`. |
| `started_at` | string | RFC 3339 UTC timestamp of cell creation. |
| `workspace.mount_point` | string | Path inside the cell, default `/work`, overridable via `workspace_mount` in the cell spec. |
| `policy.host_services` | string[] | Per-cell host-service ACL (bare names; the global declares ports). |

### What changed in v2

v1 also published `workspace.host_path` — the absolute path on the
host where the cell's workspace lives. We removed it.

The reason is a confused-deputy attack: a cell can drop a symlink
inside its workspace pointing at a host secret, then ask a host-side
worker to read by path. The host kernel follows the symlink and
returns the secret — the cell exfiltrated a file it could never
reach itself (gVisor blocked direct reads). There is no kernel-mount
fix available on macOS, so the only defense is at the application
that opens the file. Removing `host_path` makes that defense
structural: consumers don't have a path string to misuse.

## Reading the metadata file from inside a cell

Any language, no library required:

```bash
# Inside the cell
cat /run/brig/cell.json | jq -r .name
# → my-cell
```

```python
# Inside the cell
import json
with open("/run/brig/cell.json") as f:
    meta = json.load(f)
print(meta["name"], meta["workspace"]["mount_point"])
```

The file is bind-mounted read-only; writes fail with `EACCES`.

---

## Reading the cell's workspace from the host

Host-side consumers of a cell's workspace files (e.g. an
agent-delegation worker running on behalf of the cell) MUST use one
of the safe primitives below. Plain `open()` on a host path
derived from the cell name is unsafe and exists exactly because a
cell can plant symlinks the host kernel will follow.

### Any language: `brig cell read <cell> <relpath>` (preferred)

Streams the file to stdout. Each path component is walked with
`O_NOFOLLOW` — a cell-planted symlink anywhere along the path
errors out instead of being followed.

```bash
brig cell read my-cell input.json > /tmp/local-copy
brig cell read my-cell data/items.txt | wc -l
```

Use this from shell, Node, Go, Rust, anywhere that can shell out.
One subprocess per file — fine for the agent-delegation pattern
(small files, modest read counts). For large bulk transfers, use
`brig cell cp my-cell:/work/dir /local/dir` (same safety property,
batched).

### Python in-process: `brig.workspace.validation.safe_open`

If your consumer is Python and shelling out per file is overhead
you'd rather avoid:

```python
from brig.workspace.validation import safe_open, WorkspaceEscape

def read_cell_file(cell: str, relpath: str) -> bytes:
    try:
        with safe_open(cell, relpath, "rb") as f:
            return f.read()
    except WorkspaceEscape:
        raise   # cell-controlled path tried to escape — refuse the read
```

`safe_open` opens the workspace root with `O_NOFOLLOW | O_DIRECTORY`,
walks each intermediate component with `openat(parent, name,
O_NOFOLLOW)`, and opens the final component with `O_NOFOLLOW`. The
caller gets an open file descriptor; there's no path string the
cell can poison after the fd binds.

### Operate inside the cell: `brig cell exec`

For the "run a command on the workspace" case, run the command
inside the cell itself via `brig cell exec`. The command runs under
gVisor in the cell's namespace, so symlink resolution happens inside
the cell — a symlink to `/etc/passwd` resolves to the cell's
`/etc/passwd` (sandboxed), not the host's:

```bash
brig cell exec my-cell -- grep "TODO" /work/notes.md
```

### What NOT to do

There's no `host_path` to copy from `cell.json`, so the most obvious
mistake (using it as a path argument) isn't even possible. But if
you derive the path yourself from the cell name:

```python
# UNSAFE — do not do this.
path = f"~/.brig/state/{cell}/workspace/{relpath}"
with open(path) as f:        # ← follows any cell-planted symlink
    data = f.read()
```

You're back where v1 was. Use one of the primitives above.

---

## Threat model — confused deputy

A cell running untrusted code can drop a symlink inside its
workspace pointing outside it:

```bash
ln -s /Users/d0c/.ssh/id_rsa /work/innocuous.txt
```

The cell itself can't read the SSH key — gVisor blocks the syscall.
But when a host-side consumer reads `/work/innocuous.txt` via a
naively-resolved host path, the kernel follows the symlink and
returns the key. The cell got the host to read on its behalf —
classic confused deputy.

> **Live exploit shape** (still works against any consumer that
> derives the host path itself and uses plain `open()`):
>
> ```bash
> # 1. Cell drops a symlink inside its workspace pointing at a host file.
> brig cell exec my-cell -- ln -sf /etc/passwd /work/foo.txt
>
> # 2. Cell asks a host-side worker to read that filename.
> #    If the worker uses safe_open / brig cell read: refused.
> #    If it derives the path and uses plain open(): leaks /etc/passwd.
> ```

### What brig does NOT defend against

The schema v2 break closes the easy mistake (publishing the path).
It does NOT close:

| Issue | Why brig can't fix it from here |
|---|---|
| Consumers that derive the host path themselves and `open()` it | Once the path is derivable from the cell name + brig install convention, anyone who tries hard enough can construct it. The safe primitives are the recommended path; using them is the consumer's responsibility. |
| In-workspace file reads inside an agent's own tools (e.g. an LLM-driven Read/Edit tool) | The tool's own file-open code runs after brig's hand-off. The fix lives in the tool. macOS doesn't have `MS_NOSYMFOLLOW`-equivalent for a directory tree, so there's no mount-level brig can apply. |

The schema break is a defense in depth that eliminates the *easy*
mistake. The full chain still requires each consumer in the read
path to use safe-open semantics.

## See also

- `brig.cell.metadata` — source for the writer
- `brig.workspace.validation` — source for `safe_open` / `safe_dirfd`
- `brig cell read --help`, `brig cell cp --help`, `brig cell exec --help` —
  the safe consumer primitives
