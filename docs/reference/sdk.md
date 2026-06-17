# Brig SDK Specification

Version 0.4.0 | Python 3.10+

The SDK calls Brig's domain modules directly (no CLI shell-out). Every
method has an `async` and `_sync` variant; the async path just offloads
to `asyncio.to_thread`.

## Import

```python
from brig.sdk import Brig, Cell, BrigError
# or
from brig import Brig, Cell, BrigError
```

## Exception Hierarchy

```
BrigError(Exception)
├── CellNotFoundError      # Cell does not exist
├── ImageVerificationError # Image digest mismatch or verification failure
├── ProfileError           # Unknown or invalid trust profile
└── SecretNotFoundError    # Referenced secret file not found
```

All exceptions carry:
- `message: str` — Human-readable error description.
- `returncode: int` — Exit code (default `1`).
- `stderr: str` — Error details.
- `suggestion: str | None` — Suggested fix.

## Dataclasses

### `CellInfo`

Returned by `Brig.list_cells()` / `Brig.list_sync()`.

| Field    | Type  | Description         |
|----------|-------|---------------------|
| `name`   | `str` | Cell name           |
| `status` | `str` | Cell status         |
| `image`  | `str` | Container image     |

### `CellRunResult`

Returned by `Brig.execute()` / `Brig.execute_sync()`.

| Field       | Type   | Description              |
|-------------|--------|--------------------------|
| `name`      | `str`  | Cell name                |
| `exit_code` | `int`  | Process exit code (`-1` if wait itself failed) |
| `stdout`    | `str`  | Combined stdout/stderr (podman merges them) |
| `stderr`    | `str`  | Always `""` — see note on `stdout` |
| `success`   | `bool` | True if `exit_code == 0` |

### `WardenStatus`

Returned by `WardenHandle.status()`.

| Field     | Type        | Description              |
|-----------|-------------|--------------------------|
| `running` | `bool`      | Whether Warden is active |
| `networks`| `list[str]` | Connected networks       |

## `Brig` Class

### Constructor

```python
Brig()
```

No parameters. The SDK calls domain modules directly — it does not shell
out to the CLI binary.

### `Brig.run()` / `Brig.run_sync()`

```python
def run_sync(
    name: str,
    image: str,
    command: list[str] | None = None,
    env: list[str] | None = None,
    secrets: list[str] | None = None,
    memory: str = "2g",
    cpus: str = "2",
    pids_limit: int = 512,
    network: str = "default",
    profile: str | None = None,
    detach: bool = True,
    timeout: str | None = None,
    labels: list[str] | None = None,
    host_services: list[dict] | None = None,
    mounts: list[dict] | None = None,   # {name, host_path, mount_point, mode?} — bounded by mount_roots
    ingress: list[dict] | None = None,
    policy_allow: list[str] | None = None,
    policy_deny: list[str] | None = None,
    policy_passthrough_tls: list[str] | None = None,
    image_digest: str | None = None,
    trust_warden_ca: bool = True,
    workdir: str | None = None,
    workspace_quota: str | None = None,
    workspace_mount: str = "/work",
    writable_rootfs: bool = False,
    seccomp_profile: str | None = None,
    restart: str = "no",          # "always" re-launches on `brig system up`
    user: str | None = None,      # podman --user; "0" to own a rw mounts: dir
) -> Cell
```

Creates and starts a new cell. Returns a `Cell` handle.

Field semantics match the cell yaml — see
[`docs/design/cell-definition.md`](../design/cell-definition.md) for
the full schema (validation rules, expected shapes for `host_services`,
`ingress`, `policy_*`). `validate_cell_definition`
runs against the SDK args before the cell starts, so the same
untrusted-profile guards and SSRF wildcard checks that apply to
`brig run --file` apply here.

Enforces:
- Invariant 9: Proxy must be running (unless `network="none"`).
- Cell name validation against `CELL_NAME_PATTERN`.
- Profile precedence: profile defaults < explicit args.

### `Brig.execute()` / `Brig.execute_sync()` — Agent API

Single-call method: runs code, waits for completion, collects output,
removes the cell. Designed for agents that don't need a long-lived
handle.

```python
def execute_sync(
    image: str,
    command: list[str],
    name: str | None = None,    # auto-generated if omitted
    timeout: str = "5m",
    network: str = "default",   # or "none" for airgap
    env: list[str] | None = None,
    secrets: list[str] | None = None,
    profile: str | None = None,
) -> CellRunResult
```

Returns `CellRunResult(name, exit_code, stdout, stderr, success)`. The
cell is always removed in `finally:` so a wait timeout doesn't leak it.
`stdout` carries the merged stream; `stderr` is always `""` because
`podman logs` does not separate streams.

`execute_sync` is intentionally a narrower surface than `run_sync` —
the long list of advanced fields (host_services, ingress, policy_*) is
not exposed because the typical agent use case doesn't need them. Drop
to `run_sync` when you do.

### `Brig.list_cells()` / `Brig.list_sync()`

```python
def list_sync() -> list[CellInfo]
```

Returns information about all existing cells (running and stopped).
The method is `list_cells()`, not `list()` — there is no `list()`
method.

### `Brig.cell()`

```python
def cell(name: str) -> Cell
```

Get a handle to an existing cell. Raises `CellNotFoundError` if it
doesn't exist.

### `Brig.warden`

A `WardenHandle` for proxy management:

```python
b = Brig()
b.warden.start()   # Start the proxy
b.warden.stop()    # Stop the proxy
b.warden.status()  # -> WardenStatus
```

## `Cell` Class

Handle to a running or completed cell. Every method has both async and
sync variants (e.g., `wait()` / `wait_sync()`).

| Method              | Returns | Description                              |
|---------------------|---------|------------------------------------------|
| `wait(timeout=None)`| `int`   | Block until cell exits; returns exit code, or `-1` if the wait itself failed |
| `stop()`            | `None`  | Gracefully stop                          |
| `kill()`            | `None`  | Immediately kill                         |
| `rm(force=False)`   | `None`  | Remove cell and resources                |
| `logs(tail=None)`   | `str`   | Combined container logs (podman merges streams) |
| `is_alive()`        | `bool`  | Whether the cell's container is running  |
| `copy_in(src, dst)` | `None`  | Copy a host file into the cell workspace |
| `copy_out(src, dst)`| `None`  | Copy a cell workspace file to the host (sanitized) |

`wait_sync` returns `-1` when the wait *itself* failed (subprocess
error, timeout, unparseable podman status), distinct from a real
non-zero cell exit code. The agent path (`execute_sync`) surfaces
this `-1` in `CellRunResult.exit_code`.

## Examples

### Agent use (single call)

```python
from brig import Brig

b = Brig()
result = b.execute_sync(
    "python:3.12",
    ["python", "-c", "print('hello from sandbox')"],
    timeout="30s",
    network="none",  # airgap
)
print(result.exit_code)  # 0
print(result.stdout)     # "hello from sandbox\n"
# Cell is automatically cleaned up.
```

### Long-running cell with file I/O

```python
from brig import Brig

b = Brig()
cell = b.run_sync(
    name="scraper",
    image="python:3.12",
    command=["python", "scrape.py"],
    profile="supervised",
    secrets=["api-key"],
)

cell.copy_in("./urls.txt", "/work/urls.txt")
exit_code = cell.wait_sync(timeout=300)
cell.copy_out("results.json", "./results.json")
cell.rm_sync()
```

### Cell with HTTP host service + ingress

```python
from brig import Brig

b = Brig()
cell = b.run_sync(
    name="webapp",
    image="localhost/webapp:latest",
    image_digest="sha256:abc123...",  # pin to a specific build
    host_services=[
        {"name": "db", "port": 5432, "protocol": "tcp"},
    ],
    ingress=[
        {"name": "api", "port": 8000,
         "path_prefix": "/api", "auth": "token"},
    ],
    policy_allow=["api.github.com", "*.example.com"],
)
```

## Architecture

The SDK calls domain modules directly (`brig.cell.lifecycle`,
`brig.cell.reconciler`, `brig.network.subnet`, etc.) rather than
shelling out to the CLI. All podman commands are routed through
`brig.vm.shell.vm_run()` which wraps them in `limactl shell brig --`.

The same security enforcement applies: gVisor runtime is hardcoded,
proxy env vars cannot be overridden, cell names are validated, and the
proxy must be running before cells start.
