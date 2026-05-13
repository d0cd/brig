# Brig SDK Specification

Version 0.2.0 | Python 3.10+

## Import

```python
from brig.sdk import Brig, Cell, BrigError
# or
from brig import Brig, Cell, BrigError
```

## Exception Hierarchy

```
BrigError(Exception)
├── CellNotFoundError     # Cell does not exist
├── ImageVerificationError # Image digest mismatch or verification failure
├── ProfileError          # Unknown or invalid trust profile
└── SecretNotFoundError   # Referenced secret file not found
```

All exceptions carry:
- `message: str` — Human-readable error description.
- `returncode: int` — Exit code (default `1`).
- `stderr: str` — Error details.
- `suggestion: str | None` — Suggested fix.

## Dataclasses

### `CellInfo`

Returned by `Brig.list()` / `Brig.list_sync()`.

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
| `exit_code` | `int`  | Process exit code        |
| `stdout`    | `str`  | Standard output          |
| `stderr`    | `str`  | Standard error           |
| `success`   | `bool` | True if exit_code == 0   |

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

No parameters. The SDK calls domain modules directly — it does not shell out to the CLI binary.

### `Brig.run()` / `Brig.run_sync()`

```python
async def run(
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
) -> Cell
```

Creates and starts a new cell. Returns a `Cell` handle.

Enforces:
- Invariant 9: Proxy must be running (unless airgapped).
- Rate limiting.
- Cell name validation against `CELL_NAME_PATTERN`.

### `Brig.list()` / `Brig.list_sync()`

```python
async def list() -> list[CellInfo]
```

### `Brig.cell()`

```python
def cell(name: str) -> Cell
```

Get a handle to an existing cell. Raises `CellNotFoundError` if it doesn't exist.

### `Brig.execute()` / `Brig.execute_sync()` — Agent API

Single-call method: runs code, waits for completion, collects output, cleans up.

```python
async def execute(
    image: str,
    command: list[str],
    name: str | None = None,       # auto-generated if omitted
    timeout: str = "5m",
    network: str = "default",      # or "none" for air-gap
    env: list[str] | None = None,
    secrets: list[str] | None = None,
    profile: str | None = None,
) -> CellRunResult
```

Returns `CellRunResult(name, exit_code, stdout, stderr, success)`.
Cell is automatically removed after execution.

### `Brig.warden`

A `WardenHandle` for proxy management:

```python
b = Brig()
b.warden.start()   # Start the proxy
b.warden.stop()    # Stop the proxy
b.warden.status()  # -> WardenStatus
```

## `Cell` Class

### Methods

All methods have both async and sync variants (e.g., `wait()` / `wait_sync()`).

| Method        | Returns     | Description                    |
|---------------|-------------|--------------------------------|
| `wait()`      | `int`       | Block until cell exits, return exit code |
| `stop()`      | `None`      | Gracefully stop                |
| `kill()`      | `None`      | Immediately kill               |
| `rm(force=False)` | `None` | Remove cell and resources      |
| `logs(tail=None)` | `str`  | Get container logs             |
| `is_alive()`  | `bool`      | Check if still running         |
| `copy_in(src, dst)` | `None` | Copy file into cell workspace |
| `copy_out(src, dst)` | `None` | Copy file from cell (sanitized) |

## Examples

### Agent use (single call)

```python
from brig import Brig

b = Brig()
result = b.execute_sync(
    "python:3.12",
    ["python", "-c", "print('hello from sandbox')"],
    timeout="30s",
    network="none",  # air-gapped
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

# Copy input file into cell.
cell.copy_in("./urls.txt", "scraper:/work/urls.txt")

# Wait for completion.
exit_code = cell.wait_sync(timeout=300)

# Copy results out (sanitized — unsafe extensions blocked, quarantine applied).
cell.copy_out("scraper:/work/results.json", "./results.json")

# Clean up.
cell.rm_sync()
```

## Architecture

The SDK calls domain modules directly (`brig.cell.lifecycle`, `brig.cell.reconciler`,
`brig.network.subnet`, etc.) rather than shelling out to the CLI. All podman commands
are routed through `brig.vm.shell.vm_run()` which wraps them in `limactl shell brig --`.

The same security enforcement applies: gVisor runtime is hardcoded, proxy env vars
cannot be overridden, cell names are validated, and the proxy must be running before
cells start.
