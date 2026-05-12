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

Returned by `Brig.run()` / `Brig.run_sync()`.

| Field          | Type  | Description         |
|----------------|-------|---------------------|
| `name`         | `str` | Cell name           |
| `container_id` | `str` | Container ID        |
| `success`      | `bool`| Whether run succeeded|

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

## Example

```python
from brig.sdk import Brig

b = Brig()

# Run a cell.
cell = b.run_sync(
    name="my-scraper",
    image="python:3.12",
    command=["python", "scrape.py"],
    profile="supervised",
    secrets=["api-key"],
)

# Wait for completion.
exit_code = cell.wait_sync(timeout=300)
print(f"Exited with code {exit_code}")

# Get logs and clean up.
print(cell.logs_sync())
cell.rm_sync()
```

## Architecture

The SDK calls domain modules directly (`brig.cell.lifecycle`, `brig.cell.reconciler`,
`brig.network.subnet`, etc.) rather than shelling out to the CLI. All podman commands
are routed through `brig.vm.shell.vm_run()` which wraps them in `limactl shell brig --`.

The same security enforcement applies: gVisor runtime is hardcoded, proxy env vars
cannot be overridden, cell names are validated, and the proxy must be running before
cells start.
