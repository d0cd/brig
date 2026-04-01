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
- `returncode: int` — CLI exit code (default `1`).
- `stderr: str` — Raw stderr from the brig CLI subprocess.

Exception mapping uses regex patterns against CLI stderr. More specific patterns match before generic ones.

## Dataclasses

### `CellInfo`

Returned by `Brig.list()`.

| Field    | Type  | Description         |
|----------|-------|---------------------|
| `name`   | `str` | Cell name           |
| `status` | `str` | Cell status         |
| `image`  | `str` | Container image     |

### `CellRunResult`

Returned as `Cell.run_result` after `Brig.run()`.

| Field             | Type            | Description                       |
|-------------------|-----------------|-----------------------------------|
| `cell`            | `str`           | Cell name                         |
| `cell_id`         | `str`           | Container ID                      |
| `image`           | `str`           | Container image                   |
| `status`          | `str`           | Initial status                    |
| `network`         | `str`           | Network name                      |
| `runtime`         | `str`           | OCI runtime (e.g., `runsc`)       |
| `timeout_seconds` | `Optional[int]` | Timeout if set, else `None`       |
| `labels`          | `dict`          | Container labels (default `{}`)   |

### `CellEvent`

Yielded by `Cell.events()`.

| Field    | Type   | Description                     |
|----------|--------|---------------------------------|
| `cell`   | `str`  | Cell name                       |
| `action` | `str`  | Event action (start, stop, etc.)|
| `time`   | `str`  | Event timestamp                 |
| `raw`    | `dict` | Full event JSON (default `{}`)  |

### `CellStats`

Returned by `Brig.stats()` and `Cell.stats()`.

| Field         | Type  | Description             |
|---------------|-------|-------------------------|
| `cell`        | `str` | Cell name               |
| `cpu_percent` | `str` | CPU usage percentage    |
| `mem_usage`   | `str` | Memory usage string     |
| `mem_percent` | `str` | Memory usage percentage |
| `pids`        | `str` | Process count           |

### `WardenStatus`

Returned by `WardenHandle.status()`.

| Field     | Type   | Description              |
|-----------|--------|--------------------------|
| `running` | `bool` | Whether Warden is active |

### `CellResult` (deprecated)

Retained for backward compatibility. Will be removed in a future release.

| Field       | Type  | Description     |
|-------------|-------|-----------------|
| `cell`      | `str` | Cell name       |
| `exit_code` | `int` | Exit code       |

## `Brig` Class

### Constructor

```python
Brig(brig_bin: str = "brig", warden_bin: str = "warden")
```

| Parameter    | Default    | Description                 |
|--------------|------------|-----------------------------|
| `brig_bin`   | `"brig"`   | Path to brig CLI binary     |
| `warden_bin` | `"warden"` | Path to warden CLI binary   |

**Attribute:** `warden: WardenHandle` — Handle for Warden proxy operations.

### `run()`

```python
async def run(
    self,
    name: str,
    image: str,
    command: list[str] = None,
    *,
    profile: str = None,
    policy_allow: list[str] = None,
    policy_deny: list[str] = None,
    egress_allow: list[str] = None,
    secrets: list[str] = None,
    env: dict[str, str] = None,
    memory: str = None,
    cpus: str = None,
    pids_limit: int = None,
    timeout: str = None,
    network: str = None,
    labels: dict[str, str] = None,
    detach: bool = True,
    rm: bool = False,
    workdir: str = None,
    image_digest: str = None,
    canary_tokens: dict[str, str] = None,
) -> Cell
```

Launch a new cell. Defaults to detached mode for programmatic use.

**Returns:** `Cell` handle for interacting with the running cell.

**Raises:**
- `BrigError` — Invalid inputs, CLI failure, or timeout.
- `ProfileError` — Unknown profile name.
- `ImageVerificationError` — Digest mismatch.
- `SecretNotFoundError` — Secret file not found.

**Sync variant:** `run_sync(**kwargs) -> Cell`

### `list()`

```python
async def list(self) -> list[CellInfo]
```

List all cells. Returns empty list on parse failure.

**Sync variant:** `list_sync() -> list[CellInfo]`

### `stats()`

```python
async def stats(self, name: str = None) -> list[CellStats]
```

Get resource usage stats. Pass `name` to filter to a specific cell.

**Sync variant:** `stats_sync(name: str = None) -> list[CellStats]`

### `get()`

```python
async def get(self, name: str) -> Optional[Cell]
```

Look up an existing cell by name. Returns `Cell` or `None` if not found.

### `cell()`

```python
async def cell(self, name: str) -> Cell
```

Get a handle to an existing cell by name. Does not verify the cell exists.

### `pipe()`

```python
async def pipe(
    self,
    source: Cell,
    source_path: str,
    dest: Cell,
    dest_path: str,
    local_tmp: str = "/tmp",
) -> None
```

Transfer data between cells via the local filesystem. Isolation is preserved because data transits through macOS, never cell-to-cell directly.

**Sync variant:** `pipe_sync(source, source_path, dest, dest_path) -> None` (always uses `/tmp` for staging)

## `Cell` Class

Returned by `Brig.run()`, `Brig.cell()`, and `Brig.get()`.

**Attributes:**
- `name: str` — Cell name.
- `run_result: Optional[CellRunResult]` — Run metadata (set after `Brig.run()`, `None` for `cell()`/`get()`).

### `wait()`

```python
async def wait(self, timeout: str = None) -> int
```

Block until cell exits. Returns the cell's exit code.

**Raises:** `BrigError` on failure.

**Sync variant:** `wait_sync(timeout: str = None) -> int`

### `stop()`

```python
async def stop(self) -> None
```

Gracefully stop the cell (SIGTERM).

**Sync variant:** `stop_sync() -> None`

### `kill()`

```python
async def kill(self) -> None
```

Immediately kill the cell (SIGKILL).

**Sync variant:** `kill_sync() -> None`

### `rm()`

```python
async def rm(self, force: bool = False, purge: bool = False) -> None
```

Remove the cell. Idempotent: does not raise if already gone.

| Parameter | Default | Description                       |
|-----------|---------|-----------------------------------|
| `force`   | `False` | Force remove even if running      |
| `purge`   | `False` | Also remove workspace directory   |

**Sync variant:** `rm_sync(force: bool = False, purge: bool = False) -> None`

### `logs()`

```python
async def logs(self, follow: bool = False, tail: int = None)
```

Get cell logs.

- `follow=False` — Returns log text as `str` (awaitable).
- `follow=True` — Returns an async iterator yielding log lines.

**Sync variant:** `logs_sync(follow: bool = False, tail: int = None) -> str` (only supports `follow=False`).

### `is_alive()`

```python
async def is_alive(self) -> bool
```

Check if the cell is still running.

### `cp_in()`

```python
async def cp_in(self, local_path: str, cell_path: str) -> None
```

Copy a file from local filesystem into the cell workspace.

**Sync variant:** `cp_in_sync(local_path, cell_path) -> None`

### `cp_out()`

```python
async def cp_out(self, cell_path: str, local_path: str) -> None
```

Copy a file from cell workspace to local filesystem.

**Sync variant:** `cp_out_sync(cell_path, local_path) -> None`

### `events()`

```python
async def events(self) -> AsyncGenerator[CellEvent]
```

Async generator yielding lifecycle events for this cell. Streams indefinitely until cancelled.

### `network_logs()`

```python
async def network_logs(self, follow: bool = True, tail: int = None) -> AsyncGenerator[dict]
```

Async generator yielding network activity logs (raw JSON dicts) for this cell.

### `stats()`

```python
async def stats(self) -> list[CellStats]
```

Get resource usage stats for this cell.

**Sync variant:** `stats_sync() -> list[CellStats]`

## `WardenHandle` Class

Accessible via `Brig().warden`.

### `status()`

```python
async def status(self) -> WardenStatus
```

Check if Warden proxy is running.

**Sync variant:** `status_sync() -> WardenStatus`

### `start()`

```python
async def start(self) -> None
```

Start the Warden proxy.

**Sync variant:** `start_sync() -> None`

### `stop()`

```python
async def stop(self) -> None
```

Stop the Warden proxy.

**Sync variant:** `stop_sync() -> None`

## Input Validation

The SDK validates all inputs before passing them to the CLI to prevent flag injection and catch errors early.

### Cell Name

Pattern: `^[a-zA-Z][a-zA-Z0-9_-]{0,62}$`

Must start with a letter, contain only alphanumeric characters, dashes, and underscores, and be at most 63 characters (DNS label limit).

### Environment Variable Keys

Pattern: `^[a-zA-Z_][a-zA-Z0-9_]*$`

Standard POSIX environment variable naming.

### Secret-in-Env Detection

Environment variable values are checked against known secret prefixes:

- `sk-`, `sk_` — API keys (OpenAI, Stripe, etc.)
- `ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_` — GitHub tokens
- `AKIA` — AWS access keys
- `xoxb-`, `xoxp-`, `xapp-` — Slack tokens
- `glpat-` — GitLab tokens
- `eyJ` — JWT-style base64 tokens

If detected, the SDK raises `BrigError` and directs the caller to use the `secrets` parameter instead. Secrets are mounted as files at `/run/secrets/`, never exposed as environment variables.

### Image Digest

Must start with `sha256:`. Verified against the local image before starting the cell.

### Profile Whitelist

Known profiles: `untrusted`, `supervised`, `dev`, `airgapped`, `honeypot`.

Unknown profile names raise `ProfileError` at the SDK layer before any CLI invocation.

### Flag Injection Prevention

All string parameters are checked to ensure they do not start with `-`, preventing CLI flag injection. The SDK also inserts `--` before the image name and command to separate flags from positional arguments.

## Security Model

### Canary Tokens

Canary tokens are passed to the CLI via a temporary file (`brig_canary_*.json`), not via command-line arguments. This prevents token exposure through `ps` output. The tempfile is deleted immediately after the CLI reads it, and the SDK cleans up on failure.

### Subprocess Isolation

The SDK communicates with the brig CLI exclusively via subprocess. It never imports brig internals, accesses container state directly, or modifies the filesystem. This preserves the security boundary: all policy enforcement, network isolation, and runtime checks happen inside the CLI and VM.

### Timeout

All subprocess calls have a default timeout of 300 seconds. The SDK raises `BrigError` on timeout and kills the subprocess.

### Error Redaction

When raising `BrigError`, the SDK only includes the binary name and subcommand in error messages (e.g., `brig run`), never the full argument list. This prevents accidental secret leakage in logs or stack traces.
