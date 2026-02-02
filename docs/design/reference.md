# Cell Reference

## CLI Reference

```
cell - Secure Workload Harness CLI

COMMANDS:
  run         Run a cell
  verify      Verify invariants (networks, proxy, runtime)
  stop        Stop a cell gracefully
  kill        Kill a cell immediately
  rm          Remove a cell and its state
  list        List cells (shows runtime, network, status)
  start       Start a stopped cell

  logs        View cell logs (stdout/stderr)
  network     View cell network activity
  files       List cell workspace
  cat         View file from workspace (safe, doesn't execute)
  cp          Copy file to/from workspace (validates paths)
  exec        Execute command in running cell
  inspect     Show cell details (runtime, network, mounts, secrets)

  proxy       Manage proxy service
  vm          Manage Lima VM
  workspace   Manage cell workspaces
  secrets     List/validate secrets

  diagnose    Diagnose connectivity issues
  test        Run verification tests
```

### Run Flags

```
--name NAME          Cell name (required)
--image IMAGE        Container image
-f FILE              Load config from file (includes secrets declarations)
-d, --detach         Run in background
--rm                 Remove after exit
--timeout DURATION   Kill after duration (e.g., 1h, 30m)
--restart POLICY     Restart policy (no, on-failure, unless-stopped, always)
--runtime RUNTIME    Container runtime (runsc default, runc requires --unsafe)
--unsafe             Allow dangerous operations (required for --runtime=runc)
--no-proxy-env       Don't set HTTP_PROXY/HTTPS_PROXY (for testing)
--env KEY=VALUE      Set additional environment variable
```

### Secrets Commands

```
brig secrets list              List all secret files in ~/.brig/secrets/
cell secrets show SECRET       Show which cells use a secret
cell secrets validate CELL     Check if all secrets for a cell exist
```

### CP Flags

```
--sanitize           Block dangerous file types (deterministic, no prompts)
--allow-scripts      Allow .sh/.py/.js/.rb/.pl with --sanitize
--allow-office       Allow .docx/.xlsx/.pptx/.pdf with --sanitize
--force              Skip safety checks (dangerous)
--follow-symlinks    Follow symlinks (default: skip with warning)
```

### VM Commands

```
cell vm status       Show VM status
cell vm shell        Open shell in VM
cell vm restart      Restart VM
cell vm recreate     Destroy and recreate VM (preserves macOS state)
cell vm logs         Show VM provisioning logs
```

### Workspace Commands

```
cell workspace list CELL        List files in workspace
cell workspace clean CELL       Delete all files in workspace
cell workspace size CELL        Show disk usage
```

### Diagnose Command

```
cell diagnose CELL              Run connectivity diagnostics

Output includes:
- Proxy status (running/stopped)
- Cell network attachment
- Last 5 blocked requests from proxy logs
- DNS resolution test
- Suggested fixes
```

### Examples

```bash
cell run --name x --image python:3.11-slim
cell run -f cells/my-cell.yaml -d
cell secrets validate my-cell
cell run --name test --no-proxy-env -- curl https://google.com
cell logs x -f
cell network x --json | jq 'select(.blocked)'
cell cp --sanitize x:/work/report.html ./report.html
cell stop x
cell vm recreate
cell diagnose x
```

---

## Cell Definition YAML Schema

### Basic Example

```yaml
name: research-agent
image: python:3.11-slim

# Restart policy for long-running cells
restart: unless-stopped    # always | unless-stopped | on-failure | no

# Optional: kill after duration (omit for continuous cells)
# timeout: 1h

# Regular environment variables
env:
  TASK_ID: "12345"
  DEBUG: "true"

# Secrets - explicitly declare which secrets this cell needs
secrets:
  - openai-key              # → Env: OPENAI_KEY_FILE
  - anthropic-key           # → Env: ANTHROPIC_KEY_FILE

files:
  - ./task.json:/work/task.json
  - ./config/:/work/config/:ro

command: ["python", "/work/main.py"]
```

### Custom Secret Env Var Names

```yaml
secrets:
  - openai-key                      # → OPENAI_KEY_FILE
  - name: anthropic-key
    as: ANTHROPIC_API_KEY_FILE      # → ANTHROPIC_API_KEY_FILE
  - name: db-password
    as: DATABASE_PASSWORD_FILE      # → DATABASE_PASSWORD_FILE
```

### Resource Limits

```yaml
resources:
  memory: 4g      # Override default 2g
  cpus: 4         # Override default 2
  pids: 1024      # Override default 512
  nofile: 8192    # Override default 4096 (file descriptors)
```

### Health Checks

```yaml
# For cells that run internal HTTP services
healthcheck:
  type: http  # or 'process'
  command: ["curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

```yaml
# For batch jobs or non-server workloads
healthcheck:
  type: process
  command: ["pgrep", "-f", "my-worker-process"]
  interval: 30s
```

### Restart Policy with Backoff

```yaml
restart: on-failure
restart_max_attempts: 3  # Stop trying after 3 failures
restart_window: 300s     # Reset failure count after 5 minutes
```

### MITM Inspection

```yaml
name: debug-cell
image: python:3.11-slim
mitm: true  # Triggers CA mount and trust setup
```

---

## Network Policy YAML Schema

```yaml
default: deny

allow:
  - pypi.org
  - "*.pythonhosted.org"
  - github.com
  - "*.githubusercontent.com"
  - api.openai.com
  - api.anthropic.com

deny:
  - pastebin.com
  - "*.ngrok.io"
```

### Pattern Matching

- Exact match: `github.com`
- Wildcard suffix: `*.github.com` (matches `api.github.com`, NOT `evilgithub.com`)

**Enforcement:** Domain allowlists are enforced using the hostname/SNI observed by the proxy. Direct IP connections are blocked.

---

## Directory Layout

```
~/.brig/
├── lima.yaml                 # VM config
├── network-policy.yaml       # Allowlist
├── cells/                    # Cell definitions
│   ├── research-agent.yaml
│   └── github-bot.yaml
├── secrets/                  # Single-value secret files
│   ├── openai-key.txt        # Contains just: sk-...
│   ├── anthropic-key.txt     # Contains just: sk-ant-...
│   ├── github-token.txt      # Contains just: ghp_...
│   └── db-password.txt       # Contains just: hunter2
└── state/                    # Cell state (workspaces, logs)
    ├── system/               # System state (survives VM recreate)
    │   └── subnets.json      # Subnet allocator persistent state
    ├── cell-abc123/
    │   ├── workspace/        # Cell's files
    │   ├── stdout.log
    │   └── stderr.log
    └── cell-def456/
        └── ...
```

**Secrets model:** One file = one secret. Cells explicitly declare which secrets they need. No implicit loading.

**Network logs:** Stored in `/var/log/cells/network/` inside the VM (not in cell state directories) to limit proxy filesystem access.

**Reserved subnets:** Index 0 (`10.60.0.0/24`) is reserved for future use. Cell subnets start at index 1.

---

## Secrets Management

### Directory Structure (macOS)

```
~/.brig/secrets/
├── openai-key.txt        # Contains just: sk-...
├── anthropic-key.txt     # Contains just: sk-ant-...
├── github-token.txt      # Contains just: ghp_...
└── db-password.txt       # Contains just: hunter2
```

**One file = one secret.** No parsing, no multi-value files.

### How Secrets Are Mounted

For a cell that declares `openai-key`:

- Host (macOS): `~/.brig/secrets/openai-key.txt`
- Guest (Lima VM): same path (via Lima mount)
- Container: `/run/secrets/openai-key` (read-only)

**Conventions:**
- Container secret paths are always `/run/secrets/<secret-name>`
- The runner adds `<NAME>_FILE=/run/secrets/<secret-name>` env vars
- The runner **never** puts secret values in env vars

### Secrets Non-goals

- Cell does not prevent exfiltration to allowed domains
- Secrets are readable by root inside the container
- No per-process isolation within a cell

---

## Resource Limits

### Default Container Limits

```bash
--memory=2g --pids-limit=512 --cpus=2 --ulimit nofile=4096:4096
```

### Proxy Limits

```bash
PROXY_MEMORY="1g"
PROXY_CPUS="1"
PROXY_PIDS="256"
PROXY_NOFILE="8192"
```

### Override via CLI

```bash
cell run --name my-cell --memory=4g --cpus=4 --image python:3.11-slim
```

---

## Subnet Allocator

Each cell network gets a unique /24 subnet for attribution.

### State Files

**Allocation state:** `/state/system/subnets.json` (persistent)

```json
{
  "next_index": 4,
  "allocated": {
    "cell-abc123": {"subnet": "10.60.1.0/24", "created": "2026-02-01T10:00:00Z"},
    "cell-def456": {"subnet": "10.60.2.0/24", "created": "2026-02-01T10:05:00Z"}
  },
  "freed": []
}
```

**Runtime mapping:** `/var/run/cells/subnet-map.json` (read by proxy)

```json
{
  "10.60.1.0/24": "cell-abc123",
  "10.60.2.0/24": "cell-def456"
}
```

### Limits

- Subnet range: `10.60.1.0/24` through `10.60.254.0/24`
- Maximum cells: 254 concurrent
- Index 0 reserved for future use

---

## Log Format

### Network Logs (JSONL)

```json
{"ts":"2026-02-01T10:00:00Z","cell":"my-cell","method":"GET","url":"https://api.github.com/user","status":200,"ms":145}
{"ts":"2026-02-01T10:00:01Z","cell":"my-cell","method":"POST","url":"https://pastebin.com","status":403,"blocked":true}
```

### Log Rotation

Configured automatically during VM provisioning:

```
# Cell logs - daily, 7 rotations, 100MB max
/state/*/stdout.log /state/*/stderr.log

# Network logs - daily, 7 rotations, 100MB max, SIGHUP to proxy
/var/log/cells/network/*.jsonl
```

---

## `cell cp` Safety Rules

### Symlink Handling

| Behavior | Default | Flag |
|----------|---------|------|
| Follow symlinks | No | `--follow-symlinks` |
| Copy symlinks as-is | No | Skipped |
| Warn on symlinks | Yes | Shows warning |

### Path Validation

- No path traversal (`..`)
- No absolute paths in archive
- No special files (devices, FIFOs, sockets)
- Destination must be in allowed directory

### `--sanitize` Behavior

| Action | File Types | Behavior |
|--------|------------|----------|
| **Block (hard)** | `.app`, `.command`, `.scpt`, `.dmg`, `.pkg`, `.webloc`, `.jar`, `.exe` | Refuse, exit non-zero |
| **Block (soft)** | `.docx`, `.xlsx`, `.pptx`, `.pdf` | Refuse unless `--allow-office` |
| **Block (scripts)** | `.sh`, `.py`, `.js`, `.rb`, `.pl` | Refuse unless `--allow-scripts` |
| **Allow** | `.txt`, `.json`, `.csv`, `.md`, `.xml`, `.yaml`, `.log` | Copy directly |
| **Allow (images)** | `.png`, `.jpg`, `.gif`, `.svg`, `.webp` | Copy directly |

---

## What Survives Lima VM Restart

| Data | Survives? | Location |
|------|-----------|----------|
| Cell workspaces | Yes | `~/.brig/state/` on Mac |
| Cell logs | Yes | Same |
| Network logs | Yes | Same |
| Cell configs | Yes | `~/.brig/cells/` on Mac |
| Secrets | Yes | `~/.brig/secrets/` on Mac |
| Proxy config | Yes | Mounted from Mac |
| Subnet allocator state | Yes | `/state/system/subnets.json` |
| **Running containers** | No | Must restart |
| **Cell networks** | No | Recreated on cell start |
| **Runtime subnet map** | No | Rebuilt from allocator state |
