# Brig Reference

## CLI Reference

```
brig - Secure Workload Harness CLI

CELL MANAGEMENT:
  run         Run a cell (supports --profile, --timeout, --network none)
  stop        Stop a cell gracefully
  kill        Kill a cell immediately
  wait        Block until cell exits (returns exit code)
  rm          Remove a cell and its state
  start       Start a stopped cell
  list        List cells (--format json for structured output)

INSPECTION & INTERACTION:
  logs        View cell logs (stdout/stderr)
  network     View cell network activity
  events      Stream cell lifecycle events (JSON)
  files       List cell workspace
  cat         View file from workspace (safe, doesn't execute)
  cp          Copy file to/from workspace (validates paths)
  exec        Execute command in running cell
  inspect     Show cell details (runtime, network, mounts, secrets)
  stats       Show resource usage (--output json)

PERFORMANCE:
  pull        Pull and cache container image
  warmup      Pre-pull images for a profile
  checkpoint  Checkpoint running cell (CRIU)
  restore     Restore cell from checkpoint

SYSTEM:
  vm          Manage Lima VM
  init        Initialize brig (create directories, VM config)
  upgrade     Upgrade state to current schema
  verify      Verify security invariants
  diagnose    Diagnose connectivity issues
  health      Check system health
  config      Manage configuration
  policy      Manage cell network policies
  history     Show operation history
  metrics     Output Prometheus metrics
  tui         Interactive terminal UI
  secrets     List/validate secrets
```

### Run Flags

```
--name NAME          Cell name (required)
--image IMAGE        Container image
-f FILE              Load config from file (includes secrets declarations)
-d, --detach         Run in background
--rm                 Remove after exit
--timeout DURATION   Kill after duration (e.g., 30s, 5m, 2h, 1d)
--profile PROFILE    Trust profile (untrusted, supervised, dev, airgapped, honeypot)
--network MODE       Network mode: default or none (air-gapped)
--output FORMAT      Output format: text or json
--label KEY=VALUE    Add label for orchestration metadata
--memory SIZE        Memory limit (default: 2g)
--cpus N             CPU limit (default: 2)
--pids-limit N       PID limit (default: 512)
--policy-allow DOMAIN  Allow domain (adds to global policy)
--policy-deny DOMAIN   Deny domain (overrides global policy)
--verify-image       Verify image signature before running
--seccomp-profile F  Apply seccomp profile (JSON file)
--env KEY=VALUE      Set additional environment variable
--secret NAME        Mount secret file at /run/secrets/
--tor                Route through Tor (requires: warden tor start && warden restart)
```

### Wait Flags

```
brig wait <name>     Block until cell exits
--timeout DURATION   Maximum time to wait
--output FORMAT      Output format: text or json
```

### Secrets Commands

```
brig secrets list              List all secret files in ~/.brig/secrets/
brig secrets show SECRET       Show which cells use a secret
brig secrets validate CELL     Check if all secrets for a cell exist
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
brig vm status       Show VM status
brig vm shell        Open shell in VM
brig vm restart      Restart VM
brig vm recreate     Destroy and recreate VM (preserves macOS state)
brig vm logs         Show VM provisioning logs
```

---

## Warden CLI Reference

Warden is the egress proxy. All commands run inside the Lima VM (prefix with `brig vm shell --` from macOS).

### Lifecycle

```
warden start             Start the proxy container
warden stop              Stop the proxy container
warden restart           Stop then start (picks up config changes)
warden status            Show proxy status and IP addresses
```

### Policy

```
warden policy validate   Validate network-policy.json syntax
warden policy reload     Hot-reload policy without restarting proxy
warden policy show       Display current policy
```

### Monitoring

```
warden stats             Show request metrics (total, blocked, rate limited)
warden stats --json      JSON output for scripting
warden stats CELL        Filter metrics to a single cell
warden health            Health check (exit 0 = healthy)
warden logs [-f]         View proxy logs (follow with -f)
```

### Diagnostics

```
warden preflight         Run pre-start validation checks
warden watchdog          Auto-restart proxy on failure (used by systemd)
```

### Tor (Anonymous Egress)

```
warden tor start         Start Tor + Privoxy bridge
warden tor stop          Stop Tor + Privoxy, remove config
warden tor status        Show Tor routing chain and component status
```

After `warden tor start`, restart Warden to activate upstream routing: `warden restart`.

### Network Management

```
warden connect CELL      Connect proxy to a cell's network
warden reconnect         Reconnect proxy to all cell networks
```

### Workspace Commands

```
brig workspace list CELL        List files in workspace
brig workspace clean CELL       Delete all files in workspace
brig workspace size CELL        Show disk usage
```

### Diagnose Command

```
brig diagnose CELL              Run connectivity diagnostics

Output includes:
- Proxy status (running/stopped)
- Cell network attachment
- Last 5 blocked requests from proxy logs
- DNS resolution test
- Suggested fixes
```

### Examples

```bash
brig run --name x --image python:3.11-slim
brig run -f cells/my-cell.yaml -d
brig secrets validate my-cell
brig run --name test --profile untrusted -- curl https://google.com
brig logs x -f
brig network x --json | jq 'select(.blocked)'
brig cp --sanitize x:/work/report.html ./report.html
brig stop x
brig vm recreate
brig diagnose x
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

### Tor Routing

```yaml
name: anon-agent
image: python:3.11-slim
tor: true  # Pre-flight check that Tor stack + Warden upstream are active
command: ["python", "/work/agent.py"]
```

### MITM Inspection

```yaml
name: debug-cell
image: python:3.11-slim
mitm: true  # Triggers CA mount and trust setup
```

---

## Trust Profiles

Built-in profiles set defaults for resource limits, network mode, and policy.
CLI flags override profile defaults.

| Profile | Runtime | Network | Resources | Use case |
|---------|---------|---------|-----------|----------|
| `untrusted` | gVisor | Explicit allowlist | 512MB, 1 CPU, 256 PIDs | Unknown/hostile code |
| `supervised` | gVisor | Broad allowlist | 2GB, 2 CPU, 512 PIDs | AI agents, CI/CD |
| `dev` | gVisor | All egress, logged | 4GB, 4 CPU, 2048 PIDs | Your own code |
| `airgapped` | gVisor | None (`--network none`) | 2GB, 2 CPU, 512 PIDs | Pure compute |
| `honeypot` | gVisor | Connected, deny all | 1GB, 1 CPU, 256 PIDs | Behavior analysis |

Usage: `brig run --profile supervised --name agent-a python:3.12`

Custom profiles: Place YAML files in `~/.brig/profiles/`.

---

## Python SDK

```python
from brig.sdk import Brig

b = Brig()

# Launch a cell
cell = await b.run(
    name="agent-a", image="python:3.12",
    command=["python", "agent.py"],
    profile="supervised",
    policy_allow=["api.openai.com"],
    secrets=["openai-key"],
    timeout="2h",
)

# Wait for completion
result = await cell.wait()  # CellResult(exit_code=0)

# Transfer files
await cell.cp_in("input.json", "/work/input.json")
await cell.cp_out("/work/output.json", "output.json")

# Stream events
async for event in cell.events():
    print(f"{event.action}: {event.cell}")

# Pipe data between cells (via host, preserving isolation)
await b.pipe(cell_a, "/output.json", cell_b, "/input.json")

# Sync wrappers available for non-async code
cell = b.run_sync(name="test", image="alpine", command=["echo", "hi"])
result = cell.wait_sync()
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
├── cells/                    # Cell definitions
│   ├── network-policy.json   # Allowlist (mounted as /policy.json in VM)
│   ├── research-agent.yaml
│   └── github-bot.yaml
├── profiles/                 # Trust profiles (custom)
│   └── custom.yaml           # User-defined profile
├── secrets/                  # Single-value secret files
│   ├── openai-key.txt        # Contains just: sk-...
│   ├── anthropic-key.txt     # Contains just: sk-ant-...
│   ├── github-token.txt      # Contains just: ghp_...
│   └── db-password.txt       # Contains just: hunter2
└── state/                    # Cell state (workspaces, logs)
    ├── system/               # System state (survives VM recreate)
    │   ├── subnets.json      # Subnet allocator persistent state
    │   └── checkpoints/      # Cell checkpoints (CRIU)
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

- Brig does not prevent exfiltration to allowed domains
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
brig run --name my-cell --memory=4g --cpus=4 --image python:3.11-slim
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

## `brig cp` Safety Rules

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

## Warden Tor Commands

```
warden tor start     Start Tor + Privoxy bridge on proxy-external network
warden tor stop      Stop Tor + Privoxy and remove config
warden tor status    Show Tor stack status and routing chain
```

After `warden tor start`, restart Warden to activate upstream routing: `warden restart`.
After `warden tor stop`, restart Warden to disable upstream routing: `warden restart`.

### Components

| Container | Port | Role |
|-----------|------|------|
| `warden-tor` | 9050 | Tor SOCKS5 proxy |
| `warden-privoxy` | 8118 | HTTP→SOCKS5 bridge |
| `warden` | 8080 | Policy-enforcing mitmproxy (chains to Privoxy when Tor active) |

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
