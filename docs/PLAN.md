# Cell Implementation Plan

Full development roadmap for Cell - Secure Workload Harness.

## Overview

Cell is a secure, observable harness for running untrusted code on macOS. This plan covers implementation from foundation through production-ready.

---

## Test-Driven Development Approach

Every milestone follows TDD principles:

1. **Write tests first** - Before implementing a feature, write the test that verifies it works
2. **Tests live in `tests/`** - One test file per milestone: `test_milestone0.sh`, `test_milestone1.sh`, etc.
3. **Red-green-refactor** - Test fails → implement → test passes → clean up
4. **Security invariants are tests** - Each security property has a corresponding verification test
5. **No code without coverage** - If it's not tested, it doesn't exist

### Test Categories

| Category | Purpose | When to run |
|----------|---------|-------------|
| Self-tests | Embedded in provisioning, fail VM creation if broken | VM start |
| Unit tests | Pure functions (path validation, subnet allocation) | Every change |
| Integration tests | Component interaction (proxy + cell + network) | Per milestone |
| Security tests | Verify invariants hold under adversarial conditions | Before merge |

### TDD Per Milestone

Test files named by functionality, not milestone number:

- **Milestone 0**: `tests/test_vm_foundation.sh` - VM structure, gVisor, networks, firewall
- **Milestone 1**: `tests/test_cell_lifecycle.sh` - Cell run/stop/kill/rm operations
- **Milestone 2**: `tests/test_subnet_allocator.sh` - Subnet allocation, network isolation
- **Milestone 3**: `tests/test_proxy_policy.sh` - Policy enforcement, logging, egress control
- **Milestone 4**: `tests/test_secrets.sh` - Secrets handling, workspace isolation
- **Milestone 5**: `tests/test_observability.sh` - Diagnostic and monitoring commands
- **Milestone 6**: `tests/test_hardening.sh` - Resource limits, security hardening
- **Milestone 7**: `tests/test_all.sh` - Full verification suite

---

## TODO: Rigorous Testing Infrastructure

**Priority: Design before Milestone 1 implementation**

Before proceeding with feature development, establish:

1. **CI Architecture**
   - Self-hosted macOS runner strategy (MacStadium, EC2 Mac, or Cirrus CI)
   - Cost/benefit analysis for test frequency
   - VM caching strategy for faster test runs

2. **Test Harness**
   - Common test utilities (log_pass, log_fail, cleanup)
   - Fixture management (create/destroy test cells, networks)
   - Parallel test execution where safe

3. **Security Test Framework**
   - Adversarial test patterns (escape attempts, policy bypass)
   - Fuzzing inputs (malformed YAML, path traversal attempts)
   - Regression tests for any security fixes

4. **Dependency Pinning**
   - Pin Lima version in tests
   - Pin Ubuntu image by SHA256
   - Pin gVisor version
   - Automated alerts for upstream security updates

5. **Test Coverage Goals**
   - 100% of security invariants
   - All error paths (not just happy path)
   - Boundary conditions (max cells, full disk, OOM)

6. **Documentation**
   - How to run tests locally
   - How to add new tests
   - How to debug test failures

This section will be expanded into a full testing specification before Milestone 1.

---

## Milestone 0: Foundation ✓

Establish the base infrastructure. **COMPLETED**

### 0.1 Lima VM Configuration

**File:** `~/.brig/lima.yaml`

- [x] Configure VZ backend (Apple Virtualization.framework)
- [x] Set resource limits (CPU, memory, disk)
- [x] Configure mounts:
  - `~/.brig/state` → `/state` (writable)
  - `~/.brig/secrets` → `/secrets` (read-only)
  - `~/.brig/cells` → `/cells` (read-only)
- [x] Select Ubuntu 24.04 cloud image
- [x] Disable IPv6

### 0.2 VM Provisioning Script

**In:** `lima.yaml` provision section

- [x] Install packages: Podman, iptables, curl, jq
- [x] Install gVisor (runsc)
- [x] Configure Podman for rootful mode
- [x] Set gVisor as default runtime in `containers.conf`
- [x] Create `proxy-external` network
- [x] Configure mount security (`/cells` as noexec)
- [x] Create runtime directories:
  - `/var/run/brig/`
  - `/var/log/brig/network/`
  - `/state/system/`
- [x] Initialize subnet allocator state

### 0.3 Self-Tests in Provisioning

- [x] Test 1: East-west isolation (two internal networks can't communicate)
- [x] Test 2: Internal network has no internet
- [x] Test 3: External network has internet
- [x] Test 4: gVisor is working

---

## Milestone 1: Core CLI ✓

Basic cell lifecycle management. **COMPLETED**

### 1.1 `brig run`

- [x] Parse cell definition YAML
- [x] Verify proxy is running (fail-fast)
- [x] Allocate subnet for cell
- [x] Create internal network
- [x] Connect proxy to cell network
- [x] Mount secrets (file-based, not env vars)
- [x] Mount workspace
- [x] Set proxy environment variables
- [x] Start container with gVisor
- [x] Verify runtime is actually runsc (via `brig verify`)
- [x] Support `-d` (detach) flag
- [x] Support `--rm` flag
- [x] Support `--timeout` flag
- [x] Support inline `--image` and `--env`

### 1.2 `brig stop`

- [x] Graceful stop with SIGTERM
- [x] Wait for container to exit
- [x] Timeout and SIGKILL if needed

### 1.3 `brig kill`

- [x] Immediate SIGKILL

### 1.4 `brig rm`

- [x] Stop container if running
- [x] Disconnect proxy from network
- [x] Remove network
- [x] Free subnet allocation
- [x] Update subnet map
- [x] Optionally remove workspace (`--purge`)

### 1.5 `brig list`

- [x] Show all cells
- [x] Display: name, status, runtime, image
- [x] Format options: table, json

### 1.6 `brig logs`

- [x] Stream stdout from `/state/{cell}/stdout.log`
- [x] Support `--stderr` for stderr
- [x] Support `--all` for both
- [x] Support `-f` (follow)
- [x] Support `--tail N`

### 1.7 `brig start`

- [x] Start a stopped cell
- [x] Verify proxy is running first
- [x] Recreate network if needed

---

## Milestone 2: Network Isolation ✓

Per-cell network isolation with subnet allocation. **COMPLETED**

### 2.1 Per-Cell Network Creation

- [x] Create network with `--internal` flag
- [x] Assign explicit subnet from allocator
- [x] Verify network has no external route (via `brig verify`)

### 2.2 Subnet Allocator

**Files:**
- `/state/system/subnets.json` (persistent)
- `/var/run/brig/subnet-map.json` (runtime)

- [x] Allocate from `10.60.1.0/24` through `10.60.254.0/24`
- [x] Reserve index 0 for future use
- [x] Implement file locking for concurrent access
- [x] Track allocated subnets with timestamps
- [x] Track freed subnets for reuse
- [x] Enforce bounds (max 254 cells)
- [x] Atomic writes (write to temp, rename)

### 2.3 Subnet Map for Proxy

- [x] Generate mapping: subnet → cell name
- [x] Atomic updates on allocation/free
- [x] Hot-reload support (proxy watches file mtime)

### 2.4 Proxy Network Joining ✓

- [x] Connect proxy to each cell's network on cell creation
- [x] Disconnect proxy on cell removal
- [x] Rebuild connections on proxy restart

---

## Milestone 3: Proxy & Policy ✓

mitmproxy-based proxy with policy enforcement and logging. **COMPLETED**

### 3.1 Proxy Container Setup

**Tool:** `warden` CLI (`warden.py`)

- [x] Pin mitmproxy image by tag (digest pinning deferred)
- [ ] Run as non-root user (1000:1000) - deferred to Milestone 6
- [ ] Apply security hardening - deferred to Milestone 6:
  - `--read-only`
  - `--security-opt=no-new-privileges`
  - `--cap-drop=ALL`
- [x] Mount volumes:
  - `/var/log/brig/network` → `/logs`
  - `/var/run/brig` → `/var/run/cells` (ro)
  - `/cells/addons` → `/addons` (ro)
  - `/cells/network-policy.json` → `/policy.json` (ro)
- [x] Set resource limits (memory, CPU, PIDs)

### 3.2 Policy Enforcement Addon

**File:** `~/.brig/cells/addons/enforce.py`

- [x] Load policy from JSON
- [x] Block non-80/443 ports
- [x] Block literal IP addresses
- [x] Block internal IP ranges:
  - RFC1918 (10/8, 172.16/12, 192.168/16)
  - Localhost (127/8)
  - Link-local (169.254/16)
  - CGNAT (100.64/10)
  - Benchmarking (198.18/15)
  - Reserved (240/4)
- [x] Implement allowlist matching:
  - Exact match: `github.com`
  - Wildcard suffix: `*.github.com` (dot-boundary)
- [x] Check denylist before allowlist
- [x] Validate Host header matches request
- [x] Default deny on policy load error
- [x] Per-cell policy support

### 3.3 Logging Addon

**File:** `~/.brig/cells/addons/logger.py`

- [x] Load subnet map
- [x] Hot-reload on file mtime change
- [x] Resolve client IP to cell name
- [x] Log entry format (JSONL):
  - `ts`: timestamp
  - `cell`: cell name
  - `src_ip`: client IP
  - `method`: HTTP method
  - `host`: hostname
  - `path`: request path
  - `status`: HTTP status
  - `bytes`: response size
  - `ms`: latency
  - `blocked`: boolean
- [x] Use file locking for concurrent-safe writes
- [x] Write to per-cell log files
- [x] Handle unknown sources (log to `unknown.jsonl`)

### 3.4 VM-Level Egress Firewall

**In:** Lima provisioning

- [x] Create PROXY_EGRESS iptables chain
- [x] Allow ESTABLISHED/RELATED
- [x] Block internal ranges (BEFORE port allows)
- [x] Allow ports 80, 443
- [x] Allow DNS (53/udp, 53/tcp)
- [x] Default DROP
- [x] Apply to FORWARD from proxy-external
- [x] Persist with iptables-persistent

### 3.5 Proxy Systemd Service

**File:** `~/.brig/cells/warden.service`

- [x] Service file created (manual installation required)
- [ ] Auto-install during VM provisioning

### 3.6 Policy Hot-Reload

- [x] `warden reload` sends SIGHUP
- [x] Addon reloads policy file
- [x] Log reload event with rule counts

---

## Milestone 4: Secrets & State ✓

Secure secrets handling and workspace management. **COMPLETED**

### 4.1 Secrets Directory Structure ✓

**macOS:** `~/.brig/secrets/`

- [x] One file per secret (e.g., `openai-key.txt`)
- [x] No parsing, no multi-value files
- [x] Mount read-only into VM at `/secrets/`

### 4.2 Secret Mounting in Cells ✓

- [x] Parse `secrets:` from cell definition
- [x] For each declared secret:
  - Verify file exists
  - Mount at `/run/secrets/{name}`
  - Set `{NAME}_FILE` env var pointing to path
- [x] Never put secret values in env vars

### 4.3 Workspace Isolation ✓

- [x] Each cell gets unique workspace directory
- [x] Mount at `/work` inside container
- [x] Cells cannot see other cells' workspaces
- [x] Workspace persists across cell restarts

### 4.4 State Persistence ✓

- [x] Cell stdout/stderr logs
- [x] Workspace files
- [x] Subnet allocator state
- [x] All in `~/.brig/state/` on macOS
- [x] Survives VM restart/recreate

---

## Milestone 5: Observability ✓

Tools for monitoring and debugging cells. **COMPLETED**

### 5.1 `brig network`

- [x] Read from `/var/log/brig/network/{cell}.jsonl`
- [x] Support `-f` (follow)
- [x] Support `--json` for raw output
- [x] Support filtering (blocked only)

### 5.2 `brig files`

- [x] List workspace contents
- [x] Support subdirectory argument
- [x] Show file sizes and dates

### 5.3 `brig cat`

- [x] View file contents (safe, doesn't execute)
- [x] Path validation (no traversal)

### 5.4 `brig cp`

- [x] Copy files to/from workspace
- [x] Path validation:
  - No `..` traversal
  - No absolute paths
  - Normalize and verify within workspace
- [x] Symlink handling (skip with warning)
- [x] `--sanitize` mode with extension blocking
- [x] `--allow-scripts` and `--allow-office` flags
- [x] `--force` mode
- [x] Deterministic behavior (no prompts)

### 5.5 `brig diagnose`

- [x] Check proxy status
- [x] Check cell network attachment
- [x] Show last blocked requests
- [x] Suggest fixes based on findings

### 5.6 `brig verify`

- [x] Check proxy is running
- [x] Check proxy is on proxy-external
- [x] Check cells are single-homed (one network only)
- [x] Check gVisor runtime is active
- [x] Check networks are internal
- [x] Exit non-zero on any failure

### 5.7 `brig exec`

- [x] Execute command in running cell
- [x] Support interactive mode (`-it`)

### 5.8 `brig inspect`

- [x] Show cell details
- [x] Runtime, network, mounts, resources
- [x] Format options (json, custom template)

### 5.9 `brig stats`

- [x] Show resource usage (CPU, memory, PIDs)
- [x] Support all cells or specific cell

---

## Milestone 6: Hardening ✓

Production hardening features. **COMPLETED**

### 6.1 Proxy Resource Limits ✓

- [x] Memory: 1g
- [x] CPU: 1
- [x] PIDs: 256
- [ ] nofile: 8192

### 6.2 Cell Resource Limits ✓

- [x] Default: 2g memory, 2 CPU, 512 PIDs
- [x] Configurable per-cell (via cell definition YAML)
- [x] CLI override flags (`--memory`, `--cpus`, `--pids-limit`)

### 6.3 Log Rotation ✓

- [x] Log rotation config created (`~/.brig/cells/brig-logrotate.conf`)
- [ ] Auto-install during VM provisioning

### 6.4 macOS State Protection ✓

- [x] Quarantine attribute support (via `brig run --quarantine`)
- [x] Documentation in security.md

### 6.5 Proxy Hardening ✓

- [x] No new privileges (`--security-opt no-new-privileges`)
- [x] Drop all capabilities (`--cap-drop ALL`)
- [x] Bypass entrypoint to avoid privilege escalation (`--entrypoint mitmdump`)
- [ ] Read-only root filesystem (incompatible with mitmproxy image)

### 6.6 Image Provenance ✓

- [x] Pin proxy image by digest
- [x] Document update process
- [x] Never use `:latest` in production

---

## Milestone 7: Testing & Verification ✓

Comprehensive test suite. **COMPLETED**

### 7.1 Provisioning Self-Tests ✓

- [x] East-west isolation
- [x] Internal network has no internet
- [x] External network has internet
- [x] gVisor is working

### 7.2 Verification Test Suite ✓

Test files implemented in `tests/`:

| Test File | Coverage |
|-----------|----------|
| `test_vm_foundation.sh` | VM structure, gVisor, networks, firewall (22 tests) |
| `test_cell_lifecycle.sh` | Cell run/stop/kill/rm operations (22 tests) |
| `test_subnet_allocator.sh` | Subnet allocation, network isolation (21 tests) |
| `test_proxy_policy.sh` | Policy enforcement, logging, egress control |
| `test_secrets.sh` | Secrets handling, workspace isolation |
| `test_observability.sh` | Diagnostic and monitoring commands |
| `test_hardening.sh` | Resource limits, security hardening |
| `test_per_cell_policy.sh` | Per-cell network policies |
| `test_all.sh` | Full verification suite runner |

Security invariants covered:
- [x] Test: Cell can't reach internet directly
- [x] Test: Cell CAN reach internet via proxy
- [x] Test: Blocked domain is blocked
- [x] Test: Cell isolation (files, processes)
- [x] Test: gVisor is active
- [x] Test: No east-west traffic
- [x] Test: Default runtime check
- [x] Test: IPv6 is disabled
- [x] Test: Subnet allocator bounds

### 7.3 `brig verify` Command ✓

- [x] Checks proxy status
- [x] Checks proxy network attachment
- [x] Checks cells are single-homed
- [x] Checks gVisor runtime is active
- [x] Checks networks are internal
- [x] Exit non-zero on any failure

### 7.4 CI Integration

- [x] Test scripts runnable from macOS
- [ ] GitHub Actions workflow (future)
- [ ] Automated VM setup for CI runners (future)

---

## Implementation Order

Recommended sequence:

1. **Milestone 0** - Foundation (Lima config, provisioning)
2. **Milestone 2.1-2.3** - Network isolation (critical path)
3. **Milestone 3** - Proxy (enables network access)
4. **Milestone 1** - Core CLI (depends on network and proxy)
5. **Milestone 4** - Secrets & state
6. **Milestone 5** - Observability
7. **Milestone 6** - Hardening
8. **Milestone 7** - Testing

---

## Dependencies

### External

- Lima 0.18+
- Podman 4.0+ with netavark
- gVisor (runsc)
- mitmproxy

### Internal

- Subnet allocator must work before `cell run`
- Proxy must work before cells can have network
- Policy enforcement must work before cells are useful

---

## File Manifest

### macOS Files

```
~/.brig/
├── lima.yaml                 # VM configuration
├── network-policy.yaml       # Proxy policy
├── cells/                    # Cell definitions
│   └── addons/              # Proxy addons
│       ├── enforce.py
│       └── logger.py
├── secrets/                  # Secret files
└── state/                    # Cell state
    └── system/
        └── subnets.json
```

### VM Files

```
/etc/
├── containers/containers.conf.d/gvisor.conf
├── systemd/system/cell-proxy.service
├── logrotate.d/cells
└── sysctl.d/99-disable-ipv6.conf

/usr/local/bin/
├── cell-proxy-start.sh
├── cell-proxy-preflight.sh
└── cell-rebuild-subnet-map.sh

/var/
├── run/cells/
│   ├── subnet-map.json
│   └── allocator.lock
└── log/cells/
    ├── network/
    │   └── {cell}.jsonl
    └── proxy.log
```

---

## Sprint 2: Improvements

Post-MVP enhancements for performance, functionality, and polish.

### 8.1 Per-Cell Network Policies ✓

**Priority: High** - Enables true multi-tenant workloads. **COMPLETED**

- [x] Cell definition YAML with `policy:` section
- [x] Per-cell allowlist overrides global policy
- [x] Policy stored in `/var/run/brig/policies/{cell}.json`
- [x] Logger addon reads cell-specific policy
- [x] Enforce addon checks cell policy first, then global
- [x] `brig policy show <name>` displays effective policy
- [x] `brig policy set <name> --allow <domain>` updates policy

### 8.2 Performance Optimizations (Partial) ✓

**Priority: High** - Critical for usability at scale.

- [x] Cache proxy status (TTL-based, avoid repeated `podman ps`)
- [x] Cache cell exists/running checks (TTL-based with invalidation)
- [x] Batch podman inspect calls where possible
- [x] Use single `podman ps --format` for `brig list`
- [x] Stream network logs (using tail -f for follow mode)
- [x] Lazy-load cell state (don't inspect unless needed)
- [ ] Connection pooling for podman API (if switching to API)

### 8.3 Additional Commands ✓

**Priority: Medium** - Feature completeness. **MOSTLY COMPLETE**

- [x] `brig attach` - Interactive session to running cell
- [x] `brig top` - Show processes inside cell
- [x] `brig diff` - Show filesystem changes from base image
- [x] `brig stats` - Real-time resource usage
- [x] `brig pause/unpause` - Suspend and resume cells
- [x] `brig cp` - Copy files with sanitization
- [x] `brig files` - List workspace contents
- [x] `brig cat` - Safe file viewing

### 8.4 Cell Definition Files ✓

**Priority: Medium** - Declarative configuration. **COMPLETED**

- [x] YAML schema for cell definitions
- [x] `brig run -f cell.yaml` to create from file
- [x] Support for: image, command, env, secrets, resources, policy
- [x] `brig export <name>` - Export running cell as YAML
- [x] Validation of cell definitions before run

### 8.5 Code Architecture Refactor ✓

**Priority: Medium** - Maintainability. **COMPLETED**

- [x] Split brig.py into modules (package structure created):
  - `brig/__init__.py` - Package init
  - `brig/config.py` - Configuration constants
  - `brig/utils.py` - Utility functions (logging, caching, helpers)
  - `brig/container.py` - Container operations (Spinner, cell helpers)
  - `brig/commands/*.py` - Command stubs (ready for incremental migration)
- [x] Add structured logging with levels
- [x] Improve error messages with suggestions
- [x] Add `--debug` flag for verbose output

### 8.6 Security Enhancements ✓

**Priority: Medium** - Defense in depth. **COMPLETED**

- [x] Audit log for all cell operations (via brig history)
- [x] Image signature verification (optional, via --verify-image)
- [x] Rate limiting for cell creation
- [x] Seccomp profiles on top of gVisor (via --seccomp-profile)
- [x] Network policy validation (no SSRF via DNS rebinding)

### 8.7 UX Polish ✓

**Priority: Low** - Nice to have. **COMPLETED**

- [x] Progress spinners for long operations
- [x] Shell completion scripts (bash/zsh)
- [x] Color-coded status in `brig list`
- [x] `--dry-run` flag for preview
- [x] `brig history` - Operation audit trail
- [x] Man pages generation

### 8.8 Production Hardening ✓

**Priority: Low** - Production deployment. **COMPLETED**

- [x] Proxy systemd service with auto-restart
- [x] Log rotation configuration
- [x] macOS state directory quarantine
- [x] Health check endpoints
- [x] Metrics export (Prometheus format)

### 8.9 Rename CLI and Components ✓

**Priority: Medium** - Branding and clarity. **COMPLETED**

- [x] Rename CLI tool: `cell` → `brig`
- [x] Rename proxy: `cell-proxy` → `warden`
- [x] Keep "cell" as the term for an isolated workload unit
- [x] Update all source files:
  - `src/cell.py` → `src/brig.py`
  - `src/cell_proxy.py` → `src/warden.py`
  - `src/cell_subnet.py` → `src/brig_subnet.py`
- [x] Update container prefixes: `cell-` → `brig-`
- [x] Update proxy container name: `cell-proxy` → `warden`
- [x] Update all test files
- [x] Update documentation
- [x] Update VM installation paths (lima.yaml updated)
- [x] Update CLAUDE.md and comments
- [x] Update VM installation paths (lima.yaml updated)

---

## Success Criteria

### Functional

- [ ] Cells run isolated from each other
- [ ] Cells can only reach internet through proxy
- [ ] All network traffic is logged
- [ ] Policy enforcement works
- [ ] Secrets are protected
- [ ] gVisor is default runtime

### Security

- [ ] All 9 security invariants hold
- [ ] All 15 verification tests pass
- [ ] No silent runtime downgrades
- [ ] Fail-closed on errors

### Operational

- [ ] Clear error messages
- [ ] Diagnose command helps debug issues
- [ ] Recovery procedures work
- [ ] Logs are useful
