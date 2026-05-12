# Implementation Architecture

This document describes **how brig works internally** — the module structure,
data flows, and component integration. It complements
[architecture.md](architecture.md) (what brig is) and
[security.md](security.md) (why the boundaries exist).

---

## Module Structure

```
src/
  brig/
    cli.py                   # CLI entry point (argparse + dispatch)
    config.py                # Constants, paths, patterns
    errors.py                # BrigError + error helpers

    cell/
      spec.py                # CellSpec dataclass + validation
      reconciler.py          # Declarative: observe() -> plan() -> apply()
      lifecycle.py           # run_cell(), stop_cell(), kill_cell(), rm_cell()
      profiles.py            # Trust profiles (untrusted, supervised, dev, etc.)

    network/
      subnet.py              # Embedded subnet allocator (single state file)
      proxy.py               # Proxy state queries
      validation.py          # Domain/IP validation

    policy/
      policy.py              # Policy CRUD (JSON + YAML)

    security/
      secrets.py             # Secret path validation (invariant 4)
      image.py               # Image signature verification
      verify.py              # All 9 invariant verification checks

    ops/
      logging.py             # Canonical logging (ONE copy)
      subprocess.py          # run() with redaction + timeout
      cache.py               # TTL cache
      ratelimit.py           # Cell creation rate limiting
      history.py             # Operation/lifecycle/policy audit logging

    commands/
      lifecycle_cmd.py       # CLI handlers for run/stop/kill/rm/list
      system_cmd.py          # CLI handlers for init/verify/health
      policy_cmd.py          # CLI handlers for policy show/set

  warden/
    cli.py                   # Warden CLI entry point
    proxy.py                 # Container lifecycle (start/stop/status)
    policy.py                # Policy validation + domain matching
    reconcile.py             # Subnet state reconciliation
    health.py                # Health checks
    logs.py                  # Log management
    tor.py                   # Tor/Privoxy bridge
    stats.py                 # Metrics query

  addons/
    enforce.py               # Policy engine (DomainTrie, DNS rebinding defense)
    logger.py                # Request logging (JSONL per cell)
    ops.py                   # Merged: metrics + rate limiting + health endpoint
    canary.py                # Opt-in: token tracking
    signer.py                # Opt-in: request signing
```

---

## Core Data Flow

```
User: brig run --name mycell alpine -- echo hello

  ┌──────────────────────────────────────────────────────┐
  │ brig CLI (src/brig/cli.py → lifecycle_cmd.py)        │
  │  1. Build CellSpec from args + profile + cell def    │
  │  2. Call run_cell(spec)                              │
  │     → Check proxy running (invariant 9)              │
  │     → Check rate limit                               │
  │     → observe(cell_name) → get actual state          │
  │     → plan_run(spec, actual) → list of Actions       │
  │     → apply(actions) → execute sequentially          │
  │        AllocateSubnet → CreateNetwork → ConnectProxy  │
  │        → PodmanRun (with --runtime runsc)            │
  └──────────────────────────────────────────────────────┘
```

---

## Declarative Reconciler

Instead of imperative multi-phase scripts with manual rollback:

```python
# 1. Observe reality
actual = observe(cell_name)  # queries podman

# 2. Compute plan
actions = plan_run(spec, actual)  # diff desired vs actual

# 3. Apply actions
result = apply(actions)  # execute sequentially, stop on failure
```

If the process dies mid-creation, running `brig run` again converges to the
desired state because `plan_run()` recomputes from current reality.

---

## Subnet Allocator

**Single state file** (`/state/system/subnets.json`) contains both allocation
state and subnet map. No dual-file reconciliation needed.

Each cell gets a /24 subnet from `10.60.1.0/24` through `10.60.254.0/24`
(max 254 cells). File-locked with `fcntl.LOCK_EX` for thread/process safety.

---

## Security Invariant Checks

All 9 invariants are verified by pure functions in `src/brig/security/verify.py`:

```python
verify_proxy_running()        # Invariant 9
verify_proxy_network()        # Invariant 6
verify_gvisor_runtime()       # Invariant 5
verify_network_isolation()    # Invariant 1
verify_single_homed()         # Invariant 8
verify_cell_network_members() # Invariant 7
```

Each returns `CheckResult(passed: bool, message: str, details: list[str])`.

---

## State Files

| File | Location | Purpose | Written By |
|------|----------|---------|------------|
| `subnets.json` | `/state/system/` | Subnet allocation state + map | `brig.network.subnet` |
| `network-policy.json` | `/cells/` | Global egress policy | User / brig init |
| `<cell>.json` | `/var/run/brig/policies/` | Per-cell policy override | `brig.policy.policy` |
| `*.jsonl` | `/var/log/brig/network/` | Per-cell request logs | `addons/logger.py` |
| `operations.jsonl` | `/state/system/` | Command operation log | `brig.ops.history` |
| `lifecycle.jsonl` | `/state/system/` | Cell lifecycle events | `brig.ops.history` |
