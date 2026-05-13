# Implementation Architecture

This document describes **how brig works internally**.

## Module Structure

```
src/
  brig/
    cli.py                   # CLI entry point (argparse + dispatch)
    config.py                # Constants, paths (HostPaths / VMPaths)
    errors.py                # BrigError

    cell/
      spec.py                # CellSpec dataclass + validation
      reconciler.py          # Declarative: observe() → plan() → apply()
      lifecycle.py           # run_cell(), stop_cell(), kill_cell(), rm_cell()
      profiles.py            # Trust profiles (untrusted, supervised, dev, etc.)
      names.py               # Auto-generated cell names

    network/
      subnet.py              # Embedded subnet allocator (single state file)
      proxy.py               # Proxy state queries
      validation.py          # Domain/IP validation

    policy/
      policy.py              # Policy CRUD (JSON + YAML)

    security/
      secrets.py             # Secret path validation
      image.py               # Image signature verification
      verify.py              # All 9 invariant verification checks

    ops/
      logging.py             # Canonical logging (ONE copy)
      cache.py               # TTL cache
      ratelimit.py           # Cell creation rate limiting
      history.py             # Operation/lifecycle/policy audit logging

    vm/
      shell.py               # All podman commands route through limactl shell
      lima.yaml.template     # VM provisioning template

    workspace/
      workspace.py           # File copy with sanitization + quarantine

    commands/
      lifecycle_cmd.py       # run/stop/kill/rm/list/exec/shell/etc.
      system_cmd.py          # init/verify/health/diagnose/preflight/metrics
      policy_cmd.py          # policy show/set
      secrets_cmd.py         # secrets list/add/rm
      config_cmd.py          # config show/set/reset
      convenience_cmd.py     # up/down/profiles
      watchdog_cmd.py        # warden watchdog
      image_cmd.py           # pull/warmup/image-verify
      network_cmd.py         # network/events

    sdk.py                   # Programmatic API (execute_sync for agents)

  warden/
    cli.py                   # Warden CLI entry point
    proxy.py                 # Container lifecycle (start/stop/status)
    reconcile.py             # Subnet state reconciliation
    health.py                # Health checks
    logs.py                  # Log management
    tor.py                   # Tor/Privoxy bridge
    stats.py                 # Metrics query

  addons/
    enforce.py               # Policy engine (DomainTrie, DNS rebinding defense)
    logger.py                # Request logging (JSONL per cell)
    ops.py                   # Merged: metrics + rate limiting + health endpoint
    canary.py                # Canary token detection
    signer.py                # Request signing
    notifier.py              # Webhook notifications
    summarizer.py            # Log summarization
```

## Declarative Reconciler

```python
actual = observe(cell_name)          # query podman for real state
actions = plan_run(spec, actual)     # diff desired vs actual
result = apply(actions)              # execute, rollback on failure
```

## VM Execution Layer

All podman commands are wrapped in `limactl shell --workdir / brig -- sudo podman ...`
by `brig.vm.shell.vm_run()`. This is the single chokepoint between the macOS host
and the Lima VM.

## State Files

| File | Location | Purpose |
|------|----------|---------|
| `subnets.json` | `~/.brig/state/system/` | Subnet allocation |
| `network-policy.json` | `~/.brig/cells/` | Global egress policy |
| `operations.jsonl` | `~/.brig/state/system/` | Command audit log |
| `lifecycle.jsonl` | `~/.brig/state/system/` | Cell lifecycle events |
