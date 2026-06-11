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
      verify.py              # Security-invariant verification checks (verify_* fns)

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

    observability/
      collector.py           # OTel collector container lifecycle (brig-otel)
      collector_config.yaml  # Collector pipeline config
      promql.py              # PromQL query helpers
      stats.py               # Stats aggregation for `brig system stats`

    commands/
      lifecycle_run.py       # brig run + its arg-parse/merge/diagnose helpers
      lifecycle_inspect.py   # list/inspect/files/read/logs/cp/top/diff/stats/export/ingress/preflight
      lifecycle_control.py   # stop/kill/rm/start/restart/pause/unpause/wait/rename/exec/shell/attach
      system_cmd.py          # init/verify/doctor/preflight/metrics/prune/history/stats
      policy_cmd.py          # policy show/set
      secrets_cmd.py         # secrets list/add/rm
      config_cmd.py          # config show/set/reset
      convenience_cmd.py     # up/down/profiles
      watchdog_cmd.py        # warden watchdog
      image_cmd.py           # pull/warmup/image-verify
      network_cmd.py         # network/events

    sdk.py                   # Programmatic API (execute_sync for agents)

    warden_addons/           # mitmproxy addons — brig package-data, flat-loaded
      _common.py             # Shared: BLOCKED_NETWORKS, SubnetResolver, atomic_write_json
      _policy.py             # Policy data structures (PolicyRule, DomainTrie, Policy)
      _log_writer.py         # Batched JSONL log writer with rotation
      _notifier_state.py     # Webhook URL SSRF resolution/state for notifier
      enforce.py             # Policy enforcer addon (uses _policy)
      logger.py              # Request logging (JSONL per cell)
      ops.py                 # Merged: metrics + rate limiting + health endpoint
      ingress.py             # Ingress reverse proxy (port 8443; auth: token|none)
      notifier.py            # Webhook notifications
      otel_export.py         # OpenTelemetry metrics + log records export

  warden/
    cli.py                   # Warden CLI entry point
    proxy.py                 # Container lifecycle (start/stop/status)
    reconcile.py             # Subnet state reconciliation
    health.py                # Health checks
    logs.py                  # Log management (prune)
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
| `network-policy.json` | `~/.brig/cells/` | Process-wide operational settings (rate limits, log filter, policy tracing) — no allow/deny |
| `policies/<cell>.json` | `~/.brig/state/system/policies/` | Per-cell egress allow/deny |
| `operations.jsonl` | `~/.brig/state/system/` | Command audit log |
| `lifecycle.jsonl` | `~/.brig/state/system/` | Cell lifecycle events |
