# Brig

Secure workload harness for running untrusted code on macOS.

Brig isolates workloads in **cells** — containers with gVisor sandboxing, dedicated networks, and mandatory egress filtering through the Warden proxy.

## Quick Start

```bash
# Prerequisites: macOS, Python 3.10+, uv, Lima
# brew install lima
# curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/d0cd/brig.git
cd brig
make setup            # install, create VM, provision gVisor, start warden
```

That's it. Run your first cell:

```bash
brig run alpine echo "Hello from a secure cell!"
```

## What Just Happened

```
┌─────────────────────────────────────────────────────────┐
│ macOS                                                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Lima VM                                           │  │
│  │  ┌─────────────┐  ┌─────────────┐                │  │
│  │  │ Cell A      │  │ Cell B      │  (isolated)    │  │
│  │  │ (gVisor)    │  │ (gVisor)    │                │  │
│  │  └──────┬──────┘  └──────┬──────┘                │  │
│  │         │                │                        │  │
│  │         └───────┬────────┘                        │  │
│  │                 ▼                                 │  │
│  │          ┌─────────────┐                          │  │
│  │          │   Warden    │  (policy enforcement)    │  │
│  │          │   Proxy     │                          │  │
│  │          └──────┬──────┘                          │  │
│  └─────────────────┼─────────────────────────────────┘  │
│                    ▼                                    │
│               Internet (filtered)                       │
└─────────────────────────────────────────────────────────┘
```

Your code ran inside a gVisor-sandboxed container, on an isolated network, with all egress filtered through the Warden proxy. It couldn't reach other cells, couldn't access the macOS host, and could only connect to domains in the policy allowlist.

## Usage

### Run cells

```bash
brig run alpine echo hello                            # quick one-off (auto-named)
brig run --name scraper python:3.12 python scrape.py  # named cell
brig run --profile untrusted -d alpine sleep 3600      # background, restricted profile
brig run --file mycell.yaml                            # from definition file
```

### Manage cells

```bash
brig list                     # list all cells
brig logs mycell -f           # follow logs
brig exec mycell -- ls -la    # run command in cell
brig stop mycell              # graceful stop
brig rm mycell                # remove cell + network + subnet
```

### Secrets

```bash
brig secrets add api-key                    # interactive prompt (safe)
echo "sk-123" | brig secrets add api-key    # from pipe
brig secrets list                           # show all secrets
brig run --secret api-key alpine cat /run/secrets/api-key
```

### Profiles

```bash
brig profiles                               # list available profiles
brig run --profile untrusted alpine sh      # 512m, 1 cpu, restricted
brig run --profile dev alpine sh            # 4g, 4 cpus, generous
brig run --network none alpine sh           # fully airgapped
```

### Policy

```bash
brig policy show                            # show global policy
brig policy set global --allow '*.example.com'  # add to global allowlist
brig policy set mycell --deny evil.com      # per-cell deny
brig policy show mycell --effective         # merged global + per-cell
```

### System

```bash
brig up                       # start everything (VM + warden)
brig down                     # stop everything
brig down --vm                # also stop the VM
brig verify                   # check all 9 security invariants
brig health                   # system health check
brig diagnose mycell          # debug a specific cell
```

## Network Policy

Default policy (`~/.brig/cells/network-policy.json`) allows pypi, github, npm:

```json
{
  "allow": [
    "pypi.org", "*.pythonhosted.org", "github.com",
    "api.github.com", "*.githubusercontent.com", "registry.npmjs.org"
  ],
  "deny": [],
  "rate_limits": {"default": {"rate": 100, "burst": 500}}
}
```

## Security Model

| Boundary | Purpose |
|----------|---------|
| Lima VM | Hardware isolation from macOS (primary security boundary) |
| gVisor | Syscall filtering (defense in depth) |
| Per-cell networks | No lateral movement between cells |
| Warden proxy | Egress filtering, logging, rate limiting |

9 security invariants, all tested. Run `brig verify` to check.

## Development

```bash
make setup                    # install with dev deps, create VM, start
make test                     # run unit tests (352 tests)
make check                    # full CI checks (lint, types, tests)
make smoke                    # end-to-end test (requires VM)
make bench                    # benchmarks
```

## Docs

- [Cell Definition Reference](docs/design/cell-definition.md)
- [Architecture](docs/design/architecture.md)
- [Security Design](docs/design/security.md)
- [SDK Specification](docs/sdk-spec.md)
- [Security Invariants](docs/INVARIANTS.md)

## License

[MIT](LICENSE)
