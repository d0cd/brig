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
brig cell list                     # list all cells
brig cell logs mycell -f           # follow logs
brig cell exec mycell -- ls -la    # run command in cell
brig cell stop mycell              # graceful stop
brig cell rm mycell                # remove cell + network + subnet
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
brig system profiles                               # list available profiles
brig run --profile untrusted alpine sh      # 512m, 1 cpu, restricted
brig run --profile dev alpine sh            # 4g, 4 cpus, generous
brig run --network none alpine sh           # fully airgapped
```

### Policy

```bash
brig policy show mycell                              # show a cell's policy
brig policy set mycell --allow '*.example.com'       # extend cell allowlist
brig policy set mycell --deny evil.com               # extend cell denylist
brig policy test mycell api.example.com              # dry-run a host against the policy
brig policy rm mycell                                # drop the per-cell policy file
```

Policy commands always operate against a named cell; the cell yaml is the source of truth for what each cell can reach.

### System

```bash
brig system up                       # start everything (VM + warden)
brig system down                     # stop everything
brig system down --vm                # also stop the VM
brig system verify                   # check all 12 security invariants
brig system doctor --quick                   # system health check
brig cell diagnose mycell          # debug a specific cell
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

12 security invariants, all tested. Run `brig system verify` to check.

## Development

```bash
make setup                    # install with dev deps, create VM, start
make test                     # run unit tests
make check                    # full CI checks (lint, types, tests)
make smoke                    # end-to-end test (requires VM)
make bench                    # benchmarks
```

## Docs

- [Quickstart](docs/learning/quickstart.md)
- [Concepts](docs/learning/concepts.md)
- [Hosting an agent](docs/learning/host-an-agent.md) — end-to-end agent + host-service walkthrough
- [Troubleshooting](docs/learning/troubleshooting.md)
- [Cell Definition Reference](docs/design/cell-definition.md)
- [Architecture](docs/design/architecture.md)
- [Security Design](docs/design/security.md) — and the [supply-chain notes](docs/design/supply-chain.md)
- [SDK Specification](docs/sdk-spec.md)
- [Brig CLI Reference](docs/reference/brig-cli.md)
- [Warden CLI Reference](docs/reference/warden-cli.md)
- [Cell Metadata Reference](docs/reference/cell-metadata.md) — `/run/brig/cell.json` schema and workspace-passthrough security model
- [Addons Reference](docs/reference/addons.md)
- [Security Invariants](docs/INVARIANTS.md)

## License

[MIT](LICENSE)
