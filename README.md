# Brig

Secure workload harness for running untrusted code on macOS.

Brig isolates workloads in **cells** - containers with gVisor sandboxing, dedicated networks, and mandatory egress filtering through the Warden proxy.

## Features

- **Defense in depth**: Lima VM (hardware boundary) + gVisor (syscall filtering) + network isolation
- **Per-cell networks**: No east-west traffic between cells
- **Policy-enforced egress**: All outbound traffic goes through Warden proxy with domain allowlists
- **Secret management**: Mount secrets as files, never exposed in environment variables
- **Observability**: Per-cell request logging, metrics, and rate limiting

## Quick Start

### Prerequisites

- macOS
- Python 3.10+
- [Lima](https://github.com/lima-vm/lima): `brew install lima`

### Installation

```bash
git clone https://github.com/d0cd/brig.git
cd brig
./install.sh
```

### Setup

```bash
# Create and start the VM
brig vm create
brig vm start

# Start the Warden proxy (inside VM)
brig vm shell -- warden start --detach
```

### Run Your First Cell

```bash
brig run --name hello --image alpine -- echo "Hello from a secure cell!"
```

## Architecture

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
│  │          │   Warden    │  (policy enforcement)   │  │
│  │          │   Proxy     │                          │  │
│  │          └──────┬──────┘                          │  │
│  └─────────────────┼─────────────────────────────────┘  │
│                    ▼                                    │
│               Internet (filtered)                       │
└─────────────────────────────────────────────────────────┘
```

## Commands

### Cell Management

```bash
brig run --name myapp --image python:3.11 -- python app.py
brig list                    # List all cells
brig logs myapp              # View cell logs
brig exec myapp -- sh        # Execute command in cell
brig stop myapp              # Gracefully stop
brig rm myapp                # Remove cell
```

### VM Management

```bash
brig vm create               # Create the Lima VM
brig vm start                # Start the VM
brig vm stop                 # Stop the VM
brig vm status               # Show VM status
brig vm shell                # Open shell in VM
```

### Warden Proxy

```bash
warden start                 # Start the proxy
warden status                # Check proxy status
warden stats                 # View request metrics
warden health                # Health check
warden policy validate       # Validate policy file
warden tor start             # Start Tor + Privoxy bridge
warden tor status            # Check Tor routing status
```

## Network Policy

Configure allowed domains in `~/.brig/cells/network-policy.json`:

```json
{
  "allow": [
    "api.github.com",
    "*.amazonaws.com",
    {"domain": "api.example.com", "paths": ["/v1/*"], "methods": ["GET", "POST"]}
  ],
  "deny": [
    "evil.com"
  ],
  "rate_limits": {
    "default": {"rate": 100, "burst": 500}
  }
}
```

## Security Model

| Boundary | Purpose |
|----------|---------|
| Lima VM | Hardware isolation from macOS (primary security boundary) |
| gVisor | Syscall filtering (defense in depth) |
| Per-cell networks | No lateral movement between cells |
| Warden proxy | Egress filtering, logging, rate limiting |

### Security Invariants

1. No east-west traffic between cells
2. All egress goes through Warden
3. gVisor runtime enforced (no silent downgrade)
4. Secrets mounted as files, never in env vars

## Documentation

- [Installation Guide](INSTALLATION.md)
- [Concepts](docs/learning/concepts.md)
- [Workflows](docs/learning/workflows.md)
- [CLI Reference](docs/design/reference.md)
- [Security Design](docs/design/security.md)
- [Performance Benchmarks](docs/BENCHMARKS.md)
- [Troubleshooting](docs/learning/troubleshooting.md)

## License

[MIT](LICENSE)
