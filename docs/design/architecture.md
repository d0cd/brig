# Brig Architecture

Component-level breakdown for contributors: how the pieces wire
together, network topology, deployment shape. For a user-facing
explanation of *why* each layer exists and what it protects you
from, see [`learning/concepts.md`](../learning/concepts.md).

## Overview

**Brig** is a secure, observable harness for running untrusted code on macOS. It provides VM-isolated containers (hardware boundary at the Lima VM) with controlled network egress and full observability.

### What It Does

- **Isolates workloads** — Each workload runs in its own container with its own network
- **Protects your host** — Lima VM provides hardware boundary; gVisor reduces kernel attack surface
- **Controls network** — All egress goes through an observable proxy with policy enforcement
- **Logs all network requests** — Every network request is logged and attributed to its source workload
- **Manages state** — Persistent workspaces, safe file export, secrets handling

### Use Cases

| Use Case | Why Brig Helps |
|----------|----------------|
| **AI agents** | Agents execute arbitrary code; Brig contains the blast radius |
| **CI/CD runners** | Build untrusted code without risking the host |
| **Student code** | Run submissions safely; prevent cheating via network |
| **Plugin sandboxes** | Extensions can't escape or exfiltrate data unobserved |
| **Research** | Experiment with untrusted software safely |
| **Development** | Test with strict network policies |

---

## Threat Model

**This is containment, not air-gapped isolation.** Brig provides:
- Strong host protection (Lima VM boundary)
- Observable network egress — proxy logs every flow by default. The
  intentional carve-out that reduces visibility on an opt-in path:
  `policy.tls_passthrough` hosts are tunneled raw with only SNI +
  bytes audited (invariant 11). It requires explicit cell-yaml
  declaration — silent egress is impossible. (Scoped `mounts:` also
  bypass Warden for host *files* — invariant 13.)
- Reduced blast radius (cells can't attack each other)

Brig does **not** provide:
- Prevention of data exfiltration to allowed domains
- Malware analysis isolation (cells have network access)
- Protection against a determined attacker with allowed egress

**Key boundary clarification:** Lima VM is the **only** hard security boundary. gVisor is defense-in-depth inside the VM—it reduces attack surface but is not a security boundary. If gVisor has a vulnerability, the Lima VM still protects macOS.

**Proxy failure mode:** If the proxy stops, all cell egress fails closed (no network path exists). Cells may hang on network calls until timeout. Run `warden status` to check, `warden start` to recover.

**Covert channel note:** Even with a tight allowlist, covert exfiltration is possible via:
- DNS over HTTPS (DoH) to allowed HTTPS endpoints
- Steganography in allowed API responses
- Timing-based channels

If you need true air-gap isolation, disable all network egress or use a dedicated offline VM.

---

## Architecture Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                          macOS Host                            │
│                                                                │
│   Your files, credentials, apps — protected from workloads     │
│                                                                │
│   ┌──────────────────────────────────────────────────────────┐ │
│   │                   Lima VM (Boundary #1)                  │ │
│   │                                                          │ │
│   │  ┌─────────┐ ┌─────────┐ ┌─────────┐      ┌─────────┐   │ │
│   │  │ gVisor  │ │ gVisor  │ │ gVisor  │      │  Proxy  │   │ │
│   │  │┌───────┐│ │┌───────┐│ │┌───────┐│      │ ─────── │   │ │
│   │  ││Cell A ││ ││Cell B ││ ││Cell C ││      │  Logs   │   │ │
│   │  │└───────┘│ │└───────┘│ │└───────┘│      │ Policy  │   │ │
│   │  │ State A │ │ State B │ │ State C │      └────┬────┘   │ │
│   │  └────┬────┘ └────┬────┘ └────┬────┘           │        │ │
│   │       └───────────┴─────┬─────┴────────────────┘        │ │
│   │                         │                               │ │
│   │              Internal Networks (no east-west)           │ │
│   │                                                         │ │
│   └─────────────────────────┼───────────────────────────────┘ │
│                             ▼                                 │
└─────────────────────────── Internet ──────────────────────────┘
```

---

## Security Model

### Two Boundaries

| Boundary | Technology | Protects Against |
|----------|------------|------------------|
| **#1: Lima VM** | Hardware virtualization (Apple VZ) | Workload attacking macOS |
| **#2: gVisor** | Syscall interception | Workload exploiting Linux kernel |

### What's Protected

| Asset | How |
|-------|-----|
| Your Mac | Lima VM — hardware boundary |
| Lima's kernel | gVisor — workloads can't make direct syscalls |
| Cell A's state | Own network + Podman namespaces + gVisor |
| Cell B's state | Own network + Podman namespaces + gVisor |
| Network traffic | Observable proxy (enforced, not bypassable) |

### What Workloads CANNOT Do

- Access your Mac's filesystem
- Access another cell's workspace
- See another cell's processes
- Communicate with other cells directly (separate networks)
- Reach the internet without going through proxy
- Use proxy as a router (IP forwarding disabled)

**gVisor note:** gVisor reduces kernel attack surface but does not eliminate kernel-level compromise risk. gVisor itself can have vulnerabilities. Lima VM remains the only hard security boundary.

### Scope

**Primary goal:** Protect macOS host from untrusted workloads.

**Acceptable risk:** A sophisticated attack could compromise the Lima VM. This is detectable (logs, monitoring) and recoverable (destroy and recreate VM). Full mitigation would require per-cell microVMs (Firecracker), which adds complexity.

**gVisor's role:** Defense-in-depth inside the Lima VM. If gVisor were disabled, macOS would still be protected by the Lima VM boundary. gVisor reduces the syscall surface presented to the Lima kernel (mitigating kernel exploit risk) and strengthens cell-to-cell isolation.

---

## Network Topology (Per-Cell Networks)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                Lima VM                                       │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │    cell-a        │  │    cell-b        │  │    cell-c        │           │
│  │   (--internal)   │  │   (--internal)   │  │   (--internal)   │           │
│  │                  │  │                  │  │                  │           │
│  │  ┌────────────┐  │  │  ┌────────────┐  │  │  ┌────────────┐  │           │
│  │  │   Cell A   │  │  │  │   Cell B   │  │  │  │   Cell C   │  │           │
│  │  │  (gVisor)  │  │  │  │  (gVisor)  │  │  │  │  (gVisor)  │  │           │
│  │  └─────┬──────┘  │  │  └─────┬──────┘  │  │  └─────┬──────┘  │           │
│  │        │         │  │        │         │  │        │         │           │
│  │  ┌─────┴──────┐  │  │  ┌─────┴──────┐  │  │  ┌─────┴──────┐  │           │
│  │  │   Proxy    │  │  │  │   Proxy    │  │  │  │   Proxy    │  │           │
│  │  │  (joined)  │  │  │  │  (joined)  │  │  │  │  (joined)  │  │           │
│  │  └────────────┘  │  │  └────────────┘  │  │  └────────────┘  │           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘           │
│                                    │                                         │
│                          ┌─────────┴─────────┐                              │
│                          │  proxy-external    │                              │
│                          │  (has internet)    │                              │
│                          └─────────┬─────────┘                              │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     ▼
                                 Internet
```

**Key points:**
- Each cell gets its own `--internal` network (created by `brig run`)
- Proxy joins each cell's network; `brig run` injects the proxy's DNS name (`warden`) into the cell's `HTTP(S)_PROXY` environment (re-resolved per connection, so egress survives warden IP changes)
- No shared network = no east-west traffic by topology
- No iptables rules needed = no chain ordering bugs
- IPv6 disabled = simpler security model
- Proxy has `ip_forward=0` and rejects requests to internal IPs

---

## Lima VM Setup

### Backend Requirements

This design is tested with:
- **Lima:** 0.18+ with `vz` (Virtualization.framework) on macOS
- **Podman:** 4.0+ with netavark backend (default on Ubuntu 24.04), **rootful mode**
- **gVisor:** runsc from official releases

**Rootful vs Rootless:** We use **rootful Podman** inside the Lima VM for simplicity:
- gVisor works reliably with rootful
- Network namespace management is simpler
- VM-level iptables rules work correctly
- The VM itself is the isolation boundary, so rootful inside VM is acceptable

Other configurations may work but are not tested:
- Podman with CNI backend (older)
- Rootless Podman (cgroups limitations with gVisor)
- Lima with QEMU backend (slower, but more portable)

### Lima Configuration (lima.yaml)

```yaml
vmType: vz
mountType: virtiofs
rosetta:
  enabled: true

cpus: 4
memory: 8GiB
disk: 50GiB

mounts:
  - location: "~/.brig/state"
    mountPoint: "/state"
    writable: true
  - location: "~/.brig/secrets"
    mountPoint: "/secrets"
    writable: false
  - location: "~/.brig/cells"
    mountPoint: "/cells"
    writable: false

images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: "aarch64"
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"
```

### VM Provisioning

The provisioning script:
1. Installs packages (Podman, iptables, gVisor)
2. Configures Podman to use gVisor by default
3. Disables IPv6
4. Creates the proxy-external network
5. Configures mount security
6. Sets up log rotation
7. Configures VM-level egress firewall (fail-closed)
8. Sets up proxy systemd service
9. Runs self-tests

---

## Proxy Service

Runs inside Lima. Routes and logs all cell traffic.

### What It Does

| Function | Description |
|----------|-------------|
| Route traffic | All cell HTTP/HTTPS goes through it |
| Enforce policy | Block requests to non-allowed domains |
| Log requests | Record URL, status, timing per cell |
| Cell identification | Track which cell made each request (via source subnet) |

### Deployment Mode

**Shared proxy (default):** One proxy container connects to all cell networks.

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   cell-a    │  │   cell-b    │  │   cell-c    │
│   Cell A    │  │   Cell B    │  │   Cell C    │
│      │      │  │      │      │  │      │      │
│  ┌───┴───┐  │  │  ┌───┴───┐  │  │  ┌───┴───┐  │
│  │ Proxy │──┼──┼──│ Proxy │──┼──┼──│ Proxy │  │  (same container)
│  └───────┘  │  │  └───────┘  │  │  └───────┘  │
└─────────────┘  └─────────────┘  └─────────────┘
        │                │                │
        └────────────────┴────────────────┘
                         │
                  proxy-external
                         │
                     Internet
```

### Proxy Unbypassability Guarantee

Cell containers are attached only to a per-cell **internal** Podman network (created with `--internal`). These networks have **no route/NAT to the VM's egress interface**.

The only component with internet access is the **proxy**, which is the **only** container attached to:
- each `brig-<cell>` internal network (to accept proxied requests), and
- the `proxy-external` network (for outbound access).

Additionally, the Lima VM applies a **fail-closed** firewall on traffic forwarded from the `proxy-external` CIDR to the VM egress interface.

---

## DNS Model

- Cells do not perform external DNS lookups directly. External name resolution happens inside the proxy as part of egress.
- Cells reach the proxy via its DNS name `warden` injected into `HTTP(S)_PROXY` at run time; the cell network's DNS (aardvark) re-resolves warden's current per-cell IP on each connection, so egress survives warden restarts that change that IP. The name is the same `config.PROXY_NAME` constant the warden container is named with, so it can't drift from the resolver target.
- **DNS over HTTPS (DoH):** If a cell attempts DoH to an allowed domain (e.g., `cloudflare-dns.com`), the request will succeed but is **visible in proxy logs** as HTTPS traffic to that domain.
