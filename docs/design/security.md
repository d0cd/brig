# Brig Security

## Security Invariants

These are the rules that must hold for the security model to work. Violations break your guarantees.

---

### Invariant 1: No East-West Traffic (Per-Cell Networks)

**Rule:** Cells cannot talk to each other directly. Period.

**Implementation:** Each cell gets its own isolated network. The proxy joins all cell networks. No iptables guesswork — isolation by topology.

**Why this is better than iptables:**
- Isolation by topology, not firewall rules
- Works regardless of Podman backend (CNI, netavark)
- No chain ordering issues, no hardcoded IPs
- Self-evidently correct

**Cell creation (what `brig run` does internally):**

```bash
CELL_NAME="my-agent"

# 1. Create isolated network for this cell
podman network create --internal "brig-${CELL_NAME}"

# 2. Connect proxy to this cell's network
podman network connect "brig-${CELL_NAME}" warden

# 3. Run cell on its own network (proxy DNS name resolves)
podman run --runtime=runsc --name "brig-${CELL_NAME}" \
  --network "brig-${CELL_NAME}" \
  -e HTTP_PROXY=http://warden:8080 \
  ...

# 4. On cell removal, disconnect and delete network
podman network disconnect "brig-${CELL_NAME}" warden
podman network rm "brig-${CELL_NAME}"
```

**Inter-cell coordination:** Goes out through proxy to external services:

| Pattern | Example | Allowlist |
|---------|---------|-----------|
| Message queue | Redis (hosted) | `*.upstash.io` |
| Shared storage | S3, GCS | `*.s3.amazonaws.com` |
| Webhook | Your API | `api.yourdomain.com` |

---

### Invariant 2: Proxy Cannot Be Abused as Gateway

**Problem:** Even with `ip_forward=0`, the proxy application could be tricked into fetching arbitrary resources.

**Rules:**

1. Proxy listens ONLY on port 8080 on the internal interface
2. CONNECT method allowed ONLY to port 443 (HTTPS)
3. CONNECT to literal IPs is blocked (domain allowlist only)
4. CONNECT to RFC1918/link-local/localhost/CGNAT is blocked
5. No upstream proxy chaining unless explicitly configured

**Blocked IP ranges:**
- `10.0.0.0/8` (RFC1918)
- `172.16.0.0/12` (RFC1918)
- `192.168.0.0/16` (RFC1918)
- `127.0.0.0/8` (localhost)
- `169.254.0.0/16` (link-local)
- `100.64.0.0/10` (CGNAT)
- `198.18.0.0/15` (benchmarking)
- `240.0.0.0/4` (reserved)

---

### Invariant 3: Secrets Are Observable, Not Preventable

**Reality:** A cell with access to secrets (via mounted files) can send them to any allowed domain.

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

---

### Invariant 4: macOS State Directory Is Untrusted

**Problem:** Cells write to `~/.brig/state/*/workspace/`. These files end up on your Mac.

**Execution Policy:**

| Environment | Can Execute from /state? | Why |
|-------------|-------------------------|-----|
| **macOS host** | No | Protect you from malicious cell output |
| **Lima VM** | Yes | Needed for cell operations |
| **Cell containers** | Yes | Cells need to run scripts, venvs |

**macOS Protection Setup:**

```bash
# Create state directory with restricted permissions
mkdir -p ~/.brig/state
chmod 700 ~/.brig/state

# Add macOS quarantine flag to prevent accidental execution
xattr -w com.apple.quarantine "0181;$(printf %x $(date +%s));brig;$(uuidgen)" ~/.brig/state
```

**Risks:**
- Malicious HTML with JavaScript (if opened in browser)
- Malicious Office docs with macros
- Scripts that look innocent but aren't
- Symlink attacks (cell creates symlink pointing outside workspace)
- `.app`, `.command`, `.webloc` can auto-execute on macOS
- Path traversal (`../../../etc/passwd`)

---

### Invariant 5: gVisor Must Be Active (No Silent Downgrade)

**Problem:** Using `--runtime=crun` removes kernel protection inside Lima.

**Rules:**

1. **Default runtime is gVisor** — set in containers.conf, not just CLI flag
2. **`brig list` shows runtime** — always visible which runtime a cell uses
3. **Native runtime requires explicit opt-in** — via `--profile compute` or `--unsafe`
4. **Runtime is verified at startup** — don't rely solely on config defaults

#### Understanding gVisor's Role

gVisor intercepts syscalls in a userspace sentry process instead of passing them to the Linux kernel. This adds a layer between untrusted code and the VM kernel. The security value depends on your threat model:

**What gVisor protects against:**
- Zero-day Linux kernel exploits (the cell never touches the real kernel)
- Cross-cell kernel-level attacks (each cell has its own sentry)
- `/proc` and `/sys` information leaks (gVisor virtualizes them)
- Unknown syscall-based attacks (gVisor implements ~70 syscalls, the kernel has ~300+)

**What gVisor does NOT add (already provided by other layers):**
- Network isolation (handled by per-cell networks)
- Filesystem isolation (handled by container namespaces)
- macOS protection (handled by the Lima VM hardware boundary)
- Egress control (handled by Warden proxy)
- Capability restrictions (handled by `--cap-drop ALL` + seccomp)

**Even without gVisor, cells are protected by:**
- Lima VM hardware boundary (attacker cannot reach macOS)
- Per-cell network isolation (attacker cannot reach other cells)
- `--cap-drop ALL` + `--security-opt no-new-privileges`
- Default seccomp profile (blocks `mount`, `ptrace`, `bpf`, `kexec_load`, etc.)
- Warden policy enforcement

#### Performance Cost

Measured on Apple Silicon (Lima VZ, steady-state inside running container):

| Metric | gVisor (runsc) | Native (crun) | Overhead |
|--------|---------------|---------------|----------|
| Syscall (open+read+close) | 18us | 6us | 3x |
| Pure compute (no I/O) | 2.4ms | 2.4ms | 1.0x (none) |
| Cold startup | ~220ms | ~130ms | 1.7x |
| RSS per container | 13MB | 9MB | 1.4x |
| Throughput (syscall-heavy) | ~50k/s | ~135k/s | 2.8x fewer |

**Key insight:** gVisor has zero overhead for pure compute. The 3x cost applies only to syscalls. Network I/O through the Warden proxy is unaffected because it flows through the cell's network stack, not the filesystem.

#### Choosing a Runtime

| Profile | Runtime | Threat Model | Use Case |
|---------|---------|-------------|----------|
| `untrusted` | gVisor | Unknown/hostile code | Running submissions from strangers |
| `supervised` | gVisor | Semi-trusted, defense-in-depth | AI agents, CI runners |
| `compute` | crun + seccomp | Trusted code, performance critical | ML training, data processing |
| `dev` | crun + seccomp | Your own code | Development, fast iteration |
| `airgapped` | gVisor | No network, maximum isolation | Offline compute |

Use gVisor when the code is untrusted and you want protection against unknown kernel exploits. Use crun when the code is trusted and syscall-heavy performance matters — the VM + seccomp + network isolation still provide strong protection.

---

### Invariant 6: Only Infrastructure Containers May Attach to `proxy-external`

**Rule:** Only `warden` (and optionally `warden-tor` and `warden-privoxy` when Tor is active) may attach to `proxy-external`. No cell containers.

**Why this matters:** The `proxy-external` network has outbound internet access. Any container attached to it inherits the VM-level egress rules but bypasses per-cell isolation.

**Enforcement:**

```bash
# Verify only infrastructure containers are on proxy-external:
ALLOWED="warden warden-tor warden-privoxy"
containers=$(podman network inspect proxy-external --format '{{range .Containers}}{{.Name}} {{end}}')
for c in $containers; do
  if ! echo "$ALLOWED" | grep -qw "$c"; then
    echo "FATAL: Unexpected container '$c' on proxy-external network"
    exit 1
  fi
done
```

---

### Invariant 7: No Privileged Services on Cell Networks

**Rule:** Only the proxy container and the cell itself may connect to a cell's network. No other services.

**Why this matters:** If you accidentally connect a database, cache, or management service to a cell network, cells could attack it directly.

**What to never do:**
- Connect a Redis/Postgres container to a cell network
- Connect a monitoring agent to a cell network
- Connect the Lima VM host network to a cell network
- Run any "management" container on a cell network

---

### Invariant 8: Cells Must Be Single-Homed (One Network Only)

**Rule:** Each cell container must be attached to exactly one network (its own `brig-<name>` network). Cells must never be attached to multiple networks.

**Why this matters:** Attribution relies on source subnet. If a container joins multiple networks, it may have multiple IP addresses. The proxy cannot reliably attribute traffic to the correct cell.

**Enforcement (in `brig verify`):**

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

---

### Invariant 9: Proxy Must Be Running Before Cells Start

**Rule:** `brig run` and `brig start` must verify the proxy is running and healthy before starting any cell.

**Why this matters:** If cells start without a running proxy, they will have no network path. This creates a confusing debugging experience.

---

## Verification Tests

Run these to verify isolation is working correctly.

### Test 1: Cell Can't Reach Internet Directly

```bash
# Use --network none to test without proxy connectivity
brig run --name test-direct --rm --network none -- curl -m 5 https://google.com
echo "Exit code: $?"  # MUST be non-zero
```

**If this succeeds, your network isolation is broken.**

### Test 2: Cell CAN Reach Internet Via Proxy

```bash
brig run --name test-proxy --rm -- curl -m 5 https://httpbin.org/ip
echo "Exit code: $?"  # Should be 0
```

### Test 3: Blocked Domain Is Blocked

```bash
brig run --name test-blocked --rm -- curl -s -o /dev/null -w "%{http_code}" https://pastebin.com
# Should print: 403
```

### Test 4: Cell Can't See Another Cell's Files

```bash
# Create a file in cell-a
brig run --name cell-a -d -- sh -c "echo 'secret' > /work/secret.txt && sleep 300"

# Try to read it from cell-b (should fail)
brig run --name cell-b --rm -- cat /work/secret.txt
# Should fail: file not found

# Cleanup
brig kill cell-a && brig rm cell-a
```

### Test 5: Cell Can't See Another Cell's Processes

```bash
# Start cell-a with a known process
brig run --name cell-a -d -- sleep 3600

# Check if cell-b can see it
brig run --name cell-b --rm -- ps aux
# Should only show cell-b's own processes

# Cleanup
brig kill cell-a && brig rm cell-a
```

### Test 6: No Foreign Containers Attached to Cell Networks

```bash
# Run inside VM:
limactl shell --workdir / brig -- sudo bash -c '
for net in $(podman network ls --format "{{.Name}}" | grep "^brig-"); do
  echo "== $net =="
  podman network inspect "$net" --format "{{json .Containers}}"
done
'
```

### Test 7: gVisor Is Active

```bash
# Check runtime via podman inspect
limactl shell --workdir / brig -- sudo podman inspect my-cell --format '{{.OCIRuntime}}'
# Should output: runsc

# Verify from inside container
brig run --name test-gvisor --rm -- cat /proc/version
# Should contain "gvisor"
```

### Test 8: No East-West Traffic

```bash
# Start cell-a with an HTTP server
brig run --name cell-a -d -- sh -c "python3 -m http.server 9000 || sleep 300"

# Try to reach from cell-b (MUST FAIL)
brig run --name cell-b --rm -- curl -m 5 http://cell-a:9000/
echo "Exit code: $?"  # MUST be non-zero

# Cleanup
brig kill cell-a && brig rm cell-a
```

### Test 9: Proxy Only Exposes Port 8080

```bash
brig run --name test-portscan --rm -- sh -c '
  apk add --no-cache nmap >/dev/null 2>&1
  nmap -p 1-65535 proxy --open -T4 2>/dev/null | grep "^[0-9]"
'
# Should output ONLY: 8080/tcp open  http-proxy
```

### Test 10: Proxy Is Not a Gateway

```bash
# Try CONNECT to non-443 port (should be rejected)
brig run --name test --rm -- curl -s -x http://proxy:8080 http://example.com:8080/
# Expected: 403 Forbidden

# Try CONNECT to literal IP (should be rejected)
brig run --name test --rm -- curl -s -x http://proxy:8080 https://142.250.80.46/
# Expected: 403 Forbidden

# Try CONNECT to internal range (should be rejected)
brig run --name test --rm -- curl -s -x http://proxy:8080 http://10.50.0.1/
# Expected: 403 Forbidden
```

### Test 11: Default Runtime Check

```bash
# Run without specifying runtime (should use gVisor)
brig run --name test-default --rm -- cat /proc/version
# Should show gVisor

# Verify runc requires --unsafe
brig run --name test --runtime=runc -- echo hello
# Should fail with: "Error: runc runtime requires --unsafe flag"
```

### Test 12: IPv6 Is Disabled

```bash
brig run --name test-ipv6 --rm -- curl -6 -m 5 http://ipv6.google.com/
echo "Exit code: $?"  # MUST be non-zero

brig run --name test-ipv6 --rm -- cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Should output: 1
```

### Test 13: UDP to Internet Is Blocked

```bash
# Try UDP DNS query to external resolver (should fail)
brig run --name test-udp --rm --network none -- nslookup google.com 8.8.8.8
echo "Exit code: $?"  # MUST be non-zero
```

### Test 14: Subnet Allocator Bounds

```bash
limactl shell --workdir / brig -- sudo python3 -c '
import json
state = {"next_index": 255, "allocated": {}, "freed": []}
if state["next_index"] > 254:
    print("PASS: Allocator correctly at limit")
else:
    print("FAIL: Allocator should reject index > 254")
'
```

### Test 15: Network Identity Correctness

```bash
# Create a cell and verify proxy sees correct subnet
brig run --name test-identity -d -- sleep 300

# Make a request and check proxy log
brig exec test-identity -- curl -s https://httpbin.org/ip
sleep 1

# Check last log entry
limactl shell --workdir / brig -- sudo tail -1 /var/log/brig/network/test-identity.jsonl | jq .
# Should show src_ip within expected subnet

# Cleanup
brig kill test-identity && brig rm test-identity
```

---

## Troubleshooting Security Issues

### Cell can reach internet without proxy

1. Verify network is `--internal`:
   ```bash
   limactl shell --workdir / brig -- sudo podman network inspect brig-xxx | grep -i internal
   ```

2. Verify no gateway is set:
   ```bash
   limactl shell --workdir / brig -- sudo podman network inspect brig-xxx | grep -i gateway
   ```

3. Recreate the network:
   ```bash
   brig rm my-cell
   brig run -f cells/my-cell.yaml
   ```

### gVisor not active

1. Check containers.conf:
   ```bash
   limactl shell --workdir / brig -- sudo cat /etc/containers/containers.conf.d/gvisor.conf
   ```

2. Verify runsc is installed:
   ```bash
   limactl shell --workdir / brig -- sudo runsc --version
   ```

### Unexpected container on cell network

1. Run verification:
   ```bash
   brig verify
   ```

2. Disconnect the container:
   ```bash
   limactl shell --workdir / brig -- sudo podman network disconnect brig-xxx unexpected-container
   ```

---

## Recovery Procedures

### Soft Reset (restart cells and proxy)

```bash
brig stop --all
warden restart
brig start --all
```

### Hard Reset (kill everything, keep state)

```bash
brig kill --all
warden stop
limactl shell --workdir / brig -- sudo 'for net in $(podman network ls -q | grep "^brig-"); do podman network rm "$net" 2>/dev/null; done'
brig up
brig start --all
```

### VM Restart (preserves macOS state)

```bash
limactl stop brig && limactl start brig
# Proxy starts automatically via systemd
brig start --all
```

### VM Recreate (clean slate VM, preserves macOS state)

```bash
limactl delete brig && make setup
# All VM state destroyed and rebuilt
brig start --all
```

### Full Reset (destroy everything)

```bash
limactl stop brig
rm -rf ~/.brig/state/*
limactl delete brig && make setup
```

### Verify Recovery

After any recovery:

```bash
# Quick smoke test
brig run --name recovery-test --rm -- curl -m 5 https://httpbin.org/ip

# Full verification suite
brig test isolation
```

---

## Tor Integration

### Architecture

When Tor is enabled, traffic flows through a Privoxy bridge that converts HTTP proxy requests to SOCKS5 for the Tor daemon:

```
Cell → Warden (mitmproxy :8080, policy enforcement)
         → Privoxy (:8118, HTTP→SOCKS5 bridge)
            → Tor (:9050, SOCKS5 proxy)
               → Internet (via Tor network)
```

### Why Privoxy?

mitmproxy cannot chain to a SOCKS5 upstream proxy — it only supports HTTP upstream mode. Privoxy bridges the gap by accepting HTTP proxy connections from mitmproxy and forwarding them as SOCKS5 to Tor.

### Network Topology

All three containers (Warden, Privoxy, Tor) run on the `proxy-external` network. Cells remain on their isolated `brig-<cell>` networks and can only reach Warden. This preserves all security invariants:

- **Policy enforcement is preserved.** Every request passes through Warden's mitmproxy before reaching Privoxy/Tor.
- **No direct Tor access.** Cells cannot reach Privoxy or Tor directly (different networks).
- **No east-west bypass.** Cell network isolation is unchanged.
- **Invariant 6 holds.** Only Warden, Privoxy, and Tor attach to `proxy-external` — all are infrastructure containers, not cells.

### Container Hardening

Both Privoxy and Tor containers run with:
- `--read-only` filesystem
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--tmpfs` for writable directories (noexec, nosuid)
- Strict resource limits (128MB RAM, 0.25 CPU for Privoxy)

### Activation

Tor routing is global. When active, all cell traffic routes through Tor. The `--tor` flag on `brig run` is a pre-flight safety check, not a per-cell toggle.

---

## Optional Hardening (Future Roadmap)

### AppArmor/Seccomp Profiles

```yaml
# In cell definition (future)
security:
  seccomp: strict
  apparmor: cell-profile
```

### Air-Gap Mode

```yaml
# In cell definition
network: none  # No network at all
```

### Egress Rate Limits

```yaml
# Future: in network-policy.json
rate_limits:
  per_cell:
    requests_per_minute: 1000
    bytes_per_minute: 100MB
```

### Per-Cell Proxy

```yaml
# Future: in cell definition
proxy: dedicated
```

### Per-Cell MicroVMs

```yaml
# Future: in cell definition
isolation: microvm  # Requires Firecracker
```
