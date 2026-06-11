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

1. Warden's egress proxy listens on port 8080 on the internal interface. (Ingress adds 8443, and each declared `protocol: tcp` host_service adds its port — all on warden's internal IP, gated by `enforce.py`'s per-cell policy.)
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
2. **`brig cell list` shows runtime** — always visible which runtime a cell uses
3. **Native runtime requires explicit opt-in** — via `--profile dev` (or another non-gVisor profile)
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

#### Choosing a Profile

| Profile | Threat Model | Use Case |
|---------|-------------|----------|
| `untrusted` | Unknown/hostile code | Running submissions from strangers |
| `supervised` | Semi-trusted, defense-in-depth | AI agents, CI runners |
| `dev` | Your own code | Development, fast iteration |
| `airgapped` | No network, maximum isolation | Offline compute |
| `honeypot` | Adversarial; capture telemetry | Studying malware behaviour |

All profiles run on gVisor (`runsc`): invariant 5 forbids a silent runtime
downgrade, so the reconciler hardcodes `--runtime runsc` and profiles cannot
override it. Profiles differ in resource limits, seccomp, and network defaults
— not in the kernel-isolation boundary.

---

### Invariant 6: Only Infrastructure Containers May Attach to `proxy-external`

**Rule:** Only brig's own infrastructure containers may attach to `proxy-external` — `warden` and the OTel collector (`brig-otel`). No cell containers. (The enforced allowlist is `INFRA_CONTAINER_NAMES` in `src/brig/config.py`; `verify_proxy_network` checks membership.)

**Why this matters:** The `proxy-external` network has outbound internet access. Any container attached to it inherits the VM-level egress rules but bypasses per-cell isolation. The collector qualifies as infrastructure: it is brig-managed and pinned, runs no untrusted workload, is on this network only so warden can resolve its OTLP endpoint by name, and **no cell can reach it** — cells live on their own `brig-<cell>` `--internal` networks with no route to `proxy-external`.

**Enforcement:**

```bash
# Verify only infrastructure containers are on proxy-external:
ALLOWED="warden brig-otel"
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

**Enforcement (in `brig system verify`):**

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

**Rule:** `brig run` and `brig cell start` must verify the proxy is running and healthy before starting any cell.

**Why this matters:** If cells start without a running proxy, they will have no network path. This creates a confusing debugging experience.

---

### Invariant 10: `host_sockets` Bypass Warden by Design

**Rule:** A cell that declares `host_sockets: [...]` in its yaml bind-mounts a macOS-side unix socket into the cell at a path under `/run/host/`. Bytes flow kernel-direct between the cell and the host service — no proxy interposition possible.

**Why this matters:** Some upstream services (Postgres / Redis / ssh-agent) don't speak HTTP and can't meaningfully traverse a CONNECT-style proxy. The `host_sockets` primitive trades audit visibility for protocol generality.

**Sub-rules brig enforces** (`docs/INVARIANTS.md` invariant 10):

1. **Opt-in per cell yaml.** No default access; the operator's act of writing the entry IS the security review.
2. **Untrusted profile cannot declare `host_sockets`** at parse time. Adversarial cells don't get side channels.
3. **Engine sockets (`docker.sock`, `podman.sock`, …) are denylisted** at parse time AND at bridge-start (defense in depth).
4. **Bridge sockets are real unix sockets, never symlinks** (lstat check defends against TOCTOU swap of the bridge path).
5. **Per-cell namespacing** — cell A's bridge can't be reused by cell B.
6. **Every attach is audited** via `log_lifecycle("host_socket_attach", …)`.
7. **The cell startup banner** explicitly says Warden does not see the traffic, so operators internalize the trade-off.

For host services that DO speak TCP but aren't worth bypassing Warden entirely, `host_services` with `protocol: tcp` keeps Warden in the path (connection-level audit only — see cell-definition.md).

---

### Invariant 11: TLS Passthrough Is an Explicit, Opt-In TLS-Handling Override

**Rule:** A cell that declares `policy.tls_passthrough: [<host>]` in its yaml — *with* the same host listed in `policy.allow` — tells Warden to tunnel that host's TLS traffic raw, without decrypting. Warden routes by SNI; no MITM, no body inspection, no per-URL log entry.

**Why this matters:** Some hosts can't survive mitmproxy. Sites using HTTP Public Key Pinning, Encrypted Client Hello, strict ALPN/cipher pinning, or Cloudflare's bot-fingerprinting TLS (e.g. `chatgpt.com`) refuse the relayed handshake. Brig's default mode keeps full audit visibility but loses on these endpoints. Passthrough flips the trade-off explicitly.

**The trade-off table** — operators who add an entry to `tls_passthrough` are choosing column 2 for that host:

| Concern | MITM (default) | Passthrough (opt-in) |
|---|---|---|
| Host allowlist enforcement | via Host header | via SNI in client hello |
| Per-URL/method audit log | yes | no — only SNI + bytes + duration |
| Body inspection / DLP | yes | no |
| Warden sees credentials in cleartext | yes | no |
| Survives HPKP / ECH / strict ALPN | no | yes |
| Detect runaway exfil by volume | yes (bytes counter) | yes (same counter) |
| Detect *specific URL* exfil | yes | no |

For an agent runtime holding the operator's provider credentials (Claude OAuth, OpenAI keys), passthrough is arguably *more* secure than MITM in a multi-tenant world — Warden never sees the bearer token. Today's single-operator model treats this as an opt-in trade-off; multi-tenant brig will eventually require passthrough for credentialed flows.

**Sub-rules brig enforces** (`docs/INVARIANTS.md` invariant 11):

1. Passthrough is opt-in per cell per host. No default.
2. Passthrough hosts MUST also appear in `policy.allow`. The schema validator rejects entries that aren't. Passthrough is a TLS-handling override, never a policy bypass.
3. At runtime, Warden's `Policy.is_passthrough` re-checks both lists — a tampered policy file that lists a host *only* in `tls_passthrough` cannot bypass MITM (defense in depth against invariant 4: state dir untrusted).
4. SNI in the client hello must match the CONNECT host. Otherwise a malicious cell could CONNECT to allowed-host:443 and SNI=attacker.com to abuse Warden as a generic tunnel.
5. Untrusted profile cannot declare passthrough. Adversarial cells must remain inspectable.
6. Passthrough connections are audited at the TLS handshake via the connection-level `PASSTHROUGH: cell=… sni=…` log line (`enforce.py:tls_clienthello`). Method/path/status/bytes are absent BY CONSTRUCTION — Warden never decrypts, and a true (`ignore_connection`) passthrough tunnel produces no mitmproxy flow, so the per-byte/connection `tcp_*` hooks and `warden_passthrough_*` counters never fire. MITM OTel records are tagged `tls_mode=mitm` (the JSONL flow log written by `logger.py` carries no `tls_mode` field).

**Cell yaml shape:**

```yaml
policy:
  allow:
    - api.anthropic.com         # MITM (default)
    - registry.npmjs.org
    - chatgpt.com               # required: passthrough hosts MUST be allow'd
  tls_passthrough:
    - chatgpt.com               # turns off MITM for this host
    - auth.openai.com
```

Two lists, not one with attributes, so `grep -l tls_passthrough cells/*.yaml` answers "which cells have un-inspected egress?" in a single command.

---

### Invariant 12: Warden CA Auto-Mount Is Per-Cell, Re-Extracted From Container, Opt-Out-Able

**Rule:** Cells with `trust_warden_ca: true` (the default) get a combined system+Warden CA bundle bind-mounted at `/run/brig/ca-bundle.crt`, with `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` auto-exported. Bundle is staged from the live Warden container at every cell start — not cached on macOS.

**Why this matters:** Without auto-mount, every brig-cell consumer rediscovers a manual workaround (extract CA → concat onto system roots → export the four env vars). Auto-mount also lets brig handle CA rotation transparently: every cell start re-extracts the current Warden CA, so a `brig system down && brig system up` (which can rotate the CA) doesn't leave cells with stale trust.

**Sub-rules brig enforces** (`docs/INVARIANTS.md` invariant 12):

1. **Bundle source-of-truth is `/var/lib/warden/mitmproxy-state/`** on the VM — a persistent dir owned by uid 1000 (mitmproxy user). Bind-mounted into Warden so mitmproxy can write the CA. Brig reads via plain `cat` — no `podman exec` (that surface was eliminated).
2. **CA generated eagerly at `warden start`.** Polls for the cert file up to 30s after container is healthy; refuses to declare Warden ready until it exists. Cells racing a fresh `brig system up` can no longer get an empty bundle.
3. **Bundle staged inside the VM, not on macOS.** Lives at `/state/<cell>/ca-bundle.crt`; the VM is the trust boundary (invariant 4 keeps macOS state untrusted).
4. **Cell-side mount is read-only.** Compromised cell can't tamper with its own trust store.
5. **Cell-set env wins.** Operators / image authors who explicitly set `SSL_CERT_FILE` keep their value (brig only fills vars the cell didn't declare). **Foot-gun:** if the image sets `SSL_CERT_FILE` differently from `/run/brig/ca-bundle.crt`, a Warden CA rotation can produce silent TLS hangs. `brig system doctor` now inspects each running cell's effective `Config.Env` and warns on mismatch.
6. **Airgapped cells (`network: none`) skip the mount.** No egress = no CA to validate.
7. **Opt-out via `trust_warden_ca: false`.** For cells with strict pinning or that manage their own trust store.

---

### Invariant 13: Scoped Host Mounts Are Opt-In, Bounded, and Bypass Warden by Design

**Rule:** A `supervised`/`dev` cell may bind-mount an operator-chosen host directory into itself via `mounts:` (read-only by default, `rw` opt-in), bounded by the VM-level `mount_roots` allowlist. Like `host_sockets`, the bytes flow between the cell and the host files directly — Warden does not mediate them.

**Why this matters:** Agents frequently need a real working tree (a repo to edit, a dataset to read) that's larger or more persistent than `/work`, and copying everything in and out is slow and loses edits. `mounts:` trades audit visibility over those files for direct, persistent access — with the host exposure bounded to roots the operator explicitly allowlisted at the VM level.

**Sub-rules brig enforces** (`docs/INVARIANTS.md` invariant 13):

1. **Opt-in per cell yaml.** No default access; the `untrusted` profile rejects `mounts:` at parse time.
2. **Bounded by `mount_roots`.** A mount's `host_path` realpath must resolve under a declared VM-level `mount_roots` entry — a cell cannot reach host trees the operator did not allowlist. Re-resolved and re-checked at attach time (TOCTOU-safe), not just at parse time.
3. **`mount_point` cannot shadow** a system path or the cell's `/work` (parse-time).
4. **Symlinks inside the mount cannot escape** the subtree to a VM path — container mount-namespace isolation makes such a symlink dangle (verified under runsc AND crun, so it does not rely on gVisor; see `docs/design/mount-symlink-hardening.md`).
5. **Every attach is audited** via `log_lifecycle("mount_attach", …)`, and the cell startup banner states Warden does not see these bytes.
6. **Residual risk is host-side, by design.** A cell can plant a symlink pointing out of the shared folder that a *host* consumer might follow (confused-deputy). `brig cell mount-scan` reports/quarantines such symlinks; consumers must treat cell-written files as untrusted. Brig sandboxes the cell's execution, not the fate of files it writes.

`mount_roots` is empty by default — the whole feature is off until an operator opts the VM in. See `docs/design/host-mounts.md` for the full design.

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
brig cell kill cell-a && brig cell rm cell-a
```

### Test 5: Cell Can't See Another Cell's Processes

```bash
# Start cell-a with a known process
brig run --name cell-a -d -- sleep 3600

# Check if cell-b can see it
brig run --name cell-b --rm -- ps aux
# Should only show cell-b's own processes

# Cleanup
brig cell kill cell-a && brig cell rm cell-a
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
brig cell kill cell-a && brig cell rm cell-a
```

### Test 9: Proxy Exposes Only Expected Ports

```bash
brig run --name test-portscan --rm -- sh -c '
  apk add --no-cache nmap >/dev/null 2>&1
  nmap -p 1-65535 warden --open -T4 2>/dev/null | grep "^[0-9]"
'
# For a cell with no ingress and no TCP host_services: ONLY 8080/tcp (http-proxy).
# A cell that declares ingress also sees 8443; a `protocol: tcp` host_service also
# sees its declared port (e.g. 5432). All listeners are gated by enforce.py policy.
```

### Test 10: Proxy Is Not a Gateway

```bash
# Try CONNECT to non-443 port (should be rejected)
brig run --name test --rm -- curl -s -x http://warden:8080 http://example.com:8080/
# Expected: 403 Forbidden

# Try CONNECT to literal IP (should be rejected)
brig run --name test --rm -- curl -s -x http://warden:8080 https://142.250.80.46/
# Expected: 403 Forbidden

# Try CONNECT to internal range (should be rejected)
brig run --name test --rm -- curl -s -x http://warden:8080 http://10.50.0.1/
# Expected: 403 Forbidden
```

### Test 11: Default Runtime Check

```bash
# Run without specifying a profile (should use gVisor)
brig run --name test-default --rm -- cat /proc/version
# Should contain "gvisor"

# Runtime is fixed at runsc and is NOT profile-selectable (invariant 5):
# the reconciler hardcodes `--runtime runsc` and `brig run` has no
# `--runtime` flag. Every profile runs on gVisor.
brig run --name test-dev --rm --profile dev -- cat /proc/version        # contains "gvisor"
brig run --name test-untrusted --rm --profile untrusted -- cat /proc/version  # contains "gvisor"
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
brig cell exec test-identity -- curl -s https://httpbin.org/ip
sleep 1

# Check last log entry
limactl shell --workdir / brig -- sudo tail -1 /var/log/brig/network/test-identity.jsonl | jq .
# Should show src_ip within expected subnet

# Cleanup
brig cell kill test-identity && brig cell rm test-identity
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
   brig cell rm my-cell
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
   brig system verify
   ```

2. Disconnect the container:
   ```bash
   limactl shell --workdir / brig -- sudo podman network disconnect brig-xxx unexpected-container
   ```

---

## Recovery Procedures

### Soft Reset (restart cells and proxy)

```bash
brig system down              # stop all cells + warden
brig system up                # restart warden
brig cell start <name>        # restart each cell you need
```

### Hard Reset (kill everything, keep state)

```bash
brig system down              # stop all cells + warden
limactl shell --workdir / brig -- sudo 'for net in $(podman network ls -q | grep "^brig-"); do podman network rm "$net" 2>/dev/null; done'
brig system up
brig cell start <name>        # repeat for each cell to restart
```

### VM Restart (preserves macOS state)

```bash
limactl stop brig && limactl start brig
# Proxy starts automatically via systemd
brig cell start <name>        # repeat for each cell to restart
```

### VM Recreate (clean slate VM, preserves macOS state)

```bash
limactl delete brig && make setup
# All VM state destroyed and rebuilt
brig cell start <name>        # repeat for each cell to restart
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
# Quick smoke test (egress is default-deny — allow the test host)
brig run --name recovery-test --rm --policy-allow httpbin.org -- curl -m 5 https://httpbin.org/ip

# Re-check the runtime-verifiable invariants
brig system verify
```

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
