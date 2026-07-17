# Cell Definition Reference

A cell definition is a YAML or JSON file that describes a cell's configuration.
Use with `brig run --file mycell.yaml`.

Unrecognized top-level keys (a typo, or a removed field such as `host_sockets`)
are **ignored**, but `brig run --file` and `brig cell preflight` print a warning
naming them — so a stray key never silently does nothing.

## Full Schema

```yaml
# Required
name: my-cell                    # Lowercase alphanumeric, max 63 chars
image: python:3.12               # Container image (OCI)

# Command (optional — defaults to image entrypoint).
# The cell stays running only as long as PID 1 (this command) is alive.
# If your command prints help and exits (a common default for CLI tools),
# the cell flips to `stopped` within milliseconds — which surprises users
# who want to attach via `brig cell exec` repeatedly. Either give the
# command its long-running mode (e.g. `["myapp", "serve"]`) or, for an
# explicitly long-lived "exec into me" cell, use `["sleep", "infinity"]`
# and drive work via `brig cell exec`.
command: ["python", "app.py"]    # List of strings, or single string

# Environment variables
env:
  APP_ENV: production            # Dict form: key-value pairs
  LOG_LEVEL: info
# Or list form:
# env:
#   - APP_ENV=production
#   - LOG_LEVEL=info

# Secrets — mounted read-only from ~/.brig/secrets/
secrets:
  - api-key                      # → /run/secrets/api-key (API_KEY_FILE env var)
  - db-password                  # → /run/secrets/db-password (DB_PASSWORD_FILE env var)

# Resource limits
memory: 2g                       # Memory limit (512m, 1g, 2g, 4g)
cpus: "2"                        # CPU limit (fractional OK: "0.5")
pids_limit: 512                  # Max processes (prevents fork bombs)

# Network mode
network: default                 # "default" = per-cell isolated network via Warden
                                 # "none"    = air-gapped, no network access

# Network policy. Per-cell — no global file to merge with. Trust
# profiles can contribute a baseline allow/deny that this block extends.
policy:
  allow:
    - "api.github.com"           # Simple domain string
    - "*.amazonaws.com"          # Wildcard (matches subdomains only)
    - domain: "api.example.com"  # Dict form with path/method restrictions
      paths: ["/v1/*"]
      methods: ["GET", "POST"]
  deny:
    - "*.evil.com"               # Deny rules take precedence over allow
  # Optional: hosts to skip Warden MITM for. Each entry must be covered
  # by an allow entry (exact or wildcard). Warden tunnels TCP raw after
  # the CONNECT, routed by SNI — for hosts whose TLS won't survive
  # mitmproxy (HPKP, ECH, Cloudflare bot-fp). Trades per-URL audit for
  # handshake compat + credential confidentiality. See invariant 11.
  tls_passthrough:
    - "chatgpt.com"
    - "auth.openai.com"

# Trust Warden's MITM CA out of the box. When true (default), brig stages
# a combined bundle (system roots + Warden CA) inside the VM and bind-
# mounts it read-only at /run/brig/ca-bundle.crt, plus sets SSL_CERT_FILE
# / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / NODE_EXTRA_CA_CERTS to point
# at it — only for env vars the cell didn't already declare. Set to
# false for cells with strict cert pinning or that manage their own
# trust store. See invariant 12.
#
# Foot-gun: do NOT also set SSL_CERT_FILE in your image's entrypoint
# or ENV. Brig's auto-mount only fills vars the cell didn't already
# declare — an entrypoint-side override points cells at a cached or
# stale CA, and silent TLS hangs follow when Warden's CA rotates
# (mitmproxy presents a valid cert client-side, the upstream handshake
# fails, the proxy drops with no signal back). `brig system doctor`
# now flags this by comparing each cell's staged ca-bundle.crt against
# Warden's current CA; run it if a previously-working cell starts
# hanging on HTTPS after a `brig system up/down` cycle.
#
# Related: if you `brig image build --use-warden`, do NOT COPY the
# warden CA from /etc/ssl/certs/warden-ca.crt into the final image.
# That bakes a soon-to-rotate CA into the layer; runtime cells then
# trust a stale cert. Mount-at-runtime is the supported pattern.
trust_warden_ca: true

# Timeout
timeout: "30m"                   # Auto-kill after duration (30s, 5m, 2h, 1d)

# Workspace
workspace_quota: "500m"          # Soft quota: enforced on `brig cp` + reactively by `brig system watchdog` (not a hard block-quota)
workspace_mount: /work           # Mount point for the cell's writable workspace (default /work)

# Cell rootfs writability. Default false (safe). When false, brig runs the
# cell with --read-only rootfs + sized tmpfs at /tmp (64m) and /run (16m).
# The cell can still write to /work (its workspace). Both tmpfs carry
# nosuid+nodev; /tmp is noexec, but /run is exec-capable so s6-overlay and
# other init systems (which exec their supervisor from /run/s6) can run.
#
# Set to true for images whose entrypoint needs to write outside /work,
# /tmp, /run — e.g. legacy daemons that write to /var/log, dev images
# that install/build at runtime. Opting in means the cell can (a) DoS
# the shared VM disk by filling its writable layer, and (b) hide state
# outside the workspace across stop/start. Don't opt in for cells that
# run untrusted code.
writable_rootfs: false

# Seccomp profile (optional). Filename of a profile staged under
# ~/.brig/cells/seccomp/ (e.g. default.json); must be a bare filename, never a
# path or "unconfined". Omit to use the container runtime's default profile.
seccomp_profile: default.json

# Execution mode
detach: false                    # Run in background

# Restart policy (default: no). "always" re-launches the cell on
# `brig system up` whenever its container is gone — e.g. a VM restart drops
# every container. brig persists the full spec at run time to replay it.
# An *exited* cell (still present, e.g. `brig cell stop`) is left alone, but a
# VM restart drops the container, so a stopped restart:always cell DOES
# relaunch on the next up; use `brig cell rm` to keep one down for good.
restart: always

# Process user (podman --user; uid[:gid] or name[:group]). Default: the image's
# USER. gVisor presents virtiofs host mounts (and /work) as owned by 0:0 inside
# the cell, so a non-root cell can't own a rw `mounts:` dir — set user: "0" to
# run the cell as root and let it fully read/write/rewrite the mount. Writes
# still land owned by the operator on macOS, so readback is unaffected. Running
# as root *inside* the gVisor+VM sandbox is not a host-privilege change.
user: "0"

# Working directory inside container (default: /work)
workdir: /app

# Labels for filtering and identification
labels:
  team: platform
  purpose: scraping

# Ingress — reverse proxy for inbound traffic (optional). Warden routes
# external requests to cell-internal ports by path prefix; all routes are logged.
#
# auth: token (default) — brig is the gate. The bearer token comes from a secret
#   named `<cell-name>-ingress-token` (preferred) or `ingress-token` (fallback);
#   register it before `brig run`, e.g.:
#     openssl rand -hex 32 | brig secrets add <cell-name>-ingress-token -
#   A cell that declares auth: token with no matching secret fails to start.
# auth: none — transparent pass-through: brig does NOT authenticate; the cell's
#   own app is the gate (the Authorization header and ?query are passed through
#   untouched). Use for services that authenticate themselves or for browser/
#   Electron WebSocket clients that can't send an Authorization header. The
#   trade-off is explicit, mirroring tls_passthrough: you give up brig's
#   perimeter gate for that route. Rejected on the `untrusted` profile and
#   announced at run time (audit event + operator NOTE). A route that omits
#   `auth` defaults to token (fail-secure).
ingress:
  - name: api                   # Alphanumeric + hyphens, max 31 chars
    port: 8642                   # Cell-internal port (1-65535)
    path_prefix: /api            # Route prefix (must start with /)
    auth: token                  # "token" (brig gates) or "none" (app gates)
  - name: dashboard             # e.g. a self-authenticating UI with WS
    port: 9119
    path_prefix: /dashboard
    auth: none

# Host services — forwarding from cell to host port, through Warden.
# Declaration here is the grant; no separate registration step.
#
# protocol: http (default) — L7 rewrite at <name>.host.brig (any path),
#                            full URL+method audit, MITM applies.
# protocol: tcp             — L4 forward via warden TCP listener.
#                            Cell connects to <name>.host.brig:<port>
#                            with a normal TCP client (psql, redis-cli,
#                            etc.). Audit is connection-level (cell,
#                            service, bytes, duration); no per-request
#                            inspection. Same trust boundary as HTTP
#                            host_services — warden stays in the path.
# Untrusted profile rejects both at parse time.
host_services:
  - {name: litellm, port: 4000}                          # HTTP (default)
  - {name: db, port: 5432, protocol: tcp}                # TCP — Postgres
  - {name: redis, port: 6379, protocol: tcp}             # TCP — Redis

# Host mounts — bind-mount a host directory into the cell, bounded by the
# VM-level `mount_roots` allowlist. ro by default; rw needs `user: "0"` (above).
# Warden does not mediate these bytes. supervised/dev only; untrusted rejects.
# See "Host Mounts" below and invariant 13.
mounts:
  - {name: repo, host_path: /Users/you/work/repo, mount_point: /workspace, mode: rw}
```

## Ingress

Cells have no inbound connectivity by default. Declaring `ingress` enables
reverse proxying through Warden — gated by a token (`auth: token`, default) or
transparent (`auth: none`, the app authenticates itself).

External requests reach the cell via:
```
https://warden:8443/{cell_name}/{path_prefix}/...
```

Requirements (`auth: token` routes — `auth: none` routes have none):
- Each request must include `Authorization: Bearer <token>`
- Token is stored as a Brig secret with a strict naming convention:
  - **Preferred:** `<cell-name>-ingress-token` — per-cell token, rotate
    independently of other cells. Example: cell named `aitelier` reads
    `~/.brig/secrets/aitelier-ingress-token`.
  - **Fallback:** `ingress-token` — a single shared token across all
    cells. Convenient for dev, not recommended for prod.
  - The cell-name-prefixed file wins when both exist.
  - If a cell declares `ingress` with `auth: token` and **neither**
    secret exists, `brig run` fails with a hard error pointing at the
    expected filename (see `brig cell preflight`).
  - Register with: `openssl rand -hex 32 | brig secrets add <cell-name>-ingress-token -`
- `network` must be `default` (ingress is incompatible with airgapped cells)
- Maximum 8 ingress entries per cell

Security properties:
- Opt-in (zero inbound unless declared)
- `auth: token` (default) gates with a salted-SHA-256 Bearer token; `auth: none`
  is transparent pass-through (the cell's app is the gate) — opt-in, rejected on
  the untrusted profile, audited at run time. A route omitting `auth` defaults to
  token (fail-secure).
- Path-scoped (only declared prefixes are routed)
- All inbound traffic logged
- CONNECT tunneling blocked on ingress port

## Policy Rule Formats

### String form
Matches all requests to the domain (any path, any method):
```yaml
allow:
  - "api.github.com"
  - "*.amazonaws.com"    # Wildcard: matches foo.amazonaws.com, NOT amazonaws.com
```

### Dict form
Restricts by path pattern and/or HTTP method:
```yaml
allow:
  - domain: "api.example.com"
    paths: ["/v1/*", "/v2/users"]    # fnmatch patterns
    methods: ["GET", "POST"]         # HTTP methods (case-insensitive)
```

## Secret Mounting Convention

When `--secret api-key` is specified:
1. File `~/.brig/secrets/api-key` is mounted read-only at `/run/secrets/api-key`
2. Environment variable `API_KEY_FILE=/run/secrets/api-key` is set

The env var name is derived from the filename:
- Extension stripped: `db-pass.txt` → `DB_PASS`
- Hyphens to underscores, uppercased
- `_FILE` suffix appended

Application reads the file at runtime — secret values never appear in env vars,
process listings, or container inspect output.

## Host Services

Cells cannot reach the macOS host by default; private IPs are blocked
by Warden. Host services expose specific host-side HTTP/HTTPS services
to a cell through virtual `<name>.host.brig` domains. Traffic is
routed through Warden, so every request is HTTP-audited.

Declaration lives entirely in the cell yaml; there is no separate
global registry or per-cell ACL:

```yaml
host_services:
  - {name: db, port: 5432}
  - {name: litellm, port: 4000}
```

From inside the cell:
```bash
curl http://db.host.brig/health
curl http://litellm.host.brig/v1/chat/completions
```

Warden intercepts `<name>.host.brig` requests, looks up the port in the
cell's own host_services map, and rewrites to (host_ip, port). The cell
never sees the real host IP.

Security properties:

- Only declared services are reachable; this is not a blanket
  private-IP bypass.
- The cell yaml is the grant. No separate registration step is
  required or supported.
- Cells without `host_services` in yaml have no host-service access.
- All traffic is logged with `host_service` attribution.
- Virtual domains only resolve through the proxy.
- Unknown `.host.brig` domains are blocked.
- The `untrusted` profile rejects `host_services` at parse time.
- DNS rebinding to `(host_ip, host_service_port)` from an allowlisted
  domain is detected. The host-service skip on `BLOCKED_NETWORKS` is
  gated on `flow.metadata["host_service"]`, not on the destination
  tuple, so a poisoned DNS response cannot reuse the exemption.

### Choosing HTTP vs TCP host_services

| | `host_services` (HTTP, default) | `host_services` (`protocol: tcp`) |
|---|---|---|
| Protocol | HTTP/HTTPS | Any TCP wire protocol |
| Audit | Per-request through Warden (URL+method) | Connection-level (cell, service, bytes) |
| Address from cell | `<name>.host.brig` (any path) | `<name>.host.brig:<port>` |
| Use for | API gateways, model serving, anything HTTP | Postgres, Redis, MongoDB, MySQL, gRPC — anything TCP |

Both keep Warden in the path. HTTP host_services get full per-request
audit; TCP host_services trade that for raw-byte forwarding (the only
option for binary DB wire protocols). Combined with `ingress` (inbound),
these cover the cell-to-host access patterns.

### Raw TCP host services (via `protocol: tcp`)

Cells reach TCP services on the host with the same `host_services`
block, using `protocol: tcp`. Warden binds a listener per declared
port (mitmproxy `--mode reverse:tcp`) and forwards raw bytes to
`host.lima.internal:<port>` — single trust boundary, connection-level
audit (no per-message body inspection, which is opaque for binary DB
wire protocols anyway).

```yaml
host_services:
  - {name: db, port: 5432, protocol: tcp}     # Postgres
  - {name: redis, port: 6379, protocol: tcp}
  - {name: mongo, port: 27017, protocol: tcp}
```

In the cell, the upstream is reachable on the same port with a normal
TCP client:

    psql -h db.host.brig -p 5432 ...
    redis-cli -h redis.host.brig -p 6379 ...

Operational notes:

- **First add of a TCP service triggers a warden restart** so the new
  `--mode reverse:tcp` listener binds. `brig run` prompts before
  restart (warden restart drops every running cell's open egress for
  ~5s). Re-run with `--yes` to auto-confirm.
- **Reserved ports**: 8080 (warden HTTP proxy) and 8443 (ingress) are
  rejected at parse time.
- **Untrusted profile** rejects `protocol: tcp` — adversarial cells
  stay HTTP-only and inspectable.
- **TCP host_services bypass mitmproxy MITM** — no URL audit, no body
  inspection. Audit shape is connection-level (cell, service, bytes,
  duration) via `tcp_start`.

Patterns where TCP host_services are the right answer:

- Database protocols (Postgres, MySQL, MongoDB, Redis, Cassandra)
- SSH from cell to a host bastion
- gRPC-over-h2c
- Replica-set / service discovery that probes by DNS
- Legacy TCP-only drivers (Oracle JDBC, MSSQL TDS)

TCP host_services keep warden in the path for audit + connection limits.

## Host Mounts

Bind-mount an operator-chosen host directory into the cell (ro default, rw
opt-in). For a sandboxed agent that edits a real host folder in place. See
`docs/design/host-mounts.md`.

```yaml
mounts:
  - {name: repo, host_path: /Users/you/work/repo, mount_point: /workspace, mode: rw}
  - {name: refdata, host_path: /Users/you/work/corpus, mount_point: /data}   # mode: ro default
```

Prerequisite — declare the allowlisted root(s) once (VM-level; a VM recreate
applies the change):

```
brig config set mount_roots /Users/you/work
```

Rules:
- `host_path` realpath must resolve under a configured `mount_roots` entry and
  be an existing directory.
- `mount_roots` may not be `/`, `$HOME`, `~/.ssh`/`~/.aws`/`~/.gnupg`/…, `~/.brig`,
  `/etc`, or an ancestor/descendant of those; each root's basename (its
  `/mnt/host/<slug>`) must be unique.
- `mount_point` must be absolute, not shadow a system path or the cell's
  workspace mount (`/work`).
- Maximum 8 mounts per cell.
- The `untrusted` profile rejects `mounts:` at parse time.
- **Warden does not see these bytes** (a deliberate bypass). The cell can't
  symlink-escape the subtree (mount-namespace isolation), but it *can* plant a
  symlink a host consumer might follow — scan with `brig cell mount-scan <cell>`
  before consuming cell-written files, and treat them as untrusted.

## Examples

### Minimal
```yaml
name: hello
image: alpine
command: ["echo", "hello world"]
```

### Web scraper
```yaml
name: scraper
image: python:3.12
command: ["python", "scrape.py"]
memory: 1g
cpus: "2"
secrets:
  - api-key
policy:
  allow:
    - "api.target-site.com"
    - "*.cdn.target-site.com"
env:
  TARGET_URL: https://api.target-site.com/v1/data
```

### Untrusted code analysis
```yaml
name: analysis
image: ubuntu:24.04
command: ["/bin/bash", "analyze.sh"]
memory: 512m
cpus: "1"
pids_limit: 256
network: none          # No network — fully air-gapped
timeout: "10m"         # Auto-kill after 10 minutes
```
