# Cell Definition Reference

A cell definition is a YAML or JSON file that describes a cell's configuration.
Use with `brig run --file mycell.yaml`.

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
trust_warden_ca: true

# Timeout
timeout: "30m"                   # Auto-kill after duration (30s, 5m, 2h, 1d)

# Workspace
workspace_quota: "500m"          # Max workspace size

# Cell rootfs writability. Default false (safe). When false, brig runs the
# cell with --read-only rootfs + sized tmpfs at /tmp (64m) and /run (16m).
# The cell can still write to /work (its workspace).
#
# Set to true for images whose entrypoint needs to write outside /work,
# /tmp, /run — e.g. legacy daemons that write to /var/log, dev images
# that install/build at runtime. Opting in means the cell can (a) DoS
# the shared VM disk by filling its writable layer, and (b) hide state
# outside the workspace across stop/start. Don't opt in for cells that
# run untrusted code.
writable_rootfs: false

# Execution mode
detach: false                    # Run in background

# Working directory inside container (default: /work)
workdir: /app

# Labels for filtering and identification
labels:
  team: platform
  purpose: scraping

# Ingress — authenticated reverse proxy for inbound traffic (optional)
# Warden routes external requests to cell-internal ports by path prefix.
# All ingress is token-authenticated and logged.
ingress:
  - name: api                   # Alphanumeric + hyphens, max 31 chars
    port: 8642                   # Cell-internal port (1-65535)
    path_prefix: /api            # Route prefix (must start with /)
    auth: token                  # Auth method (only "token" supported)
  - name: webhooks
    port: 8642
    path_prefix: /webhooks
    auth: token

# Host services — HTTP/HTTPS forwarding from cell to host port,
# routed through Warden under the <name>.host.brig virtual domain.
# Declaration here is the grant; no separate registration step.
host_services:
  - {name: db, port: 5432}
  - {name: litellm, port: 4000}

# Host sockets — bind-mount macOS unix sockets into the cell for
# non-HTTP protocols (Postgres, Redis, ssh-agent). Bytes flow
# kernel-direct; Warden is not in the path.
host_sockets:
  - name: postgres
    host_path: /tmp/postgres.sock
    mount_point: /run/host/postgres.sock
    mode: rw
```

## Ingress

Cells have no inbound connectivity by default. Declaring `ingress` enables
authenticated reverse proxying through Warden.

External requests reach the cell via:
```
https://warden:8443/{cell_name}/{path_prefix}/...
```

Requirements:
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
- Token-authenticated with salted SHA-256 hashing
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

## Host Sockets

Bind-mount macOS-side unix sockets into the cell at a path under
`/run/host/`. Bytes flow directly between the cell and the host
service through the kernel; Warden is not in the path. This is the
mechanism for non-HTTP services (Postgres, Redis, MySQL, ssh-agent)
that cannot traverse an HTTP proxy.

```yaml
host_sockets:
  - name: postgres                       # alphanumeric+hyphens, max 31 chars
    host_path: /tmp/postgres.sock        # absolute, must be a real unix socket
    mount_point: /run/host/postgres.sock # must start with /run/host/
    mode: rw                             # ro (default) or rw
```

Then from inside the cell:

```python
import psycopg
psycopg.connect("host=/run/host/postgres.sock dbname=app")
```

Requirements:

- `host_path` must exist on the macOS host and be a real unix socket
  (not a symlink, not a regular file)
- `socat` must be installed (`brew install socat`) — used by the
  launchd bridge
- Maximum 8 host_sockets per cell
- The `untrusted` profile rejects `host_sockets` at parse time:
  bypassing Warden via a kernel side channel is incompatible with
  the profile's threat model.

Security properties:

- Opt-in per cell yaml (no default access)
- Engine sockets (`docker.sock`, `podman.sock`, `containerd.sock`,
  `crio.sock`, `firecracker.sock`, `limactl.sock`) are denied
- Bridge sockets are real unix sockets — symlinks rejected at runtime
- Per-cell namespacing: two cells declaring the same physical service
  each get their own bridge instance
- Every attach is logged (`brig system history` or
  `~/.brig/state/system/lifecycle.jsonl`)
- Cell startup prints a NOTE that Warden does not see this traffic

Limitations:

- No per-request observability. Warden's HTTP audit does not apply
  to raw TCP or binary protocols.
- No automatic detection: every socket is declared in the cell yaml.
- Cannot expose services that lack a unix-socket transport. See
  [Not supported: raw TCP host services](#not-supported-raw-tcp-host-services)
  below for affected protocols and workarounds.

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

### Choosing between host_services and host_sockets

| | host_services | host_sockets |
|---|---|---|
| Protocol | HTTP/HTTPS only | Anything (TCP via unix socket) |
| Audit | Per-request through Warden | Connect/disconnect only |
| Address from cell | `<name>.host.brig` (DNS) | `/run/host/<name>.sock` (filesystem) |
| Setup | `host_services: [{name, port}]` | `host_sockets: [{name, host_path, mount_point}]` + socat |
| Use for | API gateways, model serving, anything HTTP | Postgres, Redis, MongoDB, MySQL, ssh-agent, anything with a unix socket |

Most database and RPC clients in active development support unix
sockets — Postgres, MySQL, Redis, MongoDB, and gRPC across most
languages. Combined with HTTP via `host_services` (egress) and
`ingress` (inbound), the unix-socket path via `host_sockets` covers
the common cell-to-host access patterns.

### Not supported: raw TCP host services

Brig does not currently expose raw TCP forwarding as a first-class
cell-yaml feature. The following patterns therefore have no
declarative form in brig today:

- **SSH from a cell to a host.** The SSH protocol requires a network
  endpoint and has no unix-socket transport.
- **Distributed or replica-set service discovery.** Mongo replica
  sets, etcd, Consul Connect, and similar protocols probe additional
  servers by DNS during connection setup. Single-instance access via
  unix socket works; replica-set discovery does not.
- **TLS services requiring strict SNI hostname verification.** When
  the client does not expose an option to override the expected
  hostname, the unix-socket transport cannot satisfy verification.
  This affects some enterprise JDBC drivers and some HTTPS libraries.
- **Legacy TCP-only drivers.** Database drivers that have not added
  unix-socket support (for example, older Oracle JDBC and some MSSQL
  TDS clients).

Adding first-class raw TCP host services is deferred pending a
concrete consumer. The open design decisions — per-cell port
allocation versus SNI demultiplexing, TLS termination versus
passthrough, per-cell connection budgets, and the audit-log shape —
are best resolved against the requirements of a specific protocol
rather than in the abstract.

Workarounds available today:

- Run a host-side tunnel that exposes the remote TCP endpoint as a
  unix socket, then declare that socket via `host_sockets`:

      socat UNIX-LISTEN:/tmp/db.sock,fork TCP-CONNECT:remote:5432

- Use SSH `LocalForward` to terminate at a unix socket on the host,
  declared via `host_sockets` as above.

- Run the dependent service inside the cell itself when isolation
  from the host is acceptable.

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
