# Cell Definition Reference

A cell definition is a YAML or JSON file that describes a cell's configuration.
Use with `brig run --file mycell.yaml`.

## Full Schema

```yaml
# Required
name: my-cell                    # Lowercase alphanumeric, max 63 chars
image: python:3.12               # Container image (OCI)

# Command (optional — defaults to image entrypoint)
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

# Network policy (per-cell override, merged with global policy)
policy:
  allow:
    - "api.github.com"           # Simple domain string
    - "*.amazonaws.com"          # Wildcard (matches subdomains only)
    - domain: "api.example.com"  # Dict form with path/method restrictions
      paths: ["/v1/*"]
      methods: ["GET", "POST"]
  deny:
    - "*.evil.com"               # Deny rules take precedence over allow

# Timeout
timeout: "30m"                   # Auto-kill after duration (30s, 5m, 2h, 1d)

# Workspace
workspace_quota: "500m"          # Max workspace size

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
- Token is stored as a Brig secret: `brig secrets add {cell}-ingress-token`
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

## Host Services

Cells cannot reach the macOS host by default (private IPs are blocked).
Host services allow cells to reach specific host-side services through
virtual `.host.brig` domains.

Declaration is two-step:

1. **Global policy** declares the (name → port) mapping that warden knows
   how to forward:
   ```bash
   brig policy set global --host-service aitelier:7777
   brig policy set global --host-service litellm:4000
   ```

2. **Per-cell policy** opts the cell into reaching specific services. By
   default a cell has *no* host-service access; you must add the names you
   want it to reach (audit fix H1):
   ```bash
   brig policy set hermes --host-service aitelier
   ```

   Or write the per-cell policy file directly:
   ```json
   {
     "allow": ["api.github.com"],
     "deny": [],
     "host_services": ["aitelier"]
   }
   ```

From inside the cell:
```bash
curl http://aitelier.host.brig/v1/health
```

Warden intercepts `.host.brig` requests and rewrites them to the macOS
host IP + declared port. The cell never sees the real host IP.

Security properties:
- Only declared services are reachable (not a blanket private IP bypass)
- A cell can only reach services in **its own** `host_services` list
  (per-cell ACL — global declaration is necessary but not sufficient)
- Cells with no per-cell policy have **no** host-service access
- All traffic logged with `host_service` attribution
- Virtual domains only resolve through the proxy
- Unknown `.host.brig` domains are blocked
- DNS rebinding to `(host_ip, host_service_port)` from an allowlisted
  domain is detected: the host-service skip on `BLOCKED_NETWORKS` is
  gated on `flow.metadata["host_service"]`, not on the destination tuple
  (audit fix H4)

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
