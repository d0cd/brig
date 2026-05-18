# Warden Addons

Warden's behavior is composed from mitmproxy addons mounted into the warden
container. This page lists each addon, what it does, whether it's required,
and how to configure it.

Addons live in `src/addons/` (host) and are copied to `~/.brig/cells/addons/`
by `make _copy-addons`. They run inside the warden container at `/addons/`.

## Required addons

These load on every `brig system up`. Without them the proxy refuses to start.

### `_common.py`

Not actually loaded as a mitmproxy script — it's a sibling module that other
addons import for the single source of truth on:

- `BLOCKED_NETWORKS` (RFC1918, localhost, CGNAT, link-local, IPv4-mapped-IPv6, etc.)
- `SubnetResolver` (IP → cell-name lookup against `subnet-map.json`)
- `atomic_write_json` (tempfile + fsync + rename)

If you add a new addon that resolves cell IDs or writes JSON state, import
from here rather than copying.

### `enforce.py`

The policy gate. For every request:

1. Check listen port (egress on 8080, ingress on 8443).
2. If the request targets `<name>.host.brig`, route to host services (per-cell ACL gated).
3. Reject non-80/443 ports.
4. Reject literal IPs and internal IP ranges.
5. Reject Host-header smuggling (CR/LF/NUL or Host ≠ URL host).
6. Apply per-cell policy (deny-then-allow); if the cell has no per-cell policy, fall through to global.
7. Apply global policy; default deny.

Also installs `server_connected` and `responseheaders` hooks that close
connections that resolve into `BLOCKED_NETWORKS` (DNS rebinding defense). The
skip for host-service rewrites is gated on `flow.metadata["host_service"]`,
not on a `(ip, port)` tuple.

Configured via `~/.brig/cells/network-policy.json`:

```json
{
  "allow": ["pypi.org", "*.pythonhosted.org"],
  "deny": ["*.evil.com"],
  "host_services": [{"name": "mydb", "port": 5432}]
}
```

Per-cell overrides go in `~/.brig/state/system/policies/<cell>.json` (managed
via `brig policy set <cell>`).

### `logger.py`

Per-cell JSONL request log under `/var/log/brig/network/<cell>.jsonl`.
Async writer with hybrid time/size flush. Cell name is validated against
`^[a-z0-9][a-z0-9._-]{0,62}$` to prevent path traversal in log filenames.

Log fields: `ts, cell, src_ip, method, host, path, status, bytes, ms,
blocked, block_reason, cert_issuer, cert_flags, host_service`.

Configured via the `log_filter` block in `network-policy.json`:

```json
{
  "log_filter": {
    "min_status": 0,
    "exclude_hosts": ["status.example.com"],
    "exclude_paths": ["/health"],
    "only_blocked": false,
    "sample_rate": 1.0
  }
}
```

### `ops.py`

Operational concerns previously split across separate addons:

- Rate limiting (per-cell request budgets).
- Health endpoint.
- Metrics counters.

## Optional addons

Loaded only if the file exists in `~/.brig/cells/addons/`.

### `ingress.py`

Authenticated reverse proxy on port 8443. Routes external requests to a
cell-internal port:

```
GET https://warden:8443/{cell}/{prefix}/...
  → http://{cell_ip}:{cell_port}/...
```

Auth: salted SHA-256 token compared with `hmac.compare_digest`. Per-IP auth
failure rate limit (10 failures per minute, LRU-evicted at 10k tracked IPs).

Routes are written by `brig run` based on the cell's `ingress` field; tokens
are read from `~/.brig/secrets/<cell>-ingress-token` (or generic
`ingress-token` as fallback). Path goes through `validate_secret_path` to
prevent symlink escape.

### `notifier.py`

Webhook on blocked requests. Validates webhook URLs against `BLOCKED_NETWORKS`
to prevent SSRF, resolves DNS once and connects to the resolved IP
(blocking DNS rebinding), uses urllib3 with `cert_reqs=CERT_REQUIRED` and
a CA bundle. The urllib fallback path explicitly disables HTTP redirects.

Circuit breaker (configurable failure threshold / recovery timeout) +
exponential backoff retries + dead-letter queue for failed notifications.

## How addons load

The warden container is started with one `-s /addons/<file>.py` per addon by
`src/warden/proxy.py`. `ingress.py` loads first when present so it can tag
authenticated ingress flows with `flow.metadata["ingress"]` before
`enforce.py` checks the flag and short-circuits.

To debug load order or see which addons are active, check `warden logs`
during startup — each addon logs a `Loading…` / `Loaded` pair.
