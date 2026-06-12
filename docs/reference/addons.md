# Warden Addons

Warden's behavior is composed from mitmproxy addons mounted into the warden
container. This page lists each addon, what it does, whether it's required,
and how to configure it.

Addons live in `src/brig/warden_addons/`, shipped with brig as package-data (so
they're present in any install, editable or wheel). `brig system up` syncs them
into `~/.brig/cells/addons/` — and bounces warden if any changed — so the
deployed copy can't silently drift from the installed package; `make _copy-addons`
does the same one-shot staging at first setup. They run inside the warden
container at `/addons/`, flat-loaded by mitmproxy (each addon imports its
siblings as flat modules, e.g. `from _common import ...`), which is why they are
data rather than an importable `brig` submodule.

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
2. If the request targets `<name>.host.brig`, route to host services
   via the cell's own `host_services` map (declared in the cell yaml).
3. Reject non-80/443 ports.
4. Reject literal IPs and internal IP ranges.
5. Reject Host-header smuggling (CR/LF/NUL or Host ≠ URL host).
6. Apply per-cell policy (deny-then-allow). Cells with no per-cell
   policy block everything — fail closed, no implicit global allow.

Also installs a `responseheaders` hook that blocks responses whose
server peer resolved into `BLOCKED_NETWORKS` (DNS rebinding defense).
The skip for warden-routed flows is gated on `flow.metadata["host_service"]`
/ `["ingress_route"]`, not on a `(ip, port)` tuple. (Prior versions also
ran the check in `server_connected`, but mitmproxy ≥ 10 removed
`data.server.close()` so the kill silently no-op'd and `data.flow` was
None there anyway — see `docs/INVARIANTS.md` invariant 2.)

A `tls_clienthello` hook implements invariant 11 (TLS passthrough): for
hosts that match both `policy.allow` and `policy.tls_passthrough` AND
whose SNI equals the CONNECT host, warden tunnels TCP raw instead of
MITM-ing. Fails closed: if the CONNECT host can't be read (mitmproxy
API quirk) or SNI doesn't match, passthrough is NOT flipped — the
flow falls through to MITM and the cell sees a cert error.

A `tcp_start` hook gates per-cell access for raw TCP `host_services`
(invariant 11/MVP+):
  - Resolves cell from peer IP via the subnet-map.
  - Loads the cell's per-cell policy.
  - Allows only if the listening port appears in `cell.tcp_host_services_map`.
  - Tags `flow.metadata["host_service_protocol"] = "tcp"` so otel_export
    emits per-service counters; logger writes a `TCP HOST_SERVICE`
    audit line.
  - Skips TLS-passthrough flows (different mechanism).
  - Fail-closed on any unexpected mitmproxy API shape.

**NOTE — passthrough emits no per-byte/connection metrics.** TLS passthrough
engages via `data.ignore_connection`, which makes mitmproxy build an *ignored*
TCP layer with no flow object — so `otel_export.py`'s `tcp_start` /
`tcp_message` / `tcp_end` hooks never fire for passthrough, and the
`warden_passthrough_*` counters they define are not produced. The only
passthrough audit is the connection-level `PASSTHROUGH: cell=… sni=…` log line
emitted by `enforce.py:tls_clienthello`. (The hooks remain for a possible
future flow-bearing relay; see `docs/INVARIANTS.md` invariant 11.)

These surface in `brig system stats` as `PT/CONN` / `PT/IN` / `PT/OUT`
columns (the `PT/*` callout appears when any cell had passthrough
connections).

Allow/deny and `host_services` are **per-cell** — each cell's policy lives in
`~/.brig/state/system/policies/<cell>.json` (managed via `brig policy set
<cell>`). A cell with no policy file is blocked (default deny):

```json
{
  "allow": ["pypi.org", "*.pythonhosted.org"],
  "deny": ["*.evil.com"],
  "host_services": [{"name": "mydb", "port": 5432}]
}
```

The process-wide `~/.brig/cells/network-policy.json` carries no allow/deny —
the enforce addon reads only its `policy_trace` block from there.

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

Reverse proxy on port 8443. Routes external requests to a cell-internal port:

```
GET https://warden:8443/{cell}/{prefix}/...
  → http://{cell_ip}:{cell_port}/...
```

Auth is per-route: `auth: token` (default) compares a salted SHA-256 Bearer
token with `hmac.compare_digest` (per-IP failure rate limit: 10/min, LRU-evicted
at 10k tracked IPs); `auth: none` is transparent pass-through — no token check,
`Authorization` forwarded untouched for the cell's app to authenticate. A route
missing `auth` is treated as `token` (fail-secure).

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

**`novel_allowed` — first-seen detection on allow-listed hosts.** Blocked-alerting
catches "tried somewhere new"; this catches "used an allowed destination a new
way" — where telemetry/exfil hide, since they ride a host you *had* to allow and
are never blocked. On each allowed response it keys `(cell, host,
path-template)` (high-cardinality segments — ids/hashes/uuids/tokens — collapse
to `{id}`; query stripped) and alerts the first time a key is seen. A separate
`suspicious_query` signal flags an over-long query string on an already-known
path (the exfil channel path-novelty can't see); it reports the query *length*,
never its content. The baseline is seeded from the cell's existing
`/var/log/brig/network/<cell>.jsonl` on load, so a warden restart doesn't replay
known paths as novel. Default off; opt in per cell and **run `dry_run` first** to
confirm the baseline + ignore-lists are tight before enabling delivery:

```json
"notifications": {
  "webhook_url": "https://example.com/webhook",
  "novel_allowed": {
    "enabled": true,
    "cells": ["sandbox-agent", "hermes"],
    "ignore_hosts": ["pypi.org"],
    "ignore_paths": ["^/v1/acp/"],
    "dry_run": false,
    "max_query_len": 512
  }
}
```

Limits: `tls_passthrough` hosts expose SNI only (no path), so novelty there is
host-level (== the allowlist); and data smuggled in a POST *body* on a known path
is out of scope (path-template + query-length don't see it).

## How addons load

The warden container is started with one `-s /addons/<file>.py` per addon by
`src/warden/proxy.py`. `ingress.py` loads first when present so it can tag
authenticated ingress flows with `flow.metadata["ingress"]` before
`enforce.py` checks the flag and short-circuits.

To debug load order or see which addons are active, check `warden logs`
during startup — each addon logs a `Loading…` / `Loaded` pair.
