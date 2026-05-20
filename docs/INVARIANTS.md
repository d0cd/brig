# Brig Security Invariants — Living Ledger

The 9 invariants from [docs/design/security.md](design/security.md) are the
thing this project exists to uphold. This document is the single source of
truth for **which tests prove them** and **which CI lane runs those tests**.

If you break a test named here, you're breaking an invariant. If you add a
new invariant, add a row. If you add a test that proves an invariant, add it
to that invariant's row — don't leave the coverage implicit.

## How to read this

- **Unit** — runs on every PR under `.github/workflows/ci.yml` on Ubuntu. No VM.
- **E2E** — runs on PRs touching `src/**`, `tests/**`, or CI config, under
  `.github/workflows/e2e.yml` on macos-15 with a real Lima VM + podman + gVisor.
- **Code location** — where the invariant is enforced in production code.

## Invariant ledger

### 1. No East-West Traffic (per-cell internal networks)

| Surface | Location |
|---|---|
| Enforcement | `src/brig/security/verify.py:verify_network_isolation`; per-cell `--internal` network created in `src/brig/cell/reconciler.py` |
| Cell-def guard | `src/brig/cell/spec.py:validate_cell_definition` rejects `network: proxy-external` and non-default/none values |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_list_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifyNetworkIsolation` |
| E2E test | `tests/test_vm_foundation.sh` — east-west ping from cell A to cell B must fail |
| CI | Unit + E2E |

### 2. Proxy Cannot Be Abused as Gateway

| Surface | Location |
|---|---|
| Enforcement | `src/addons/enforce.py` — port allowlist (80/443), literal-IP block, RFC1918/CGNAT/etc block at request + http_connect + responseheaders |
| Blocklist source | `src/addons/_common.py:BLOCKED_NETWORKS` — single source shared by enforce + notifier |
| DNS rebinding defense | `responseheaders` re-checks resolved IP (`flow.server_conn.peername`) against `BLOCKED_NETWORKS`. Skip is **gated on `flow.metadata["host_service"]` / `["ingress_route"]`** (populated by `_handle_host_service` / ingress.py), not on a `(ip, port)` tuple — a tuple skip would let a DNS-rebinding allowlisted domain reach a host service. The check used to ALSO run in `server_connected`, but `data.server.close()` no longer exists on mitmproxy >= 10 (raised AttributeError, masked the would-be block) AND `data.flow` was None there so exemptions didn't fire either. Aitelier diagnosed; check now lives only in `responseheaders` where metadata is populated. |
| Host header smuggling | `_host_header_mismatches` in `request()` and `http_connect()`. Multi-colon strings validated via `ipaddress.ip_address` so non-IPv6 inputs like `example.com:80:extra` don't silently get treated as bare IPv6. |
| Host services | `.host.brig` virtual domains are an intentional, scoped relaxation of this invariant. The cell yaml declares `host_services: [{name, port}]`; that declaration is the sole grant. Warden reads the port from the cell's own per-cell policy file (there is no separate global registry). Cells without `host_services` in yaml have no host-service access. Unknown `.host.brig` domains are blocked. The `untrusted` profile rejects `host_services` at parse time. See `_handle_host_service()` in `src/addons/enforce.py`. |
| Ingress | Warden ingress (port 8443) allows authenticated inbound traffic to cells. enforce.py blocks unhandled ingress requests (fail closed). CONNECT is blocked entirely on the ingress port. See `src/addons/ingress.py`. |
| Unit test | `tests/test_addons_ops.py` — token bucket rate limiting |
| Unit test | `tests/test_ingress.py` — ingress routing, token auth, cell IP validation (rejects `.0` / `.1` / `.255`), rate limiting |
| Unit test | `tests/test_security_audit.py::TestResponseHeadersDnsRebinding` — RFC1918, localhost, link-local, IPv4-mapped-IPv6, IPv6 link-local; flow-metadata-gated host-service / ingress-route skip; a naked tuple match must NOT bypass |
| Unit test | `tests/test_security_audit.py::TestConnectMethodEnforcement` — CONNECT to disallowed port / internal IP / literal IP / disallowed domain / ingress port |
| Unit test | `tests/test_security_audit.py::TestNormalizeHostspecRobustness` — bracketed IPv6, multi-colon non-IPv6 strings |
| Unit test | `tests/test_security_audit.py::TestHandleHostService` — per-cell ACL: cell with no per-cell policy is blocked; cell whose policy doesn't list the service is blocked |
| Unit test | `tests/test_addon_common.py::TestBlockedNetworks` — covers every entry in the SSRF blocklist |
| E2E test | `tests/test_proxy_policy.sh` tests 7-11 — asserted via JSONL log entries |
| CI | Unit + E2E |

### 3. Secrets Are Observable, Not Preventable

**Not testable by design.** A cell with access to a mounted secret can send
it to any allowlisted destination. The design choice is observability via
proxy logs, not prevention.

### 4. macOS State Directory Is Untrusted

| Surface | Location |
|---|---|
| Path validation | `src/brig/security/secrets.py:validate_secret_path` — resolve + relative_to |
| Unit test | `tests/test_security_secrets.py::TestValidateSecretPath` — legit file, symlink escape, double-hop symlink, nonexistent secret |
| E2E test | `tests/test_hardening.sh` |
| CI | Unit + E2E |

### 5. gVisor Must Be Active (no silent downgrade)

| Surface | Location |
|---|---|
| Enforcement | `src/brig/cell/reconciler.py:build_run_command` hardcodes `--runtime runsc` |
| Verify check | `src/brig/security/verify.py:verify_gvisor_runtime` |
| Unit test | `tests/test_cell_reconciler.py::TestBuildRunCommand::test_runtime_always_runsc` |
| Unit test | `tests/test_security_verify.py::TestVerifyGvisorRuntime::test_runtime_downgrade` |
| E2E test | `tests/test_cell_lifecycle.sh` — dmesg grep for "Starting gVisor" |
| CI | Unit + E2E |

### 6. Only Infrastructure Containers May Attach to proxy-external

| Surface | Location |
|---|---|
| Cell-def guard | `src/brig/cell/spec.py:validate_cell_definition` rejects `network: proxy-external` |
| Verify check | `src/brig/security/verify.py:verify_proxy_network` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_arbitrary_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifyProxyNetwork` |
| CI | Unit + E2E |

### 7. No Privileged Services on Cell Networks

| Surface | Location |
|---|---|
| Verify check | `src/brig/security/verify.py:verify_cell_network_members` — flags any member of a `brig-<cell>` network that isn't warden or the cell itself |
| Unit test | `tests/test_security_verify.py::TestVerifyCellNetworkMembers::test_foreign_container` |
| Unit test | `tests/test_security_verify.py::TestVerifyCellNetworkMembers::test_only_warden_and_cell` |
| Gap | No E2E test that actually attaches a foreign container and asserts detection. Tracked for a future E2E test pass. |
| CI | Unit |

### 8. Cells Must Be Single-Homed

| Surface | Location |
|---|---|
| Cell-def guard | `src/brig/cell/spec.py:validate_cell_definition` rejects list network values |
| Verify check | `src/brig/security/verify.py:verify_single_homed` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_list_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifySingleHomed::test_multi_homed` |
| CI | Unit + E2E |

### 9. Proxy Must Be Running Before Cells Start

| Surface | Location |
|---|---|
| Enforcement | `src/brig/cell/lifecycle.py:run_cell` checks `proxy_running()` early |
| Unit test | `tests/test_cell_lifecycle.py::TestRunCell::test_invariant_9_proxy_must_be_running` |
| E2E test | `tests/test_cell_lifecycle.sh` |
| CI | Unit + E2E |

### 10. host_sockets Bypass Warden by Design

The prior nine invariants imply "Warden sees all cell traffic." That is
not literally true once host_sockets are declared. The bytes flowing
over a bind-mounted unix socket move through the kernel directly between
the cell and the host service — no proxy interposition possible. This
is the trade-off for supporting non-HTTP services (Postgres, Redis,
ssh-agent) that cannot meaningfully traverse an HTTP proxy.

The invariant we DO uphold:

  - host_sockets are opt-in per cell yaml (no default access)
  - The `untrusted` profile cannot declare them at all (parse-time reject)
  - Engine sockets (docker.sock, podman.sock, etc.) are denylisted at
    parse time AND at bridge start (defense in depth)
  - Bridge sockets are real unix sockets, never symlinks (lstat check)
  - Per-cell namespacing — cell A's bridge cannot be reused by cell B
  - Every attach is audited (`log_lifecycle("host_socket_attach", ...)`)
  - The cell startup banner explicitly says Warden does not see the
    traffic, so operators internalize the trade-off

| Surface | Location |
|---|---|
| Parse-time guards | `src/brig/cell/spec.py:_v_host_socket_entry`, `_v_host_sockets` |
| Engine denylist | `src/brig/config.py:HOST_SOCKET_ENGINE_DENYLIST` |
| Runtime TOCTOU | `src/brig/cell/reconciler.py:_attach_host_sockets` (lstat, S_ISSOCK) |
| Bridge defense | `src/brig/cell/host_sockets_bridge.py:_validate_target` |
| Audit | `src/brig/cell/lifecycle.py:run_cell` emits `host_socket_attach` |
| Banner | `src/brig/cell/lifecycle.py:run_cell` prints NOTE on cells with sockets |
| Unit tests | `tests/test_host_sockets_spec.py` (19 cases) |
| Unit tests | `tests/test_reconciler_host_sockets.py` (7 cases) |
| Unit tests | `tests/test_host_sockets_bridge.py` (9 cases) |
| Unit tests | `tests/test_metadata_host_sockets.py` (3 cases) |
| CI | Unit |

### 11. TLS Passthrough Is an Explicit, Opt-In TLS-Handling Override

Some hosts (Cloudflare-fronted endpoints, sites with HPKP / Encrypted Client
Hello / strict ALPN-cipher pinning) refuse mitmproxy's relayed TLS
handshake. The operator can opt the cell out of MITM for a specific host
by adding it to `policy.tls_passthrough` in the cell yaml. The host then
flows through Warden as a raw TCP tunnel after the CONNECT, routed by SNI.

This is a deliberate **security model shift** for that host. Brig's MITM
default offers full URL/body audit but loses on (a) strict-TLS compat and
(b) credential confidentiality vs. Warden. Passthrough flips both — gains
compat + confidentiality, loses per-URL audit + body inspection. The
trade-off is documented and opt-in per host so the operator's act of
adding the entry IS the security review.

The invariants we DO uphold for passthrough hosts:

  - **Passthrough is opt-in per cell per host.** No default-passthrough
    list. A cell with no `tls_passthrough:` block behaves exactly as today.
  - **Passthrough hosts MUST also appear in `policy.allow`.** Passthrough
    is a TLS-handling override, NOT a policy bypass. Validated at parse
    time — a `tls_passthrough` entry without a matching `allow` entry is
    a hard validation error. Without this guard, an operator could opt a
    host out of MITM without ever granting it allow, silently leaking
    egress past the policy.
  - **SNI in the client hello must match the CONNECT host** (Phase 2).
    Otherwise a malicious cell could CONNECT to allowed-host:443 then
    send SNI=attacker.com to abuse Warden as a generic TLS tunnel.
  - **Audit log entries are tls_mode-tagged.** Passthrough records carry
    SNI + bytes + duration; per-URL/body attributes are absent **by
    construction** (Warden never decrypted them). Operators can grep for
    `tls_mode=passthrough` to enumerate uninspected flows (Phase 3).
  - **Untrusted profile cannot declare passthrough** (Phase 1 follow-up).
    The trade-off requires informed operator consent; untrusted profiles
    don't get to make that choice.

| Surface | Location |
|---|---|
| Cell-def guard | `src/brig/cell/spec.py:_v_policy` — cross-field check that every `tls_passthrough` host appears in `allow`; rejects passthrough under the untrusted profile |
| Spec field | `src/brig/cell/spec.py:CellSpec.policy_passthrough_tls` |
| YAML flattening | `src/brig/commands/lifecycle_cmd.py` (`policy.tls_passthrough` → `policy_passthrough_tls`) |
| Profile propagation | `src/brig/cell/profiles.py` (profile-level `policy.tls_passthrough` prepends to cell's list) |
| Per-cell policy write | `src/brig/commands/lifecycle_cmd.py:_sync_cell_policy` writes `tls_passthrough` to `<cell>.json` |
| Policy class | `src/addons/_policy.py:Policy.is_passthrough` — defense-in-depth: a host must match BOTH passthrough rules AND allow rules (a tampered policy file can't opt a host out of MITM without allow coverage) |
| Addon hook | `src/addons/enforce.py:tls_clienthello` — reads SNI, flips `client_conn.tls_passthrough` when matched, blocks SNI/CONNECT mismatches |
| OTel counters | `src/addons/otel_export.py:tcp_start/tcp_message/tcp_end` — `warden_passthrough_connections_total`, `warden_passthrough_bytes_total{direction}`, `warden_passthrough_duration_ms` |
| Log shape | `src/addons/otel_export.py` tags MITM records with `tls_mode=mitm`, passthrough records with `tls_mode=passthrough`. Passthrough records omit method/path/status BY CONSTRUCTION (warden never saw them) |
| CLI rendering | `src/brig/commands/network_cmd.py:_print_network_line` renders passthrough lines as `PASSTHROUGH <host> (NB in / NB out)` — visually distinct from `OUT:` and `INGRESS:` |
| Unit tests | `tests/test_cell_spec.py::TestValidateCellDefinition::test_policy_tls_passthrough_*` (4 cases) |
| Unit tests | `tests/test_passthrough_tls.py` (10 cases — `is_passthrough` defense-in-depth, wildcard semantics, untrusted-profile rejection, per-cell-policy persistence, CLI render) |
| Unit tests | `tests/test_cell_profiles.py::test_policy_tls_passthrough_propagates_from_profile` |
| CI | Unit |

**Not yet landed** (tracked separately):

  - E2E: `tests/test_passthrough_tls.sh` against a Cloudflare-fronted host (e.g. chatgpt.com), validating both the handshake-survives path and the SNI/CONNECT-mismatch rejection.

### 12. Warden CA Auto-Mount Is Per-Cell, Re-Extracted From Container, Opt-Out-Able

Cells need to trust Warden's MITM CA to make HTTPS requests; without
this, every consumer rediscovers the workaround (mount CA, concat onto
system roots, export SSL_CERT_FILE / REQUESTS_CA_BUNDLE / etc.). Brig
stages a combined bundle (system roots + Warden CA) inside the VM and
bind-mounts it read-only at `/run/brig/ca-bundle.crt`, then sets
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` /
`NODE_EXTRA_CA_CERTS` to point at it — but only when the cell hasn't
already set those env vars.

The invariants we DO uphold:

  - **Bundle source of truth is a persistent VM-side dir owned by uid 1000.**
    Warden's mitmproxy state lives at `/var/lib/warden/mitmproxy-state/`
    (chowned to 1000:1000 by `warden start` before the bind mount, so
    mitmproxy can write its CA + key). Brig reads the cert from there
    via a direct `cat`, no `podman exec` — eliminates the auto-sudo trap
    in vm_run (only specific cmd[0] values get sudo'd; `sh -c '...'`
    wrappers don't) AND removes the dependency on warden being live at
    cell-start time. A tamperer who writes to `~/.brig/state/` (invariant
    4: untrusted) still cannot poison the bundle because the bundle is
    staged into `/state/<cell>/` which is on the VM trust boundary, not
    macOS.
  - **CA generated eagerly at `warden start`, not on first proxied
    request.** `warden start` polls `/var/lib/warden/mitmproxy-state/
    mitmproxy-ca-cert.pem` for up to 30s after the container is healthy
    and refuses to declare warden ready until the cert exists. Cells
    that race a fresh `brig up` can no longer get an empty / missing
    bundle. (Aitelier diagnosed all three of: lazy CA gen, root-owned
    tmpfs, and sh-c bypassing auto-sudo. Each is structurally fixed.)
  - **Bundle staged inside the VM, not on macOS.** Lima's `/state` virtio
    mount is the trust boundary; the file lives at `/state/<cell>/ca-bundle.crt`.
  - **Cell mount is read-only.** A compromised cell can't tamper with its
    own trust store (still affects only itself, but limits blast radius).
  - **Cell-set env wins.** Operators / image authors who explicitly set
    `SSL_CERT_FILE` keep their value. Brig only fills in vars the cell
    didn't already set.
  - **Airgapped cells skip the bundle.** `network: none` cells have no
    egress; no CA to validate.
  - **Opt-out via cell yaml.** `trust_warden_ca: false` removes the mount
    and the env vars entirely. Cells with strict pinning or custom trust
    can take control.

| Surface | Location |
|---|---|
| Spec field | `src/brig/cell/spec.py:CellSpec.trust_warden_ca` (default True) |
| Validator | `src/brig/cell/spec.py:_v_trust_warden_ca` |
| Staging | `src/brig/cell/ca_bundle.py:stage_bundle` (extracts + concats + atomic mv) |
| Reconciler | `src/brig/cell/reconciler.py` PODMAN_RUN action invokes stage_bundle; `build_run_command` adds `--volume` and `-e SSL_CERT_FILE=...` when applicable |
| Unit tests | `tests/test_warden_ca_mount.py` (8 cases) |
| CI | Unit |

## State-consistency invariants

### Warden's in-memory state must match on-disk allocator state

| Surface | Location |
|---|---|
| Enforcement | `src/warden/reconcile.py:reconcile_subnet_state` — cross-checks `subnets.json` ↔ `subnet-map.json` ↔ `podman network ls` under `fcntl.flock(LOCK_SH)` |
| Unit test | `tests/test_warden_reconcile.py::TestReconcileSubnetState` — 11 cases |
| CI | Unit |

### Policy load fails closed and reloads serialize

| Surface | Location |
|---|---|
| Enforcement | `src/addons/enforce.py:PolicyEnforcer.load()` calls `_reload_policy(strict=True)` |
| CI | Unit |

## Adversarial tests

| Attack | Test |
|---|---|
| `--env HTTP_PROXY=attacker` to bypass warden | `test_cell_reconciler.py::TestBuildRunCommand::test_all_proxy_env_names_rejected` |
| Symlink in secrets dir escaping | `test_security_secrets.py::TestValidateSecretPath::test_symlink_escaping_rejected` |
| Double-hop symlink in secrets | `test_security_secrets.py::TestValidateSecretPath::test_double_hop_symlink_rejected` |
| Symlink at ingress token read site | `src/brig/cell/lifecycle.py:_register_cell_ingress` calls `validate_secret_path` (covered by the symlink-escape tests above, applied at the read site) |
| Concurrent allocator race — 50 threads | `test_network_subnet.py::TestConcurrentAllocation::test_concurrent_allocate_no_duplicates` |
| Cell def with `network: proxy-external` | `test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| DNS rebinding to host-service tuple | `test_security_audit.py::TestResponseHeadersDnsRebinding::test_does_not_skip_without_metadata` — naked (ip,port) match must not bypass |
| Webhook redirect to internal host | `notifier.py` urllib fallback uses a redirect-disabling opener; urllib3 path uses `assert_hostname` and `cert_reqs=CERT_REQUIRED` |
| Cell with deny-all reaching host service | `test_security_audit.py::TestHandleHostService::test_no_cell_policy_blocked` |
| Ingress route pointing at warden gateway IP | `src/addons/ingress.py` `_reload_routes` rejects host octets `< 2` (audit M4) |

## CI wiring

- `.github/workflows/ci.yml` — all unit tests, every PR, Linux, Python 3.10/3.11/3.12.
- `.github/workflows/e2e.yml` — real Lima VM + podman + gVisor on macos-15. Path-triggered + weekly cron.

## Amendment policy

- **Before landing a PR that touches an invariant**, update this ledger.
- **Before deferring an invariant**, add it to "Known gaps" with a reason.
- **Never** add an invariant to security.md without adding a row here.
