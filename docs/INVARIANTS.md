# Brig Security Invariants — Living Ledger

The invariants from [docs/design/security.md](design/security.md) are the
thing this project exists to uphold (numbered 1–13; #10 is retired). This
document is the single source of
truth for **which tests prove them** and **which CI lane runs those tests**.

If you break a test named here, you're breaking an invariant. If you add a
new invariant, add a row. If you add a test that proves an invariant, add it
to that invariant's row — don't leave the coverage implicit.

## How to read this

- **Unit** — runs on every PR under `.github/workflows/ci.yml` on Ubuntu. No VM.
- **E2E** — the `.github/workflows/e2e.yml` lane (real Lima VM + podman + gVisor
  on macos-15) is **gated on nested virtualization** (`kern.hv_support == 1`),
  which GitHub-hosted runners do NOT provide — so it runs **manually / on
  dispatch / on a self-hosted runner only**, NOT automatically on PRs. Rows
  that list an "E2E test" name the test that exists; "CI" states what actually
  runs in hosted CI.
- **Code location** — where the invariant is enforced in production code.

## Invariant ledger

### 1. No East-West Traffic (per-cell internal networks)

| Surface | Location |
|---|---|
| Enforcement | `src/brig/security/verify.py:verify_network_isolation`; per-cell `--internal` network created in `src/brig/cell/reconciler.py` |
| Cell-def guard | `src/brig/cell/validators.py:_v_network` rejects `network: proxy-external` and non-default/none values |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_list_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifyNetworkIsolation` |
| E2E test | `tests/test_vm_foundation.sh` — east-west ping from cell A to cell B must fail |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 2. Proxy Cannot Be Abused as Gateway

| Surface | Location |
|---|---|
| Enforcement | `src/brig/warden_addons/enforce.py` — port allowlist (80/443), literal-IP block, RFC1918/CGNAT/etc block at request + http_connect + server_connect + responseheaders |
| Blocklist source | `src/brig/warden_addons/_common.py:BLOCKED_NETWORKS` — single source shared by enforce + notifier |
| DNS rebinding (layered) | Request-time checks see the cell-supplied host *name*; the resolved upstream IP is only known at/after connect, so three hooks cover the resolved IP across flow types (below). |
| DNS rebinding · MITM connect | `server_connect` resolves the destination and refuses (`data.server.error`) any flow resolving into `BLOCKED_NETWORKS`, before the request is forwarded. Exempts warden's own routing: host_service rewrite (→ host IP) and ingress reverse-proxy (client on :8443 → cell IP). |
| DNS rebinding · passthrough | `tls_clienthello` resolves the SNI and refuses to flip TLS passthrough into a blocked range — a raw-TCP passthrough tunnel produces no HTTP response, so `responseheaders` never re-checks it. Refusal falls through to MITM, which fails closed. |
| DNS rebinding · MITM response | `responseheaders` re-checks `flow.server_conn.peername`, skip-gated on `flow.metadata["host_service"]` / `["ingress_route"]` — NOT on a `(ip, port)` tuple, which would let a rebinding allowlisted domain reach a host service. |
| DNS rebinding · rejected approach | `server_connected` was tried and abandoned: `data.server.close()` is gone on mitmproxy ≥ 10 and `data.flow` was None there (exemptions couldn't fire). `server_connect` is the workable connect-time hook. |
| Host header smuggling | `_host_header_mismatches` in `request()` and `http_connect()`. Multi-colon strings validated via `ipaddress.ip_address` so non-IPv6 inputs like `example.com:80:extra` don't silently get treated as bare IPv6. |
| Host services | `.host.brig` virtual domains are an intentional, scoped relaxation of this invariant. The cell yaml declares `host_services: [{name, port}]`; that declaration is the sole grant. Warden reads the port from the cell's own per-cell policy file (there is no separate global registry). Cells without `host_services` in yaml have no host-service access. Unknown `.host.brig` domains are blocked. The `untrusted` profile rejects `host_services` at parse time. See `_handle_host_service()` in `src/brig/warden_addons/enforce.py`. |
| Ingress | Warden ingress (port 8443) routes declared inbound traffic to cells. Per-route auth is operator policy: `auth: token` (default — brig is the Bearer-token gate) or `auth: none` (transparent pass-through; the cell's app is the gate). A route missing `auth` is treated as `token` (fail-secure); `auth: none` is rejected on the `untrusted` profile and audited at run time (`ingress_unauthenticated` lifecycle event + operator NOTE). enforce.py blocks unhandled ingress requests (fail closed). CONNECT is blocked entirely on the ingress port. See `src/brig/warden_addons/ingress.py`. |
| Unit test | `tests/test_addons_ops.py` — token bucket rate limiting |
| Unit test | `tests/test_ingress.py` — ingress routing, token auth, rate limiting. Cell-IP validation: `TestIngressAddonCellIpValidation::test_in_range_reserved_host_octets_rejected` feeds in-subnet `10.60.x.0/.1/.255` so the reserved-host-octet gate (`host_octet < 2`, `.255`) is actually exercised, plus `test_invalid_cell_ip_rejected` for out-of-range IPs |
| Unit test | `tests/test_addon_common.py::TestBlockedNetworks` — every `BLOCKED_NETWORKS` class has a representative blocked address (RFC1918, CGNAT, link-local, IPv4-mapped, IPv6 NAT64/6to4/discard, IPv4 6to4-relay/NAT64-WKA, alternate IPv4 encodings) so a deleted/mistyped CIDR fails CI |
| Unit test | `tests/test_security_audit.py::TestResponseHeadersDnsRebinding` — RFC1918, localhost, link-local, IPv4-mapped-IPv6, IPv6 link-local; flow-metadata-gated host-service / ingress-route skip; a naked tuple match must NOT bypass |
| Unit test | `tests/test_security_audit.py::TestConnectMethodEnforcement` — CONNECT to disallowed port / internal IP / literal IP / disallowed domain / ingress port |
| Unit test | `tests/test_security_audit.py::TestNormalizeHostspecRobustness` — bracketed IPv6, multi-colon non-IPv6 strings |
| Unit test | `tests/test_security_audit.py::TestHandleHostService` — per-cell ACL: cell with no per-cell policy is blocked; cell whose policy doesn't list the service is blocked |
| Unit test | `tests/test_addon_common.py::TestBlockedNetworks` — covers every entry in the SSRF blocklist |
| E2E test | `tests/test_proxy_policy.sh` tests 7-11 — asserted via JSONL log entries |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

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
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 5. gVisor Must Be Active (no silent downgrade)

| Surface | Location |
|---|---|
| Enforcement | `src/brig/cell/reconciler.py:build_run_command` hardcodes `--runtime runsc` |
| Verify check | `src/brig/security/verify.py:verify_gvisor_runtime` — reads the top-level `OCIRuntime` (named runtime, `runsc`/`crun`), NOT `HostConfig.Runtime` (the OCI category, always `"oci"`, which cannot tell runsc from a crun downgrade) |
| Unit test | `tests/test_cell_reconciler.py::TestBuildRunCommand::test_runtime_always_runsc` |
| Unit test | `tests/test_security_verify.py::TestVerifyGvisorRuntime::test_runtime_downgrade` |
| Unit test | `tests/test_security_verify.py::TestVerifyGvisorRuntime::test_real_podman_inspect_shape` — drives the check with a real `podman inspect` fixture so the field name can't silently regress |
| E2E test | `tests/test_cell_lifecycle.sh` — dmesg grep for "Starting gVisor" |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 6. Only Infrastructure Containers May Attach to proxy-external

| Surface | Location |
|---|---|
| Allowlist | `src/brig/config.py:INFRA_CONTAINER_NAMES` — the enforced set: warden + the OTel collector `brig-otel` (both brig-managed infra; no cell can reach proxy-external) |
| Cell-def guard | `src/brig/cell/validators.py:_v_network` rejects `network: proxy-external` |
| Verify check | `src/brig/security/verify.py:verify_proxy_network` (membership ⊆ `INFRA_CONTAINER_NAMES`) |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_arbitrary_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifyProxyNetwork` |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 7. No Privileged Services on Cell Networks

| Surface | Location |
|---|---|
| Verify check | `src/brig/security/verify.py:verify_cell_network_members` — flags any member of a `brig-<cell>` network that isn't warden or the cell itself |
| Unit test | `tests/test_security_verify.py::TestVerifyCellNetworkMembers::test_foreign_container` |
| Unit test | `tests/test_security_verify.py::TestVerifyCellNetworkMembers::test_only_warden_and_cell` |
| E2E test | `tests/test_invariants_7_8.sh` — attaches a foreign container to a cell's network and asserts `brig system verify` detects it |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 8. Cells Must Be Single-Homed

| Surface | Location |
|---|---|
| Cell-def guard | `src/brig/cell/validators.py:_v_network` rejects list network values |
| Verify check | `src/brig/security/verify.py:verify_single_homed` |
| Unit test | `tests/test_cell_spec.py::TestValidateCellDefinition::test_network_list_rejected` |
| Unit test | `tests/test_security_verify.py::TestVerifySingleHomed::test_multi_homed` |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 9. Proxy Must Be Running Before Cells Start

| Surface | Location |
|---|---|
| Enforcement | `src/brig/cell/lifecycle.py:run_cell` checks `proxy_running()` early |
| Unit test | `tests/test_cell_lifecycle.py::TestRunCell::test_invariant_9_proxy_must_be_running` |
| E2E test | `tests/test_cell_lifecycle.sh` |
| CI | Unit (the E2E `.sh` lane is gated on nested-virt and does NOT run on GitHub-hosted CI — manual/dispatch only) |

### 10. (retired) host_sockets

The unix `host_sockets` feature — a launchd bridge that mounted a macOS host
service's unix socket into a cell — was **removed** (see CHANGELOG). It never
worked under brig's mandatory gVisor runtime (a cell could not `connect()` to a
bind-mounted host unix socket), no consumer used it, and it deliberately
bypassed Warden. Cell→host access goes through **TCP/HTTP `host_services`**
(Warden stays in the path) or scoped **`mounts`** (invariant 13).

This number is retired rather than reused so invariants 11–13 keep stable
references. See removed-feature design notes in GitHub issue #21.

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
  - **Passthrough connections are audited at the TLS handshake.** Warden
    logs `PASSTHROUGH: cell=<cell> sni=<host>` in `tls_clienthello` when it
    engages passthrough, so the cell + destination of every uninspected flow
    is recorded. Per-URL/body/byte detail is absent **by construction** —
    Warden never decrypts, and a true (ignore_connection) passthrough tunnel
    produces no mitmproxy flow, so the tcp_*/byte hooks don't fire.
  - **Untrusted profile cannot declare passthrough** (Phase 1 follow-up).
    The trade-off requires informed operator consent; untrusted profiles
    don't get to make that choice.

| Surface | Location |
|---|---|
| Cell-def guard | `src/brig/cell/validators.py:_v_policy` — cross-field check that every `tls_passthrough` host appears in `allow`; rejects passthrough under the untrusted profile |
| Spec field | `src/brig/cell/spec.py:CellSpec.policy_passthrough_tls` |
| YAML flattening | `src/brig/commands/lifecycle_run.py` (`policy.tls_passthrough` → `policy_passthrough_tls`) |
| Profile propagation | `src/brig/cell/profiles.py` (profile-level `policy.tls_passthrough` prepends to cell's list) |
| Per-cell policy write | `src/brig/commands/lifecycle_run.py:_sync_cell_policy` writes `tls_passthrough` to `<cell>.json` |
| Policy class | `src/brig/warden_addons/_policy.py:Policy.is_passthrough` — defense-in-depth: a host must match BOTH passthrough rules AND allow rules (a tampered policy file can't opt a host out of MITM without allow coverage) |
| Addon hook | `src/brig/warden_addons/enforce.py:tls_clienthello` — reads SNI, sets `data.ignore_connection = True` (the passthrough switch mitmproxy's TLS layer reads) when the SNI matches BOTH allow and passthrough, blocks SNI/CONNECT mismatches, and refuses passthrough whose SNI resolves into a blocked IP range |
| Passthrough audit | The connection-level `PASSTHROUGH: cell=… sni=…` log line in `tls_clienthello`. NOTE: a true (ignore_connection) passthrough tunnel produces no TCPFlow, so `otel_export.tcp_start/message/end` do NOT fire — the `warden_passthrough_*` counters are not emitted today. Byte/duration metering would require a flow-bearing relay (e.g. a `next_layer`-installed TCPLayer); tracked separately. |
| Log shape | `src/brig/warden_addons/otel_export.py` tags MITM records with `tls_mode=mitm`. (Passthrough flows don't reach the otel hooks — see Passthrough audit above.) |
| CLI rendering | `src/brig/commands/network_cmd.py:_print_network_line` renders passthrough lines as `PASSTHROUGH: <host>` — visually distinct from `OUT:` and `INGRESS:` |
| Unit tests | `tests/test_cell_spec.py::TestValidateCellDefinition::test_policy_tls_passthrough_*` (4 cases) |
| Unit tests | `tests/test_passthrough_tls.py` — `is_passthrough` defense-in-depth, wildcard semantics, untrusted-profile rejection, per-cell-policy persistence, CLI render, and `tls_clienthello` engaging passthrough via `ignore_connection` (asserts the real switch, not a no-op attr) incl. SNI/CONNECT-mismatch and blocked-IP-resolution refusal |
| Unit tests | `tests/test_cell_profiles.py::test_policy_tls_passthrough_propagates_from_profile` |
| CI | Unit |

**Verified e2e** (manual, against the pinned warden image, mitmproxy 10.1.1):

  - A cell with `example.com` in `allow` + `tls_passthrough` receives
    example.com's **real upstream certificate** (Cloudflare) — warden tunnels
    the TLS raw, no decryption. A cell with `example.com` in `allow` only
    receives **warden's MITM cert** (`mitmproxy`). This confirms
    `data.ignore_connection` engages passthrough exactly for opted-in hosts.
    Cert issuer is the reliable signal; warden stdout is buffered and a busybox
    `wget` (alpine) can't complete the handshake — use a real TLS client.

**Not yet landed** (tracked separately):

  - Automated E2E (`tests/test_passthrough_tls.sh`) using a real TLS client
    (python `ssl`, not busybox `wget`) that inspects the peer cert issuer to
    assert passthrough-vs-MITM, plus the SNI/CONNECT-mismatch rejection.

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
    that race a fresh `brig system up` can no longer get an empty / missing
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
| Validator | `src/brig/cell/validators.py:_v_trust_warden_ca` |
| Staging | `src/brig/cell/ca_bundle.py:stage_bundle` (extracts + concats + atomic mv) |
| Reconciler | `src/brig/cell/reconciler.py` PODMAN_RUN action invokes stage_bundle; `build_run_command` adds `--volume` and `-e SSL_CERT_FILE=...` when applicable |
| Unit tests | `tests/test_warden_ca_mount.py` (9 cases) |
| CI | Unit |

### 13. Scoped Host Mounts Are Opt-In, Bounded, and Bypass Warden by Design

A `supervised`/`dev` cell may bind-mount an operator-chosen host directory into
itself via `mounts:` (ro default / rw opt-in), bounded by the VM-level
`mount_roots` allowlist. The bytes flow between the cell and the host files
directly — Warden does not mediate them (an explicit Warden-bypass trade-off).

The invariants we DO uphold:

  - Opt-in per cell yaml (no default access); the `untrusted` profile rejects
    `mounts:` at parse time.
  - `host_path` realpath must resolve under a declared `mount_roots` entry — a
    cell cannot reach host trees the operator did not allowlist, and the VM's
    host exposure is bounded to those roots.
  - A cell-created symlink inside the mount cannot escape the subtree to a VM
    path: container mount-namespace isolation makes it dangle (verified under
    runsc AND crun — runtime-independent, not reliant on gVisor; see
    docs/design/mount-symlink-hardening.md).
  - `mount_point` cannot shadow a system path or the cell's `/work` (parse-time).
  - Every attach is audited (`log_lifecycle("mount_attach", ...)`) and the cell
    banner states Warden does not see these bytes.
  - Residual risk is HOST-SIDE: a cell can plant a symlink pointing out of the
    shared folder that a host consumer might follow. `brig cell mount-scan`
    reports/quarantines such symlinks; the consumer must treat cell-written
    files as untrusted. brig sandboxes the cell's execution, not the fate of
    files it may write (confused-deputy boundary).

| Surface | Location |
|---|---|
| Parse-time guards | `src/brig/cell/validators.py:_v_mount_entry`, `_v_mounts` |
| Root allowlist | `src/brig/config.py:mount_roots()`, `validate_mount_roots()`, `src/brig/vm/lima_mounts.py` (lima.yaml managed block) |
| Runtime translation + containment recheck | `src/brig/cell/reconciler.py:_attach_mounts`, `_mount_bind_arg` |
| Profile gate | `_v_mounts` rejects on `untrusted` (via `_profile_is_untrusted`) |
| Audit + banner | `src/brig/cell/lifecycle.py:run_cell` emits `mount_attach` |
| Host-side symlink guard | `src/brig/workspace/workspace.py:find_escaping_symlinks`; `brig cell mount-scan` |
| Unit tests | `tests/test_mounts_spec.py` (22), `tests/test_reconciler_mounts.py` (8), `tests/test_lima_mounts.py` (13), `tests/test_mount_scan.py` (7), `tests/test_mount_roots_validation.py` (17) |
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
| Enforcement | `src/brig/warden_addons/enforce.py:PolicyEnforcer.load()` calls `_reload_policy(strict=True)` |
| Unit test | `tests/test_security_audit.py::TestStrictPolicyLoadFailsClosed` — strict load raises on missing/malformed `/policy.json`; non-strict reload swallows a bad edit and keeps last-good |
| CI | Unit |

## Adversarial tests

| Attack | Test |
|---|---|
| `--env HTTP_PROXY=attacker` to bypass warden | `test_cell_reconciler.py::TestBuildRunCommand::test_all_proxy_env_names_rejected` |
| Symlink in secrets dir escaping | `test_security_secrets.py::TestValidateSecretPath::test_symlink_escaping_rejected` |
| Double-hop symlink in secrets | `test_security_secrets.py::TestValidateSecretPath::test_double_hop_symlink_rejected` |
| Symlink at ingress token read site | `src/brig/cell/lifecycle.py:register_ingress_for` calls `validate_secret_path` (covered by the symlink-escape tests above, applied at the read site) |
| Concurrent allocator race — 50 threads | `test_network_subnet.py::TestConcurrentAllocation::test_concurrent_allocate_no_duplicates` |
| Cell def with `network: proxy-external` | `test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |
| DNS rebinding to host-service tuple | `test_security_audit.py::TestResponseHeadersDnsRebinding::test_does_not_skip_without_metadata` — naked (ip,port) match must not bypass |
| Webhook redirect to internal host | `notifier.py` urllib fallback uses a redirect-disabling opener; urllib3 path uses `assert_hostname` and `cert_reqs=CERT_REQUIRED` |
| Cell with deny-all reaching host service | `test_security_audit.py::TestHandleHostService::test_no_cell_policy_blocked` |
| Ingress route pointing at warden gateway IP | `src/brig/warden_addons/ingress.py` `_reload_routes` rejects host octets `< 2` |

## CI wiring

- `.github/workflows/ci.yml` — all unit tests, every PR, Linux, Python 3.10/3.11/3.12.
- `.github/workflows/e2e.yml` — real Lima VM + podman + gVisor on macos-15. Path-triggered + weekly cron.

## Amendment policy

- **Before landing a PR that touches an invariant**, update this ledger.
- **Before deferring an invariant**, add it to "Known gaps" with a reason.
- **Never** add an invariant to security.md without adding a row here.
