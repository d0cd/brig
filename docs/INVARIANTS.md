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
| Enforcement | `src/addons/enforce.py` — port allowlist (80/443), literal-IP block, RFC1918/CGNAT/etc block at request + http_connect + server_connected |
| DNS rebinding defense | `server_connected` re-checks resolved IP against `BLOCKED_NETWORKS` |
| Host header smuggling | `_host_header_mismatches` in `request()` and `http_connect()` |
| Host services | `.host.brig` virtual domains are an **intentional, scoped relaxation** of this invariant. Only explicitly declared name:port pairs are reachable on the host. Unknown `.host.brig` domains are blocked. `server_connected`/`responseheaders` skip the blocked-IP check only for registered host service targets. See `_handle_host_service()` in enforce.py. |
| Ingress | Warden ingress (port 8443) allows authenticated inbound traffic to cells. enforce.py blocks unhandled ingress requests (fail closed). CONNECT is blocked entirely on the ingress port. See `src/addons/ingress.py`. |
| Unit test | `tests/test_addons_ops.py` — token bucket rate limiting |
| Unit test | `tests/test_ingress.py` — ingress routing, token auth, cell IP validation, rate limiting |
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
| Concurrent allocator race — 50 threads | `test_network_subnet.py::TestConcurrentAllocation::test_concurrent_allocate_no_duplicates` |
| Cell def with `network: proxy-external` | `test_cell_spec.py::TestValidateCellDefinition::test_network_proxy_external_rejected` |

## CI wiring

- `.github/workflows/ci.yml` — all unit tests, every PR, Linux, Python 3.10/3.11/3.12.
- `.github/workflows/e2e.yml` — real Lima VM + podman + gVisor on macos-15. Path-triggered + weekly cron.

## Amendment policy

- **Before landing a PR that touches an invariant**, update this ledger.
- **Before deferring an invariant**, add it to "Known gaps" with a reason.
- **Never** add an invariant to security.md without adding a row here.
