# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`brig system verify` can again detect non-warden/non-cell containers on cell and proxy-external networks (invariants 6 & 7).** The member checks enumerated containers from `podman network inspect`'s `.containers` field, which is **unpopulated under netavark** (the field is absent), so both checks read an empty member set and *always passed* — a foreign container planted on a cell network (inv 7) or a rogue container on `proxy-external` (inv 6) went undetected. Membership is now read from `podman ps --filter network=<net>` (the authoritative source, `--all` so a stopped-but-attached container can't hide), and fails closed if the query errors. Surfaced by `tests/test_invariants_7_8.sh` once it was migrated to run against real podman state.

- **Cell network is verified `--internal` before reuse.** `observe()` recorded only whether a `brig-<cell>` network existed, and `plan_run` skipped `CREATE_NETWORK` (the sole `--internal` site) on the reuse path — so a leftover/tampered/operator-made non-internal network of the same name was silently adopted, giving the cell off-segment routes (invariant 1) and a path around Warden. The state dir / VM network set is untrusted (invariant 4), so the reconciler now inspects the network and **fails closed** if it isn't internal.
- **Blocked-request paths are redacted in the `ctx.log` sink too.** The `BLOCKED:` (enforce) and `INGRESS MISS:` (ingress) log lines went to warden's container stdout with only control-character stripping, so a secret in the path/query (`?api_key=…`) on a *blocked* request landed verbatim in `podman logs warden`. Both now run the path through the shared `redact_path` redactor, closing the one sink the redaction pipeline missed.
- Query-value redaction broadened: the sensitive-param allowlist gains `session`/`sig`/`signature`/`code`/`refresh_token`/`id_token`/`sas`, and **any** query value that classifies as a secret segment (token-shaped / high-entropy) is now masked regardless of its parameter name.
- `server_connect` re-checks the upstream port against the egress allowlist (80/443) as defense-in-depth, so the connect-time guard is self-sufficient even if a future flow type reaches it without the request-time port check (legitimate non-80/443 destinations — host_service rewrites, ingress, declared TCP host_services — stay exempt).
- The proxy-env override guard now strips/normalizes the env key before comparison, and `_v_env` rejects keys that aren't valid POSIX environment names — so a whitespace-padded ` http_proxy` can't slip past the guard protecting the Warden choke point.
- `mount_root_slug` is derived from the realpath everywhere (validation, lima.yaml render, reconciler bind), so two symlinked `mount_roots` can't collide at one `/mnt/host/<slug>` with no validation error (which would shadow one host tree with another).
- `_v_workdir` rejects `..`/`.` segments and doubled slashes, matching the other in-cell path validators.
- Path filters (`policy.allow` with `paths:`) match on the path **without** its query string, so an intended endpoint scope isn't affected by query content; the glob-over-path semantics are now documented.
- `brig system down` self-heals orphaned subnet allocations (frees `/24`s whose podman network is gone, then sweeps their ingress routes) instead of leaking them until a manual `prune`; fails safe if the network list can't be read.
- Connect-time destination-IP validation closes the SSRF / DNS-rebinding gap on the egress paths the response-only check missed. `enforce.server_connect` resolves the destination and refuses (`data.server.error`) any MITM flow that resolves into a blocked range *before* the request is forwarded; `enforce.tls_clienthello` resolves the SNI and refuses to flip TLS passthrough into a blocked range (a raw-TCP passthrough tunnel produces no HTTP response, so the old `responseheaders` re-check never covered it). Warden's own routing — host_service rewrites (→ host IP) and ingress reverse-proxy (→ cell IP) — is exempt.
- `brig run --profile untrusted` now enforces the untrusted-profile guards on the CLI path. The profile name was not recorded where validation could see it, so a cell launched with `--profile untrusted -f cell.yaml` could declare `tls_passthrough` or `host_services` unchecked. (The SDK path was already correct.)
- Image references beginning with `-` are rejected on the cell-yaml `image:` and SDK `image=` paths, and `podman run` now gets a `--` end-of-options marker before the image. An `image:` value like `--runtime=runc` (silent gVisor downgrade), `--privileged`, or `-v /:/host` can no longer be parsed by podman as a flag.
- `verify_gvisor_runtime` reads the named runtime (top-level `OCIRuntime`) instead of `HostConfig.Runtime` (the OCI category, always `"oci"`). `brig system verify` can now actually distinguish a `runsc` cell from a `crun` downgrade (invariant 5) instead of false-failing every cell.
- `workspace_mount` rejects non-normalized paths (doubled/leading/trailing slashes, `.` segments). A value like `/run//host` previously slipped past the lexical forbidden-prefix check while the kernel collapsed it back onto a brig-internal mount root.
- `BLOCKED_NETWORKS` adds the IPv4 6to4-relay anycast (`192.88.99.0/24`) and IETF protocol-assignment / NAT64 well-known (`192.0.0.0/24`) ranges, for parity with the existing IPv6 tunnel prefixes.
- Per-cell policy read-modify-write is serialized under one exclusive lock (`mutate_cell_policy`), so a concurrent `brig policy set` racing `brig run`'s policy re-sync can no longer silently drop an update.
- `image_digest` is matched at the exact per-algorithm hex length (sha256/384/512); cell-name / secret-name / domain / memory validators anchor with `\Z` so a trailing newline is rejected.

### Changed

- **Unknown cell-yaml keys now warn instead of silently no-op-ing.** brig builds the spec by filtering to known `CellSpec` fields, so a typo'd or stale key (e.g. a leftover `host_sockets:`) was dropped without a word. `brig run --file` and `brig cell preflight` now print a warning naming the unrecognized key(s); the cell still runs (warn, not reject). The known set is derived from `CellSpec` fields (+ the nested `policy:` alias) so it can't drift.
- Version bumped to **0.4.0** (new invariants 11–13 + removed `brig cell trace`); `pyproject.toml` and `brig.config.VERSION` are now guarded against drift by a test.
- The pinned mitmproxy base image has a single source of truth (`warden.proxy.BASE_IMAGE`), imported by `brig image warmup`; a test keeps the warden Dockerfile `FROM`/`LABEL` in lockstep, matching the gVisor/collector pin discipline.
- Invariant 6 docs realigned with the code: `proxy-external` admits brig infrastructure (warden **and** the OTel collector `brig-otel`, per `INFRA_CONTAINER_NAMES`); no cell can reach that network.
- **Fail-closed behavior changes** (operators take note): `brig cell start` now refuses to start a digest-pinned cell whose container reports an empty image digest (was: started unverified); a cell that declares `ingress` now fails and rolls back if its container can't be inspected or has no IP at start (was: started with the route silently unregistered); TLS passthrough is refused (falls through to MITM) when the host resolves into a blocked range.
- `brig system verify` no longer reports airgapped (`--network none`) cells as single-homing violations, and now flags network members that lack a name instead of silently skipping them.
- The warden addons moved from the loose top-level `src/addons/` into the brig package as shipped data (`src/brig/warden_addons/`). They now ship in the wheel (declared as `brig` package-data) and `brig.ops.addon_deploy` resolves them via `importlib.resources`, so the deployed data plane is resolvable in any install layout, not just an editable checkout. The addons stay flat-loaded by mitmproxy (no `__init__.py`); the deploy target (`~/.brig/cells/addons` → `/addons`) is unchanged.

### Removed

- **Unix `host_sockets`** (the launchd bridge that mounted a macOS host service's unix socket into a cell). It never worked under brig's mandatory gVisor runtime — a cell cannot `connect()` to a bind-mounted host unix socket (`Not supported`), and the socket file couldn't even be bind-mounted off the virtiofs `/state` share (`statfs ... operation not supported`). No consumer ever used it (verified across all projects — they use TCP/HTTP `host_services` + `mounts`), and it deliberately bypassed Warden. Removed the `host_sockets` cell-yaml field + SDK param, `cell/host_sockets_bridge.py`, the validators/reconciler/metadata/doctor/down plumbing, the per-cell launchd-bridge management, and the `HOST_SOCKET_*` config. Cell→host access is served by `host_services` (HTTP, or `protocol: tcp` — both keep Warden in the path) and scoped `mounts:`. **Invariant 10 is retired** (its number is not reused, so invariants 11–13 keep stable references). Design notes: GitHub issue #21.
- `brig cell trace` and the OTel **traces** pipeline. No addon ever emitted a span (the tracer/exporter were initialized but unused), so the collector's traces lane and `traces.jsonl` were always empty and the command always returned no data. Removed the command, the unused `TracerProvider`/`OTLPSpanExporter` setup in `otel_export.py`, the `traces` pipeline + `file/traces` exporter in the collector config, `brig/observability/traces.py`, and the stale docs claim that spans are attached per request. Metrics and logs (the signals that actually flow) are unaffected.

### Fixed

- **`warden reload` works against the pinned mitmproxy image.** It ran `podman exec warden kill -HUP 1`, but the mitmproxy image has no standalone `kill` binary (only the shell builtin), so the exec failed with 127 and the policy/addon hot-reload never fired. It now signals via `podman kill --signal HUP warden`, which delivers SIGHUP to PID 1 directly (mitmproxy reloads in place; the container stays up). Surfaced by the migrated `tests/test_warden_features.sh`.
- **s6-overlay (and other init-system) images now run under the hardened rootfs.** The read-only-rootfs `/run` tmpfs was mounted `noexec`, so s6-overlay — PID 1 for linuxserver.io and most modern images — died at stage0 (`exec: /run/s6/basedir/bin/init: Permission denied`) and brig rolled the cell back ("cell IP could not be determined"). `/run` is now exec-capable; `nosuid,nodev` are kept and `/tmp` stays `noexec`. The flag protected nothing `/work` (always exec-capable) doesn't already expose, is bypassable (`memfd_create`+`execveat`), and was never a brig boundary — containment is the VM/gVisor/Warden choke point plus cap-drop ALL + read-only rootfs + `nosuid`/`no-new-privileges`. (Reported by hermes.)
- **Cells no longer lose egress when warden's IP changes.** The per-cell `HTTP(S)_PROXY` env was baked to warden's *literal* per-cell-network IP at cell creation. That IP isn't stable across warden restarts (VM reboot, resume, addon reload, `system down/up`), so a running cell would keep the dead IP and silently lose all egress (`HTTP 000`, no error) until recreated. Cells are now pointed at warden by its DNS **name** (`http_proxy=http://warden:8080`), re-resolved per connection via the cell network's DNS, so egress survives every warden restart with no cell recreate. The connectivity precondition (refuse to start a non-airgapped cell whose warden isn't connected) is preserved. (Reported by hermes.)
- **Documentation accuracy (quality audit).** `docs/learning/concepts.md` claimed the `dev` profile disables gVisor (it can't — gVisor is mandatory, invariant 5) and documented a `--sanitize` / `--allow-scripts` / `--allow-office` flag family and blocklist that don't exist (export sanitization is unconditional; the real blocklist is `UNSAFE_EXTENSIONS`). Also corrected: `security.md` "proxy listens ONLY on 8080" (ingress adds 8443, TCP host_services add their ports) and the `tls_mode=mitm` scope (OTel records, not the JSONL flow log); `INVARIANTS.md` symbol `_register_cell_ingress` → `register_ingress_for`; `warden reload` addon credit; `secrets add --force` flag; `sdk.py` `list_sync` docstring.
- More actionable errors: "Invalid cell name" now states the allowed format; `Could not parse …` raises suggest `brig system doctor`; the TCP-restart prompt fails fast with a `--yes` hint on non-interactive callers instead of an EOF-driven abort.
- **TLS passthrough (invariant 11) now actually engages.** `tls_clienthello` set `client_conn.tls_passthrough = True`, an attribute the warden image's mitmproxy (10.1.1) does not read — so passthrough was a silent no-op: every host was MITM'd, and a host that refuses mitmproxy's relayed handshake simply failed. Warden now sets `data.ignore_connection = True`, the switch the TLS layer actually reads. Verified e2e (manual, against the pinned image): a host in `tls_passthrough` receives its real upstream certificate (warden tunnels raw, no decryption), while an allowlisted-but-not-passthrough host still receives warden's MITM cert. The gating is preserved (allow-coverage, SNI/CONNECT match, resolved-IP guard). NOTE: a true passthrough tunnel produces no mitmproxy flow, so the `warden_passthrough_*` otel counters and the `tcp_*` hooks do NOT fire for it — the only passthrough audit is the connection-level `PASSTHROUGH: cell=… sni=…` log line. See `docs/INVARIANTS.md` invariant 11.
- `scripts/local-smoke-test.sh` updated to the 0.3.0 noun-verb CLI (`brig system up/verify`, `brig cell list/inspect/exec/stop/rm`); it had broken against the restructured surface.
- Atomic file writes `fsync` the parent directory after rename, so a crash immediately after the rename can't lose the directory entry.

## [0.3.1] - 2026-05-26

### Fixed

- `brig cell start` now replays ingress registration with a freshly-inspected cell IP. Without this, a `brig system down` / `brig system up` cycle left the cell running but external requests through warden's `:8443` reverse proxy returned 502 indefinitely because the routes file still held the pre-restart cell IP. Ingress entries are now stored in `cell-metadata.json` (no secrets — the bearer token still lives in the secrets directory) so the start path can replay registration without the original yaml.

### Added

- TCP `host_services` — declare `protocol: tcp` on a host_service entry to forward L4 traffic from the cell to a host port through warden's TCP listener. HTTP entries still go through mitmproxy at L7. Warden auto-restarts when a cell adds a new TCP host_service port that needs a listener bound.
- TLS passthrough (invariant 11): `policy.tls_passthrough` opts a cell out of MITM for specific hosts that refuse mitmproxy's relayed handshake. Each entry must also appear in `policy.allow`; the untrusted profile cannot declare passthrough.
- Auto-mount Warden CA bundle (invariant 12): cells get `/run/brig/ca-bundle.crt` (system roots + Warden CA) plus `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` pointed at it, unless the cell sets those env vars itself or opts out via `trust_warden_ca: false`.
- OpenTelemetry collector subsystem (phases 1-3): sidecar collector container (pinned image digest), warden SDK instrumentation, `brig system stats` (per-cell summary scraped from the collector), `brig cell trace <trace_id>` (request trace by id), `brig cell network --otel` (read warden flows from the collector instead of per-cell JSONL), benchmark forwarding.
- `brig image build <dir>` — wrap `podman build` inside the VM. `--use-warden` injects HTTPS_PROXY / HTTP_PROXY / NO_PROXY and mounts the Warden CA so the build's HTTP traffic flows through the same policy as runtime.
- `brig cell trace <trace_id>` — render a request trace from the collector.
- `brig system stats` — per-cell summary (requests, bytes, blocks) from the collector.
- `brig system prune` detects orphan workspace directories under `~/.brig/state/` whose cell no longer exists.

### Security

- `image_digest` is now enforced at runtime, not just at parse time. The reconciler rewrites `image` to `image@digest` form before `podman run`, so podman refuses any mismatch at pull time.
- Secret-name validator rejects empty strings, null bytes, and leading dashes (in addition to traversal). An empty name would previously collapse `Path("/secrets") / ""` and bind-mount the whole secrets directory into the cell.
- Reconciler calls `validate_secret_path` before bind-mounting each secret into a cell. Defends against a symlink under `~/.brig/secrets/` escaping the directory at run time.
- `O_NOFOLLOW` when writing secrets via `brig secrets add` so a pre-planted symlink at the target name can't redirect the write.
- `host_socket` bridge plist freezes the connect target via `realpath` before launchd sees it; a swap of the host path after the plist is written can no longer redirect the bridge.
- `save_cell_policy` writes are serialized under `fcntl` so concurrent `brig policy set` invocations don't interleave.
- Ops addon's health endpoint binds to loopback inside the warden container so it isn't reachable from cells.
- `ca_bundle` staging shell-quotes interpolated paths.
- `BLOCKED_NETWORKS` now includes `64:ff9b::/96` (NAT64), `100::/64` (discard), and `2002::/16` (6to4) — covers IPv6 SSRF vectors the original list missed.
- `/run/host` and `/run/brig` added to `workspace_mount` forbidden_prefixes. Shadowing either silently breaks host_sockets or the downward-API metadata.
- Policy reload uses nanosecond mtime comparison so a sub-second rewrite triggers a reload.
- Operations-log error redactor tightened so paths and secret values don't leak through error messages.
- Host-side `domain_matches_rule` matches the addon's IDN encoding so YAML wildcard rules and runtime evaluation agree on punycode hosts.
- Webhook notifier resolves the configured URL's host at config load and refuses connections that resolve to a different IP later (pins DNS).

## [0.3.0] - 2026-05-18

### Added

- `brig prune [--cells|--logs|--subnets] [--dry-run] [--log-days N]` — cleans up stopped cells, rotated log files older than N days, and orphan subnet allocations (cells whose podman network is gone).
- `brig.ops.logging.error()` — companion to `info`/`warn`/`debug`. All CLI error output now flows through this so `--quiet` and `--no-color` are honored uniformly.
- `make pin-gvisor` + `scripts/pin-gvisor.sh` — fetches the current gVisor release's sha512s from the official storage bucket and rewrites `GVISOR_SHA512_BY_ARCH` in `provision-vm.sh`. Run once per gVisor version bump.
- `make _copy-addons` now also copies `src/seccomp/*.json` to `~/.brig/cells/seccomp/`. Fixes `--seccomp-profile <name>` looking up a non-existent path inside the warden container.
- Cross-module constant-mirror tests (`tests/test_addon_brig_constant_mirror.py`) — fails loudly if `INGRESS_PORT`, `HOST_SERVICE_SUFFIX`, or `BLOCKED_NETWORKS` drift between `brig.config` and the addons.
- 41 new tests covering `workspace.py` sanitize/quarantine, `_log_writer.py` directly, `brig prune` parser, `brig --version`, and the new constant mirrors.

### Changed

- **B1**: `brig.ops.history._maybe_rotate` now runs under a sidecar `.lock` file. Two concurrent brig invocations can no longer race on the JSONL rotation rename.
- **B2**: `tests/benchmarks/test_bench_proxy.py` updated to call `enforcer.subnets.get_cell_name` after the SubnetResolver extraction (the old `_build_subnet_index` reference broke `benchmarks.yml`).
- **B3**: `--filter name=` callers now use the regex-anchored form `--filter name=^brig-`. A user-created container named `my-brig-foo` no longer pollutes `brig list`.
- **B4**: `Cell.wait_sync` returns `-1` whenever the wait itself fails (subprocess error, non-zero `podman wait` returncode, or unparseable status output), so the caller can distinguish "cell exited 1" from "we couldn't wait on it".
- **R3**: `notifier.Notifier.last_notification` (OrderedDict) is now read+written under a `threading.Lock`, defending against the LRU `popitem`/`move_to_end` invariant violation if more than one worker is ever introduced.
- **O4**: Ingress body-size limit now comments that the check is post-buffer (mitmproxy already buffered the body before we see it); kept the cap as it still gates the *cell-side* memory.
- **O5**: `DEFAULT_MAX_ROTATED_FILES` raised from 1 → 4. At the default 100MB/file, a 100 req/s cell now retains ~85 minutes of history before the oldest rotation drops, vs. ~17 minutes previously.
- **C1**: `brig.__init__` no longer eagerly imports the SDK. `python -c "import brig"` and CLI startup no longer pay the cost of `brig.sdk` (which transitively imports subprocess, json, etc.). SDK attributes are still importable via `from brig import Brig`; resolved lazily via `__getattr__`.
- **C2**: `Notifier._stop_worker` now joins its worker thread with a 1.0s timeout, matching `AsyncLogWriter.stop()`. Shutdown is now consistently bounded across both worker-thread addons.
- **D1**: `pyproject.toml` and `brig.config.VERSION` bumped to `0.3.0`.
- **D2**: SDK docstring example in `src/brig/__init__.py` rewritten to `print(result.stdout, end="")` so users copying it don't get the literal `\n` doubled.
- **CI3**: Added `pre-commit` job to `ci.yml` (`SKIP=no-commit-to-branch pre-commit run --all-files`). Catches drift between `.pre-commit-config.yaml` and CI-side mypy/ruff/etc.
- Coverage floor raised from 60% to 65% (current actual: 66%). 0.4 target: convenience_cmd / watchdog_cmd / sdk async paths → restore 70%.

### Security

- Host services: cells reach declared host:port pairs via `<name>.host.brig` virtual domains, rewritten by Warden to the macOS host. Per-cell ACL: cells may only reach host services explicitly listed under `host_services` in their per-cell policy. (Audit fix H1.)
### Added (pre-0.3.0 audit-pass, included in this release)

- Authenticated ingress reverse proxy through Warden: external requests to `https://warden:8443/{cell}/{prefix}/...` route to a cell-internal port after Bearer-token auth. Salted SHA-256 token hashing, constant-time comparison, per-IP auth-failure rate limiting.
- WebSocket passthrough through Warden (logged but not re-policy-checked once the upgrade has been allowed).
- `brig doctor` — deep environment check (PATH, Lima VM state, addon presence, directory permissions, port collisions). Complements the lighter `--quick` check.
- `brig policy test <domain>` — host-side passthrough that runs the same allow/deny logic warden uses.
- `brig events --follow` — block and tail new lifecycle events.
- `brig network <cell> --blocked` — filter to only the requests warden blocked, with reason.
- `brig list --format=wide` — adds CREATED, NETWORK columns.
- `canary` addon: scans egress traffic for canary tokens registered against a cell; on detection, blocks the request and kills the cell.
- `signer` addon scaffolding for outbound request signing.
- Shared `_common.py` addon helper module: single-source-of-truth `BLOCKED_NETWORKS`, `SubnetResolver`, `atomic_write_json`.
- Sibling addon modules (`_` prefix; not registered as mitmproxy addons): `_policy.py` for `PolicyRule` / `DomainTrie` / `Policy` (extracted from `enforce.py`); `_log_writer.py` for `AsyncLogWriter` / `LogFilter` (extracted from `logger.py`); `_notifier_state.py` for circuit-breaker / config dataclasses / URL helpers (extracted from `notifier.py`). Top-level addon files (`enforce.py` 710, `logger.py` 345, `notifier.py` 442) now own just the mitmproxy lifecycle.
- `brig.ops.atomic.atomic_write_json` host-side helper for the same temp+fsync+rename pattern.
- Invariant tests for DNS rebinding rechecks (IPv4-mapped-IPv6, IPv6 link-local), CONNECT method enforcement, IPv6 host normalization edge cases.

### Changed

- `ops` addon now bundles what was previously split across `metrics`, `ratelimit`, and `health`.
- `brig run` flag-after-image foot-gun now produces a clear error suggesting `--`.
- `brig secrets rm` requires `--yes` (or interactive y/N) before destroying a secret.
- `brig cp` colon parsing rejects ambiguous paths like `./out:put.txt` instead of silently treating them as cell references.
- gVisor (`runsc`) install in `provision-vm.sh` is pinned to a release + sha512 instead of fetching latest from the same TLS endpoint as the checksum.

### Removed

- `brig upgrade` (was a no-op printing "State is up to date").
- `brig run --tor` flag and `CellSpec.tor` field (the Tor stack management was a stub; `warden tor start` did not exist).
- `brig checkpoint` / `brig restore` argparse-unregistered handlers (dead code in `image_cmd.py`).
- `src/tui.py` and `src/dashboard.py` (1110 lines, never wired into the CLI; no tests; deferred `brig watch` in the roadmap).
- `setup.py` (referenced nonexistent modules `brig_cli` / `warden_cli` / `brig_subnet_cli`; pyproject.toml is the canonical source).
- `tui` extra in `pyproject.toml` and the `runtime` field in `BUILTIN_PROFILES` (never propagated by `apply_profile`; reconciler hardcodes `--runtime runsc`).
- `src/install-addons.sh` (duplicated `make _copy-addons` with stale `limactl start cell` instructions; the Makefile is the canonical install path).
- `requirements.lock` and `requirements-dev.lock` (auto-generated months ago; `uv.lock` is the canonical lockfile and matches `make setup`).
- Dead constants `HOST_SERVICE_DOMAIN_SUFFIX` and `SCRIPT_EXTENSIONS` in `brig/config.py` (defined but never imported).
- `addons*` from the setuptools `packages.find` include list — `src/addons/` has no `__init__.py` and is mounted into the warden container by `make _copy-addons`, not installed by pip.
- `src/addons/summarizer.py` (519 lines): never loaded by warden (missing from `proxy.py:166` optional addon list); no `addons = [...]` declaration so mitmproxy wouldn't register anything anyway; advertised CLI `warden logs compact` doesn't exist; `compact_cell_logs()` had no callers; the `log_compaction` policy key was read by no enforcement path; referenced 2024-era Claude model names. AI log summarization belongs as a host-side `brig logs compact` tool (future work) reading JSONL rather than running inside the minimal warden container.
- `src/addons/signer.py` (273 lines): warden "loaded" it via `-s /addons/signer.py` but it had no `addons = [...]` declaration and no mitmproxy hooks (`request` / `response` / etc.), so mitmproxy registered nothing; `init()` was never called, `add_entry()` was never called from outside its own tests; the `verify_batch()` helper had no host-side audit-verifier consumer. Audit-trail signing as a feature should be re-implemented as either a real mitmproxy addon (with hooks that wrap logger.py) or a host-side `brig audit verify` tool.
- `src/addons/canary.py` (214 lines): the addon was fully wired into warden and would correctly block + kill cells on canary detection, **but no part of brig (CLI, SDK, or policy-set command) writes the `canary_tokens` field to per-cell policy files**, so the only way to register a canary was hand-editing JSON. Removed because the surface didn't exist and isn't planned for the first ship. If/when canary tokens come back, they need a `brig canary add <cell>` command (with `getpass`-style value entry), persistence to per-cell policy via the existing atomic-write helpers, and a `warden reload` after registration.
- `src/warden/stats.py` (45 lines): `query_metrics()` queried a Unix socket that no addon creates (`ops.py`'s health endpoint is HTTP). The only past caller was `src/tui.py`, which is gone.
- `src/warden/tor.py` (88 lines) and the `warden tor` subcommand tree: `warden tor start` was already removed as a stub, leaving `stop` / `status` operating on `warden-tor` / `warden-privoxy` containers that no code in the repo could ever create.
- `warden/logs.py:export_logs`: defined but had no `warden logs export` subcommand and no callers. `warden logs prune` (the actually-wired path) is unaffected.
- `scripts/brig-manpage.py` (377 lines): orphan man-page generator. No `make manpage` target invoked it, no docs referenced it, and macOS Python CLIs rarely ship man pages. If we want one, generate from `argparse` directly in CI.
- `src/brig-completion.bash` and `src/brig-completion.zsh` (179 + ~100 lines): hand-maintained shell completion that drifted badly — listed nonexistent `brig cat`, missing 15+ real commands (doctor, health, history, init, metrics, preflight, profiles, up, down, watchdog, pull, warmup, image-verify, secrets subcommands, config subcommands, events, shell, wait, rename, files), missing every flag added since the script was written. No install path documented. If completion comes back, generate from argparse via a `brig completion bash|zsh` subcommand (e.g. argcomplete).
- `brig.ops.cache.invalidate_cell_cache`: defined but never called from any production path. The cache is keyed for general use; cell-state cache invalidation can be added back when there's an actual call site.

### Added

- `brig policy rm <cell>`: drops a cell's per-cell policy; the cell then blocks all egress (default-deny) on the next request. Wired up an existing-but-unreachable `delete_cell_policy()` function that already had tests.
- The `log_compaction` block in `docs/examples/network-policy.example.json` (no consumer).

### Moved

- `src/brig-manpage.py` → `scripts/brig-manpage.py` (one-shot generator script; was at top-level src/ where importable modules live).
- `src/config/network-policy.example.json` → `docs/examples/network-policy.example.json` (reference doc, not installed by anything).
- `src/config/brig-logrotate.conf` → `docs/examples/brig-logrotate.conf` (admin-installed manually).

### Security

- **H1**: Host services now require explicit per-cell ACL via `host_services` in cell policy. Previously any cell could reach any declared host service regardless of per-cell policy.
- **H2/H5**: `notifier` urllib fallback no longer follows redirects (a 302 from a webhook could otherwise reach an internal-by-name host that DNS validation hadn't pre-checked). urllib3 PoolManager now sets `cert_reqs=CERT_REQUIRED` and a CA bundle explicitly.
- **H3**: `_normalize_hostspec` now validates multi-colon strings against `ipaddress.ip_address` instead of treating them as bare IPv6 by colon count. Closes a host-header smuggling edge case.
- **H4**: `server_connected` and `responseheaders` now skip blocked-IP checks based on `flow.metadata["host_service"]`, not on a `(ip, port)` tuple. The tuple match was exploitable via DNS rebinding to a (host_ip, host_service_port) pair.
- **M1**: Ingress token reads call `validate_secret_path` to prevent symlink escape from the secrets directory.
- **M2**: `verify_image_signature` no longer falls back to `podman image trust show` (which only inspects global policy and could vacuously accept any image when a single `accept` line was present anywhere). cosign is now a hard prerequisite.
- **M3**: Sensitive directories (`~/.brig/secrets`, `~/.brig/cells/addons`, `~/.brig/state/system`) are chmod 0700 on `brig init`.
- **M4**: Ingress route validator rejects `cell_ip` ending in `.1` (warden gateway address on every cell network), preventing an HTTP-level loop into mitmproxy itself.

## [0.2.0] - 2026-02-20

### Added

- SDK exception subclasses: `CellNotFoundError`, `ImageVerificationError`, `ProfileError`, `SecretNotFoundError`.
- `Brig.get(name)` method — returns `Cell` or `None` for existence checks.
- `Cell.is_alive()` method — checks if cell is still running.
- `Cell.logs(follow=True)` streaming — returns async iterator yielding lines.
- `Brig.run()` new parameters: `egress_allow`, `workdir`, `image_digest`, `canary_tokens`.
- CLI flags: `--workdir`, `--image-digest` for `brig run`.
- Canary token detection addon for Warden (`src/addons/canary.py`).
- Image digest verification — pre-start check, no cell created on mismatch.
- Canary tokens passed via tempfile to avoid `ps` exposure.
- SDK-side profile validation against known profile names.
- SDK-side `image_digest` format validation (`sha256:` prefix required).
- SDK-side `secrets` flag injection validation.
- Error pattern sync test to guard CLI/SDK error message contract.

### Changed

- **Breaking:** `Cell.wait()` now returns `int` (exit code) instead of `CellResult`.
- **Breaking:** `Cell.rm()` only catches `CellNotFoundError`, not all `BrigError`.
- `Cell.rm()` is now idempotent (does not raise if cell already gone).
- `logs_sync(follow=True)` now raises `BrigError` instead of returning unusable object.
- Canary addon `_kill_cell` runs in background thread to avoid blocking proxy traffic.
- Load test thresholds bumped from 2s to 5s for CI stability.

### Deprecated

- `CellResult` dataclass — `wait()` returns `int` directly. Will be removed in 0.3.0.

### Security

- Canary file path validation: must have `brig_canary_` prefix, no path traversal.
- `_kill_cell` validates cell name and uses `--` separator to prevent argument injection.
- Non-string canary token values are safely skipped (no TypeError).
- Empty image digest from failed inspect produces clear error instead of confusing mismatch.

## [0.1.0] - 2026-02-12

### Added

- Core cell lifecycle: `brig run`, `start`, `stop`, `rm`, `list`, `inspect`.
- Warden egress proxy with mitmproxy, policy enforcement, and request logging.
- gVisor sandboxing with runtime verification (no silent downgrade).
- Per-cell networking with dedicated subnets and no east-west traffic.
- Network policy system with domain allowlists, deny rules, and rate limiting.
- Initial Warden addon system: `enforce` (policy), `logger` (per-cell JSONL logs), `ratelimit`, `metrics`, `health`, `notifier`, `summarizer` (AI log compaction).
- SDK for programmatic cell management (`brig.sdk`).
- TUI dashboard via optional `textual` dependency (`brig tui`).
- Security model with 9 invariants and verification tests (`brig verify`).
- Warden watchdog with automatic proxy restart on failure.
- Log compaction with multiple strategies (delete, aggregate, sample, archive, AI).
- Secret management via file-based mounts (never in environment variables).
- Lima VM integration for macOS hardware isolation boundary.
- Subnet allocator for automatic per-cell network assignment.
- Cell pause/unpause, rename, export/restore, diff, and file operations.
- Configuration system with `brig config show/set/reset`.
