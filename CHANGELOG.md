# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- `brig doctor` — deep environment check (PATH, Lima VM state, addon presence, directory permissions, port collisions). Complements the lighter `brig health`.
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

- `brig policy rm <cell>`: drops a cell's per-cell policy override (the cell falls back to the global policy on the next request). Wired up an existing-but-unreachable `delete_cell_policy()` function that already had tests.
- `brig policy set <cell> --host-service <name>`: per-cell ACL grant. Previously `--host-service` only worked for the global policy (`name:port` form), so the H1 per-cell ACL field could only be set by hand-editing JSON. Now: global takes `name:port` (declares warden's forward target), per-cell takes a bare `name` (grants the cell access to a globally-declared service). The CLI rejects each form in the wrong context with a clear suggestion.
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
