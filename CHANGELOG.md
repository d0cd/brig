# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- 8-addon system: enforce, logger, ratelimit, metrics, health, notifier, sanitizer, summarizer.
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
