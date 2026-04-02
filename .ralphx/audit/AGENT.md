# Agent Instructions

## Repository

- Python 3.12+ codebase in `/workspace/src/`
- Tests in `/workspace/tests/` — run with `cd /workspace && python -m pytest tests/ -x`
- ~12,500 lines of source across src/

## CRITICAL: Do NOT modify source code or tests

This is a read-only audit. Only write to `.ralphx/audit/findings/report.md`.

## Key source files

- `src/addons/enforce.py` (733 lines) — mitmproxy policy enforcement
- `src/warden.py` (2063 lines) — Egress proxy manager
- `src/brig/commands/_helpers.py` (1509 lines) — Shared helpers, constants, globals
- `src/brig/commands/system.py` (1272 lines) — System commands
- `src/brig/commands/lifecycle.py` (1125 lines) — Container lifecycle
- `src/brig/sdk.py` (771 lines) — SDK module
- `src/addons/logger.py` (763 lines) — Request logging addon
- `src/addons/notifier.py` (536 lines) — Webhook notifications with circuit breaker
- `src/addons/summarizer.py` (513 lines) — AI-powered log compaction
- `src/addons/metrics.py` (457 lines) — Prometheus metrics
- `src/addons/ratelimit.py` (308 lines) — Rate limiting
- `src/addons/signer.py` (278 lines) — Request signing
- `src/addons/canary.py` (217 lines) — Canary token detection
- `src/addons/health.py` (213 lines) — Health checks

## Security model (for validating security findings)

- Lima VM is the only hard security boundary
- gVisor is defense-in-depth (not a security boundary)
- No east-west traffic between cells
- Warden is mandatory egress choke point
- All paths must be validated (no traversal)
- IPs must block RFC1918, CGNAT, localhost, link-local, reserved
- Ports restricted to 80/443 for egress
- Secrets in files only, never env vars
- Default-deny on errors (fail closed)

## Report format

Append all findings to `.ralphx/audit/findings/report.md`. Create the file on first story if it doesn't exist. Each story adds a section. Do not overwrite previous sections.
