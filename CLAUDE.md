# Brig - Secure Workload Harness

## Project Overview

Brig runs untrusted code safely on macOS using Lima VM + gVisor + per-cell networks. All egress goes through the Warden proxy.

### Terminology

- **Brig**: The CLI tool for managing cells (`brig run`, `brig list`, etc.)
- **Warden**: The egress proxy that enforces network policy
- **Cell**: An isolated workload unit (container with gVisor + dedicated network)

## Key Principles

### Security First

- Validate all inputs at system boundaries
- Never hardcode secrets, keys, or credentials
- Error messages must not leak sensitive information
- Assume adversarial input on all external interfaces
- Check for injection vulnerabilities (path traversal, command injection)
- Fail closed on errors

### Correctness

- Prove code works; do not assume
- Trace logic step-by-step for non-trivial changes
- Check boundary conditions: zero, empty, null, max, negative
- If you cannot prove correctness, treat it as a bug
- Test-driven development: write the failing test first

### Minimal Changes

- Smallest change that solves the problem
- No refactoring outside the immediate task
- No "while I'm here" improvements
- Match existing code style exactly

## Security Model

### Boundaries

1. **Lima VM** - Hardware boundary protecting macOS (ONLY hard security boundary)
2. **gVisor** - Defense-in-depth inside VM (NOT a security boundary)
3. **Per-cell networks** - Isolation by topology
4. **Warden** - Mandatory egress choke point (proxy)

### Security Invariants

1. No east-west traffic between cells
2. Warden cannot be abused as gateway
3. Secrets are observable (exfiltration detectable), not preventable
4. macOS state directory is untrusted
5. gVisor must be active (no silent downgrade)
6. Only Warden may attach to proxy-external network
7. No privileged services on cell networks
8. Cells must be single-homed (one network only)
9. Warden must be running before cells start

### Validation Rules

- All paths: No traversal (`..`), normalize before use
- IP addresses: Block RFC1918, CGNAT, localhost, link-local, reserved
- Ports: Only 80/443 for egress
- Domains: Dot-boundary suffix matching for wildcards
- Secrets: Files only, never in env vars

## Usability

### Error Messages

- Include what failed and why
- Suggest next steps or diagnostic commands
- Reference relevant documentation
- Example: "ERROR: Warden is not running. Start it with: warden start"

### Determinism

- No interactive prompts in automation paths
- `--sanitize` uses allowlist/blocklist, not prompts
- Exit codes are meaningful
- Idempotent operations where possible

### Fail Fast

- Check Warden before starting cells
- Validate secrets exist before mounting
- Verify runtime after container starts
- Run preflight checks on Warden startup

## Code Patterns

### Atomic File Writes

Use the helpers — don't reinvent the temp+rename pattern.

```python
from brig.ops.atomic import atomic_write_json
atomic_write_json(target_file, data)
```

Inside addons (which can't import `brig.*`):

```python
from _common import atomic_write_json
atomic_write_json(target_file, data)
```

Both write to a tempfile in the same directory, fsync, and rename — POSIX-atomic.

### File Locking

```python
with open(LOCK_FILE, 'w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    # Critical section
```

### Path Validation

For secrets, use `brig.security.secrets.validate_secret_path` — it resolves the path
and verifies it stays inside the secrets directory (defends against symlinks).

```python
def validate_path(path):
    if '..' in path.split('/'):
        raise SecurityError("Path traversal not allowed")
    normalized = os.path.normpath(path)
    if normalized.startswith('..'):
        raise SecurityError("Path escapes workspace")
    return normalized
```

## Directory Structure

### Source (`src/`)

```
src/
├── brig/
│   ├── cli.py              # CLI entry point (argparse + dispatch)
│   ├── config.py           # Constants, paths, container_name() helper
│   ├── errors.py           # BrigError + error helpers
│   ├── sdk.py              # Programmatic SDK (Brig, Cell)
│   ├── cell/               # Cell lifecycle (spec, reconciler, profiles, names)
│   ├── network/            # Subnet allocator, proxy, validation, ingress routes
│   ├── policy/             # Policy CRUD (JSON + YAML)
│   ├── security/           # Secrets validation, image verify, invariant checks
│   ├── ops/                # Logging, cache, rate limiting, history, atomic
│   ├── workspace/          # Cell workspace file ops (cp in/out, sanitize)
│   ├── vm/                 # Lima shell wrapper + VM config template
│   ├── commands/           # Thin CLI handlers (one file per command group)
│   └── warden_addons/      # mitmproxy addons (brig package-data, NOT a submodule):
│                           # _common (shared helpers), _policy (policy data
│                           # structures), enforce, logger, ops, ingress,
│                           # notifier
└── warden/                 # Proxy manager (lifecycle, policy, health, reconcile, logs)
```

Addons ship as brig package-data and are synced into the warden container by
`brig system up`. They run inside the container with their own Python env,
flat-loaded by mitmproxy: they import sibling addons (e.g. `from _common import
...`) but cannot import `brig.*`. They are data, not an importable `brig`
submodule (no `__init__.py`), which is what keeps the flat imports valid.

### Data (`~/.brig/`)

```
~/.brig/
├── lima.yaml           # VM config
├── cells/              # Cell definitions
│   ├── network-policy.json  # Process-wide warden settings (rate limits, log
│   │                        # filter, policy trace, notifications) — NOT egress
│   │                        # allow/deny, which is per-cell
│   └── addons/        # Warden addons (deployed copy of brig/warden_addons)
├── secrets/            # One file per secret
└── state/              # Cell workspaces and logs
    └── system/        # Subnet allocator state (subnets.json)
```

## Documentation

- `docs/design/` - Architecture, security, implementation, reference
- `docs/learning/` - Quickstart, concepts, workflows, troubleshooting
- `docs/INVARIANTS.md` - Security invariant test coverage ledger

## Testing

All security invariants must have corresponding verification tests. Run `brig verify` to check invariants are maintained.

### Test-Driven Development

1. Write the failing test first.
2. Implement minimum code to pass.
3. Refactor while tests stay green.
4. Tests live in `tests/` named by functionality: `test_subnet_allocator.sh`, not `test_milestone2.sh`.
5. Every security invariant has a corresponding test.
6. No feature is complete until tests pass.

### Documentation Requirements

- **Scripts**: Header comment with purpose, usage, and prerequisites
- **Functions**: Brief comment if behavior isn't obvious from name
- **Config files**: Comment non-obvious settings and security-relevant choices
- **Tests**: Each test describes what it verifies and why it matters
- Comments explain *why*, not *what* - code shows what

### Comment Style

- Start with capital letter, end with period.
- Use consistent capitalization throughout.
- Keep comments concise but complete.
- Bad: `# check if valid` Good: `# Validate index is in range 1-254.`
