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

```python
# Write to temp, rename to target
tmp_file = target_file.with_suffix('.tmp')
with open(tmp_file, 'w') as f:
    json.dump(data, f)
tmp_file.rename(target_file)  # Atomic on POSIX
```

### File Locking

```python
with open(LOCK_FILE, 'w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    # Critical section
```

### Path Validation

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

```
~/.brig/
├── lima.yaml           # VM config
├── network-policy.yaml # Warden allowlist
├── cells/              # Cell definitions
│   └── addons/        # Warden addons
├── secrets/            # One file per secret
└── state/              # Cell workspaces and logs
    └── system/        # Subnet allocator state
```

## Documentation

- `docs/design/` - Architecture, security, reference
- `docs/learning/` - Quickstart, concepts, workflows, troubleshooting
- `docs/PLAN.md` - Implementation roadmap

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
