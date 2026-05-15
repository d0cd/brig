# Brig Security

## Security Model

Four boundaries protect the macOS host from untrusted workloads:

```
macOS Host
  └─ Lima VM              ← Hard security boundary (hardware virtualization)
     └─ gVisor            ← Defense-in-depth (syscall filtering)
        └─ Cell           ← Per-cell isolated network (--internal)
           └─ Warden      ← Mandatory egress/ingress choke point
```

### Nine Invariants

1. **No east-west traffic** — per-cell `--internal` networks, no bridge
2. **Proxy cannot be abused as gateway** — port 80/443 only, private IP block, DNS rebinding defense
3. **Secrets are observable, not preventable** — Warden logs all egress
4. **macOS state directory is untrusted** — path validation, input sanitization
5. **gVisor must be active** — `--runtime runsc` hardcoded, verified by `brig verify`
6. **Only Warden on proxy-external** — cell spec rejects `network: proxy-external`
7. **No privileged services on cell networks** — verified by `brig verify`
8. **Cells must be single-homed** — cell spec rejects list network values
9. **Warden must run before cells start** — enforced in `run_cell()`

### Scoped Relaxations

- **Host services** (`.host.brig`) relax invariant 2 for explicitly declared name:port pairs
- **Ingress** adds authenticated inbound through Warden (opt-in per cell, token-authenticated)

See [docs/INVARIANTS.md](INVARIANTS.md) for enforcement locations and test coverage.

## Supply Chain Security

### What's in place

| Layer | Protection |
|---|---|
| **Python deps** | Minimal surface — only `pyyaml` in production. `pip-audit` in CI checks for known CVEs on every PR. |
| **CI actions** | All GitHub Actions pinned by commit SHA (not tag). Dependabot auto-updates weekly. |
| **Container image** | Mitmproxy image pinned by SHA256 digest in `src/warden/proxy.py`. Tag mutations don't affect builds. |
| **SAST** | Bandit scans `src/` on every PR. Skips B101 (assert), B104 (bind 0.0.0.0), B108 (hardcoded tmp). |
| **Secrets** | TruffleHog scans git history for leaked credentials on every PR. |
| **Dependabot** | Weekly PRs for pip + GitHub Actions dependency updates. |

### Dependency inventory

| Dependency | Version | Why | Risk |
|---|---|---|---|
| `pyyaml` | >=6.0 | Cell definition parsing | Low — C extension, well-maintained |
| `mitmproxy` | pinned SHA | Warden proxy runtime | Medium — large dependency tree inside container |
| `lima` | system install | VM management | Low — Apple-maintained |
| `podman` | system install | Container runtime | Low — Red Hat-maintained |
| `gvisor (runsc)` | system install | Syscall filtering | Low — Google-maintained |

### Container image maintenance

The mitmproxy container image is pinned by digest:
```python
IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec..."
```

To update:
1. Pull the new image: `podman pull docker.io/mitmproxy/mitmproxy:latest`
2. Get the digest: `podman inspect --format '{{.Digest}}' docker.io/mitmproxy/mitmproxy:latest`
3. Update `src/warden/proxy.py` with the new digest
4. Run E2E tests: `make e2e`
5. Commit with the mitmproxy version in the message

### Responding to CVEs

**Python dependency CVE:**
1. `pip-audit` CI job will fail on the next PR, flagging the vulnerability
2. Update the pinned version in `pyproject.toml`
3. Verify tests pass, merge

**Container image CVE:**
1. Check if the CVE affects packages in the mitmproxy image
2. If yes, update the image digest (see above)
3. If the fix isn't in a released mitmproxy image, consider building a patched image

**Lima / Podman / gVisor CVE:**
1. These are system installs managed by Homebrew (Lima, Podman) or direct download (gVisor)
2. Update via `brew upgrade lima podman` or download new runsc binary
3. Run `brig verify` to confirm invariants still hold

**Brig's own code:**
1. Security issues should be reported via GitHub security advisories (private disclosure)
2. All 9 invariants have tests — run `brig verify` after any security fix
3. The audit trail is in `docs/INVARIANTS.md`

## Reporting Security Issues

Report security vulnerabilities privately via GitHub Security Advisories,
not public issues. See [GitHub's guide](https://docs.github.com/en/code-security/security-advisories).
