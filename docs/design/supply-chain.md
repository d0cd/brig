# Supply Chain Security

How we keep Brig's dependencies, container images, and CI infrastructure trustworthy.

## What's in place

| Layer | Protection |
|---|---|
| **Python deps** | Minimal surface — only `pyyaml` in production. `pip-audit` in CI checks for known CVEs on every PR. |
| **CI actions** | All GitHub Actions pinned by commit SHA (not tag). Dependabot auto-updates weekly. |
| **Container image** | Mitmproxy image pinned by SHA256 digest in `src/warden/proxy.py`. Tag mutations don't affect builds. |
| **gVisor (runsc)** | Pinned to a specific release + sha512 checksum in `scripts/provision-vm.sh`. The previous "latest + checksum from same TLS endpoint" pattern only detected corruption, not authenticity. |
| **SAST** | Bandit scans `src/` on every PR. Skips B101 (assert), B104 (bind 0.0.0.0), B108 (hardcoded tmp). |
| **Secrets** | TruffleHog scans git history for leaked credentials on every PR. |
| **Dependabot** | Weekly PRs for pip + GitHub Actions dependency updates. |
| **Image signatures** | `brig image-verify` requires `cosign`. The previous `podman image trust` fallback was removed — it returned a global policy that could vacuously accept any image when a single `accept` line was present anywhere. |

## Dependency inventory

| Dependency | Version | Why | Risk |
|---|---|---|---|
| `pyyaml` | >=6.0 | Cell definition parsing | Low — C extension, well-maintained |
| `mitmproxy` | pinned SHA | Warden proxy runtime | Medium — large dependency tree inside container |
| `lima` | system install | VM management | Low — Apple-maintained |
| `podman` | system install | Container runtime | Low — Red Hat-maintained |
| `gvisor (runsc)` | pinned release + sha512 | Syscall filtering | Low — Google-maintained |
| `cosign` | system install (optional) | Image signature verification | Low — Sigstore project |
| `certifi` | optional | CA bundle for `notifier` addon TLS | Low |

## Container image maintenance

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

## gVisor (runsc) bumps

`scripts/provision-vm.sh` pins `GVISOR_RELEASE` and a per-arch sha512. To bump:

1. Pick a release from <https://github.com/google/gvisor/releases>.
2. Fetch the sha512 from the release page (don't compute it from the same source you're pulling the binary from).
3. Update `GVISOR_RELEASE` and the matching `GVISOR_SHA512_BY_ARCH` entry in `scripts/provision-vm.sh`.
4. Verify locally before merging:

```bash
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RELEASE}/${ARCH}/runsc" \
  | sha512sum
# Expected sha512 must match the value you put in the script.
```

## Responding to CVEs

**Python dependency CVE:**

1. `pip-audit` CI job will fail on the next PR, flagging the vulnerability.
2. Update the pinned version in `pyproject.toml`.
3. Verify tests pass, merge.

**Container image CVE:**

1. Check if the CVE affects packages in the mitmproxy image.
2. If yes, update the image digest (see above).
3. If the fix isn't in a released mitmproxy image, consider building a patched image.

**Lima / Podman / gVisor CVE:**

1. Lima and Podman are system installs managed by Homebrew. Update via `brew upgrade lima podman`.
2. gVisor is pinned in `scripts/provision-vm.sh`. Bump the version + sha512 (see above) and re-run `make setup`.
3. Run `brig verify` to confirm invariants still hold.

**Brig's own code:**

1. Security issues should be reported via GitHub security advisories (private disclosure). See `SECURITY.md` at the repo root.
2. All 9 invariants have tests — run `brig verify` after any security fix.
3. The audit trail is in `docs/INVARIANTS.md`.
