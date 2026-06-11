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
| **Image signatures** | `brig image verify` requires `cosign`. The previous `podman image trust` fallback was removed — it returned a global policy that could vacuously accept any image when a single `accept` line was present anywhere. |

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

Warden runs a **custom** image (mitmproxy + the OpenTelemetry SDK), built
inside the VM so wheels match the runtime arch. `src/warden/proxy.py` holds:

```python
WARDEN_IMAGE_TAG    = "..."          # localhost/brig-warden:<TAG>
WARDEN_IMAGE_DIGEST = "sha256:..."   # pin verified at start (_verify_warden_image)
BASE_IMAGE          = "docker.io/mitmproxy/mitmproxy@sha256:..."  # no-OTel fallback only
```

`_warden_image()` runs `localhost/brig-warden:<TAG>` whenever
`WARDEN_IMAGE_DIGEST` is pinned (the normal case); `BASE_IMAGE` is only the
fallback when no custom image is pinned. **Patching `BASE_IMAGE` alone does
NOT change the launched image.** To update:

1. Bump `BASE_IMAGE` and/or the OTel SDK version in `src/warden/image/Dockerfile`.
2. Rebuild + re-pin: `./scripts/build-warden-image.sh` — it builds inside the
   VM and rewrites `WARDEN_IMAGE_TAG` + `WARDEN_IMAGE_DIGEST` in `proxy.py`.
3. Run E2E tests: `make e2e`
4. Commit the one-line digest update with the version in the message.

## gVisor (runsc) bumps

`GVISOR_RELEASE` + a per-arch sha512 are pinned in **two** files that must
stay in sync — `scripts/provision-vm.sh` and `src/brig/vm/lima.yaml.template`
— and `scripts/check-gvisor-pin.sh` (wired into CI) hard-fails on drift. Use
the canonical updater, which writes both:

1. Pick a release from <https://github.com/google/gvisor/releases>.
2. `make pin-gvisor` (or `./scripts/pin-gvisor.sh <RELEASE>`) — fetches the
   per-arch sha512 from the release and rewrites both files.
3. Verify: `./scripts/check-gvisor-pin.sh` (the same check CI runs).
4. Commit; do not hand-edit only one of the two files (CI will reject it).

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
3. Run `brig system verify` to confirm invariants still hold.

**Brig's own code:**

1. Security issues should be reported via GitHub security advisories (private disclosure). See `SECURITY.md` at the repo root.
2. All 12 invariants have tests — run `brig system verify` after any security fix.
3. The audit trail is in `docs/INVARIANTS.md`.
