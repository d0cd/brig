"""Stage a combined CA bundle for each cell so HTTPS clients trust
Warden's MITM cert out of the box.

Without this, every cell-image author has to extract Warden's CA, mount
it as a secret, append it onto /etc/ssl/certs, and export the assorted
SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / NODE_EXTRA_CA_CERTS
env vars themselves. Aitelier flagged that as their #1 adoption ask —
every consumer was rediscovering the workaround.

Threat model:

  - The CA cert is a PUBLIC cert (mitmproxy keeps the private key inside
    its container). Mounting it into cells does not leak signing material.
  - Source of truth is the Warden container's filesystem, not a host-side
    cached copy. Re-extracting on every cell start defends against tamper
    in `~/.brig/state/` (invariant 4: state dir untrusted) AND keeps the
    bundle correct across Warden CA rotation.
  - Bundle is staged inside the VM at /state/<cell>/ca-bundle.crt (which
    Lima virtio-fs maps to ~/.brig/state/<cell>/ — read-only mount into
    the cell). VM is the trust boundary, not macOS.
  - Bundle is the system roots concatenated with Warden's CA. Cells need
    both: MITM flows present Warden-signed certs; passthrough flows
    (invariant 11) hit upstream's real public-CA-signed cert.
  - Airgapped cells (network: none) skip the bundle — no egress = nothing
    to trust.

Cells can opt out via `trust_warden_ca: false` in cell yaml; the file
is then not mounted and the SSL_CERT_FILE / sibling env vars aren't
set, leaving the cell's image defaults in place.
"""

from __future__ import annotations

from pathlib import Path

from brig.config import PROXY_NAME, VMPaths
from brig.vm.shell import vm_run

WARDEN_CA_PATH_IN_CONTAINER = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"

# Lima's Ubuntu image keeps the system CA bundle here. If a future
# base image moves it (Alpine, RHEL-style), we'll need to detect.
SYSTEM_CA_BUNDLE_IN_VM = "/etc/ssl/certs/ca-certificates.crt"

# Where the cell sees the bundle. Same /run/brig/ namespace as the
# downward-API metadata file — cells already trust that path.
IN_CELL_PATH = "/run/brig/ca-bundle.crt"


def vm_bundle_path(cell_name: str) -> Path:
    """In-VM path of the staged bundle for `cell_name`."""
    return VMPaths.STATE_DIR / cell_name / "ca-bundle.crt"


def stage_bundle(cell_name: str) -> None:
    """Build the cell's combined CA bundle inside the VM.

    Runs sequentially in the VM via vm_run so Warden's CA extraction
    and the concat happen on the same trust boundary the cell will
    see. Atomic write (temp + mv) so cell start never sees a torn
    file. Raises RuntimeError if Warden isn't reachable — that's also
    invariant 9 (proxy must be running), so cell start would fail
    further down anyway; this is a friendlier early signal.
    """
    bundle = vm_bundle_path(cell_name)
    tmp = bundle.with_suffix(".crt.tmp")
    # Use shell composition inside the VM: extract Warden CA to a temp
    # file, concat with system roots, mv into place. All under sudo
    # because /state/<cell>/ is owned by the brig user (uid 1000),
    # and warden's container exec needs root in the VM.
    script = (
        f"set -e; "
        f"mkdir -p {bundle.parent}; "
        f"podman exec {PROXY_NAME} cat {WARDEN_CA_PATH_IN_CONTAINER} "
        f"  > /tmp/{cell_name}-warden-ca.pem; "
        f"cat {SYSTEM_CA_BUNDLE_IN_VM} /tmp/{cell_name}-warden-ca.pem > {tmp}; "
        f"mv {tmp} {bundle}; "
        f"rm -f /tmp/{cell_name}-warden-ca.pem; "
        f"chmod 0644 {bundle}"
    )
    result = vm_run(["sh", "-c", script], timeout=15)
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to stage CA bundle for {cell_name}: {result.stderr.strip()}"
        )


# Env vars common HTTPS clients honor. Order matters only for clarity —
# they all map to the same file, and any subset set by the cell wins.
_CLIENT_ENV_VARS = (
    "SSL_CERT_FILE",        # OpenSSL / Python urllib / Go crypto/tls
    "REQUESTS_CA_BUNDLE",   # Python requests
    "CURL_CA_BUNDLE",       # curl
    "NODE_EXTRA_CA_CERTS",  # Node — appends rather than replaces
)


def default_env(spec_env: list[str]) -> list[str]:
    """Return env vars to add for this cell so common runtimes pick up
    the bundle. Only adds vars the cell didn't already set — cell image
    or yaml wins. Java/Rust have no env-var convention; the file is
    still at IN_CELL_PATH for those.
    """
    already_set = set()
    for entry in spec_env:
        if "=" in entry:
            already_set.add(entry.split("=", 1)[0])
    extras: list[str] = []
    for var in _CLIENT_ENV_VARS:
        if var not in already_set:
            extras.append(f"{var}={IN_CELL_PATH}")
    return extras
