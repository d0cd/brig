"""
Image signature verification using cosign or podman trust.

Cosign and podman run on the host (macOS), not inside the VM,
so these use subprocess directly (not vm_run).
"""

from __future__ import annotations

import json
import subprocess

from brig.ops.logging import debug


def _parse_cosign_output(stdout: str) -> dict:
    """Parse cosign verify JSON output for verification details."""
    try:
        data = json.loads(stdout)
        if isinstance(data, list) and data:
            first = data[0]
            return first if isinstance(first, dict) else {}
        return {}
    except (json.JSONDecodeError, IndexError):
        return {}


def verify_image_signature(
    image: str,
    key: str | None = None,
    keyless: bool = False,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
) -> tuple[bool, str, dict]:
    """Verify image signature using cosign or podman trust.

    Returns (success, message, details) tuple.
    Note: cosign runs on macOS host, not in the VM.

    Keyless verification is ADVISORY unless both certificate_identity and
    certificate_oidc_issuer are supplied: with neither, cosign accepts a
    signature from any Fulcio identity, so a success means "signed by
    someone", not "signed by who you trust". Image integrity at run time is
    enforced by digest pinning, not by this command.
    """
    result = subprocess.run(
        ["which", "cosign"], check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        # cosign is a hard prerequisite: `podman image trust show` accepts an
        # image whenever ANY policy line says "accept", even when the specific
        # image isn't in that policy's scope — vacuous trust, so no fallback.
        return (
            False,
            "cosign is not installed. Install from https://docs.sigstore.dev/cosign/. "
            "Image signature verification requires cosign — `podman image trust` is "
            "not specific enough to attest individual images.",
            {},
        )

    cmd = ["cosign", "verify"]
    if key:
        cmd.extend(["--key", key])
    elif keyless:
        if certificate_identity:
            cmd.extend(["--certificate-identity", certificate_identity])
        if certificate_oidc_issuer:
            cmd.extend(["--certificate-oidc-issuer", certificate_oidc_issuer])
    cmd.append(image)

    debug(f"Verifying image with cosign: {image}")
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    if result.returncode == 0:
        details = _parse_cosign_output(result.stdout)
        return True, "Signature verified with cosign", details

    stderr = result.stderr or ""
    if "no matching signatures" in stderr.lower():
        return False, "Image has no signature", {}
    return False, f"Signature verification failed: {stderr.strip()}", {}
