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
            return data[0]
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
    """
    result = subprocess.run(
        ["which", "cosign"], check=False, capture_output=True,
    )
    if result.returncode != 0:
        debug(f"Verifying image with podman trust: {image}")
        result = subprocess.run(
            ["podman", "image", "trust", "show"],
            check=False, capture_output=True, text=True,
        )
        if result.returncode == 0 and "accept" in result.stdout.lower():
            return True, "Image from trusted registry", {}

        return (
            False,
            "cosign is not installed. Install from https://docs.sigstore.dev/cosign/",
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
