"""
Image signature verification using cosign.

Cosign runs on the host (macOS), not inside the VM, so this uses subprocess
directly (not vm_run). There is no `podman trust` fallback — `podman image
trust show` returns a global accept/reject policy that can't attest an
individual image, so cosign is a hard requirement.
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
    key: str,
) -> tuple[bool, str, dict]:
    """Verify an image signature against a cosign public key.

    Returns (success, message, details) tuple.
    Note: cosign runs on macOS host, not in the VM.

    Key-based only: a success proves the image was signed by the holder of
    `key`. Keyless (Fulcio) verification is intentionally not offered — without
    an identity/issuer constraint it only proves an image is signed, not by
    whom, which is false confidence. Image integrity at run time is enforced by
    digest pinning (see `_verify_image_digest_on_start`), not by this command.
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

    cmd = ["cosign", "verify", "--key", key, image]

    debug(f"Verifying image with cosign: {image}")
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    if result.returncode == 0:
        details = _parse_cosign_output(result.stdout)
        return True, "Signature verified with cosign", details

    stderr = result.stderr or ""
    if "no matching signatures" in stderr.lower():
        return False, "Image has no signature", {}
    return False, f"Signature verification failed: {stderr.strip()}", {}
