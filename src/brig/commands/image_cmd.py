"""
CLI handlers for image operations.
"""

from __future__ import annotations

from typing import Any

from brig.vm.shell import vm_run
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.security.image import verify_image_signature


def cmd_pull(args: Any) -> int:
    """Handle `brig pull` — pull and cache an image."""
    result = vm_run(
        ["podman", "pull", args.image],
    )
    if result.returncode != 0:
        raise BrigError(f"Failed to pull image: {result.stderr.strip()}")
    info(f"Pulled {args.image}")
    return 0


def cmd_warmup(args: Any) -> int:
    """Handle `brig warmup` — pre-pull images for a profile."""
    from brig.cell.profiles import BUILTIN_PROFILES, load_profile

    profile_name = getattr(args, "profile", None)
    if profile_name:
        load_profile(profile_name)  # Validate profile exists.

    # Warmup just ensures the proxy image is available.
    output("Warming up proxy image...")
    result = vm_run(
        ["podman", "image", "exists",
         "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"],
    )
    if result.returncode != 0:
        output("Pulling proxy image...")
        vm_run(
            ["podman", "pull",
             "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"],
        )
    output("Warmup complete")
    return 0


def cmd_verify_image(args: Any) -> int:
    """Handle `brig image-verify` — verify image signature."""
    ok, msg, details = verify_image_signature(
        args.image,
        key=getattr(args, "key", None),
        keyless=getattr(args, "keyless", False),
    )
    output(f"{'VERIFIED' if ok else 'FAILED'}: {msg}")
    return 0 if ok else 1
