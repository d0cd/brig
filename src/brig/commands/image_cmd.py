"""
CLI handlers for image operations.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from brig.vm.shell import vm_run
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.security.image import verify_image_signature


def cmd_build(args: Any) -> int:
    """Handle `brig build <context-dir>` — build a container image.

    Brig runs podman inside the Lima VM, and only ~/.brig/* is mounted
    there. Rather than asking users to stage build contexts under ~/.brig,
    tar the host directory and stream it into `sudo podman build -` over
    `limactl shell`. That works for any host path.

    Tag is derived from the directory's basename if --tag isn't supplied
    (e.g. `brig build cells/hermes` → localhost/hermes:latest). The
    Containerfile is picked up implicitly by podman (Containerfile or
    Dockerfile).
    """
    ctx = Path(args.context).resolve()
    if not ctx.is_dir():
        raise BrigError(f"Build context is not a directory: {ctx}")

    tag = getattr(args, "tag", None) or f"localhost/{ctx.name}:latest"
    if not re.match(r"^[a-z0-9][a-z0-9._/:-]*$", tag):
        raise BrigError(
            f"Invalid image tag: {tag!r} "
            "(expected lowercase alnum + . _ / : -)"
        )

    # Find Containerfile / Dockerfile so we can refuse early if neither exists.
    if not any((ctx / f).is_file() for f in ("Containerfile", "Dockerfile")):
        raise BrigError(
            f"No Containerfile or Dockerfile in {ctx}",
            suggestion="Add one, or pass --containerfile-relative-path",
        )

    build_args: list[str] = []
    for ba in getattr(args, "build_arg", None) or []:
        build_args += ["--build-arg", ba]

    info(f"Building {tag} from {ctx}")
    # Compose: tar | limactl shell <vm> -- sudo podman build -t <tag> [args] -
    tar = subprocess.Popen(
        ["tar", "-C", str(ctx), "-cf", "-", "."],
        stdout=subprocess.PIPE,
    )
    try:
        build = subprocess.Popen(
            [
                "limactl", "shell", "--workdir", "/", "brig", "--",
                "sudo", "podman", "build", "-t", tag, *build_args, "-",
            ],
            stdin=tar.stdout,
        )
        if tar.stdout:
            tar.stdout.close()  # Let SIGPIPE propagate if build exits early.
        rc_build = build.wait()
    finally:
        tar.wait()

    if rc_build != 0:
        raise BrigError(f"podman build failed (rc={rc_build})")

    output(f"Built {tag}")
    return 0


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
