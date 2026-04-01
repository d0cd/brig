"""Image management commands: pull, warmup."""

import re

from brig.commands._helpers import (
    Spinner,
    error,
    output,
    print_error,
    run,
)

# Valid image reference: registry/repo:tag or registry/repo@sha256:digest.
_IMAGE_RE = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*'  # Name (registry/repo).
    r'(?::[a-zA-Z0-9._-]+)?'          # Optional tag.
    r'(?:@sha256:[a-fA-F0-9]{64})?$'  # Optional digest.
)


def _validate_image_name(image: str) -> bool:
    """Validate image name is safe and well-formed."""
    if not image or len(image) > 512:
        return False
    if not _IMAGE_RE.match(image):
        return False
    return True


def cmd_pull(args) -> int:
    """Pull and cache a container image inside the Lima VM."""
    image = args.image

    if not _validate_image_name(image):
        error(
            f"Invalid image name: {image}",
            "Image must be in format: [registry/]name[:tag][@sha256:digest]"
        )

    with Spinner(f"Pulling image {image}") as spinner:
        result = run(["podman", "pull", image], check=False, capture=True)
        if result.returncode != 0:
            spinner.fail(f"Failed to pull {image}")
            print_error(
                result.stderr.strip() if result.stderr else "Unknown error",
                "Check the image name and registry connectivity"
            )
            return 1
        spinner.success(f"Image {image} pulled successfully")

    return 0


def cmd_warmup(args) -> int:
    """Pre-pull commonly used images for a profile or explicit image list."""
    profile_name = getattr(args, "profile", None)
    images = getattr(args, "images", None) or []

    # Default images for profiles.
    profile_images = {
        "untrusted": ["alpine:3.21"],
        "supervised": ["python:3.12-slim", "node:20-slim"],
        "dev": ["python:3.12", "node:20", "golang:1.22", "ubuntu:22.04"],
        "airgapped": ["alpine:3.21", "python:3.12-slim"],
    }

    if profile_name:
        images = profile_images.get(profile_name, []) + images
        output(f"Warming up images for profile: {profile_name}")
    elif not images:
        error(
            "Specify --profile or provide image names",
            "Example: brig warmup --profile supervised"
        )

    # Deduplicate.
    seen = set()
    unique_images = []
    for img in images:
        if img not in seen:
            seen.add(img)
            unique_images.append(img)

    failures = 0
    for image in unique_images:
        with Spinner(f"Pulling {image}") as spinner:
            result = run(["podman", "pull", image], check=False, capture=True)
            if result.returncode != 0:
                spinner.fail(f"Failed to pull {image}")
                failures += 1
            else:
                spinner.success(f"Pulled {image}")

    if failures:
        print_error(f"{failures} image(s) failed to pull", "Check image names and registry connectivity")
        return 1

    output(f"Warmed up {len(unique_images)} image(s)")
    return 0
