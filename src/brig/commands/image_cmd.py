"""
CLI handlers for image operations.
"""

from __future__ import annotations

import fnmatch
import io
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from brig.vm.shell import vm_run
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.security.image import verify_image_signature


def _load_ignore_patterns(ctx: Path) -> list[str]:
    """Read `.containerignore` (preferred) or `.dockerignore` from `ctx`.

    Returns the raw pattern list with comments and blank lines stripped.
    """
    for name in (".containerignore", ".dockerignore"):
        ig = ctx / name
        if not ig.is_file():
            continue
        patterns: list[str] = []
        for raw in ig.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
        return patterns
    return []


def _path_excluded(relpath: str, patterns: list[str]) -> bool:
    """Match a path-relative-to-context against dockerignore-style globs.

    Supports `*`, `?`, `**` (any-depth), and exact paths. Trailing slash
    on a pattern means directory-only. No support for negation (`!`); add
    when we hit a case that needs it.
    """
    rel = relpath.replace("\\", "/")
    for pat in patterns:
        # Strip trailing slash; pattern still matches dir + descendants
        # when we compare the path prefix below.
        is_dir_only = pat.endswith("/")
        p = pat.rstrip("/")

        # `**` cross-component → translate to a regex-friendly form.
        # Convert each segment, joining with `/`; `**` becomes `.*`.
        regex_parts = []
        for seg in p.split("/"):
            if seg == "**":
                regex_parts.append(".*")
            else:
                regex_parts.append(fnmatch.translate(seg).rstrip(r"\Z").rstrip("$"))
        # Anchor at start; allow trailing path after the matched prefix so
        # `hermes-src/.git` matches `hermes-src/.git/HEAD`.
        pattern = "^" + "/".join(regex_parts) + r"(/.*)?$"
        if re.match(pattern, rel):
            return True
        # Plain string prefix match for simple "dir" forms.
        if not is_dir_only and rel == p:
            return True
    return False


def _stream_tar_context(ctx: Path, patterns: list[str]) -> bytes:
    """Tar the context directory honoring ignore patterns. Returns bytes.

    Buffered (not streamed) for simplicity; most contexts are <100 MB and
    fitting in memory is acceptable. If/when someone needs to build a
    >1 GB context, switch to a streaming Popen-tar pipeline.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in sorted(ctx.rglob("*")):
            rel = path.relative_to(ctx).as_posix()
            if _path_excluded(rel, patterns):
                continue
            try:
                tar.add(str(path), arcname=rel, recursive=False)
            except OSError as e:
                info(f"  skip {rel}: {e}")
    return buf.getvalue()


def cmd_build(args: Any) -> int:
    """Handle `brig image build <context-dir>` — build a container image.

    Brig runs podman inside the Lima VM, and only ~/.brig/* is mounted
    there. Rather than asking users to stage build contexts under ~/.brig
    or add a Lima mount for the source tree, tar the host directory and
    stream it into `sudo podman build -`. Works for any host path and
    keeps the host-filesystem-invisible-to-VM property intact (hermes
    team's brig-image-build-feedback.md). `.containerignore` and
    `.dockerignore` are honored.

    Tag is derived from the directory's basename if --tag isn't supplied
    (e.g. `brig image build cells/hermes` → localhost/hermes:latest).
    The Containerfile is auto-detected (Containerfile or Dockerfile)
    unless overridden with --file.
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

    # Containerfile resolution: explicit --file wins, else auto-detect.
    cfile = getattr(args, "file", None)
    if cfile:
        cfile_path = (ctx / cfile) if not Path(cfile).is_absolute() else Path(cfile)
        if not cfile_path.is_file():
            raise BrigError(f"Containerfile not found: {cfile_path}")
        cfile_arg = ["-f", str(cfile_path.relative_to(ctx))]
    else:
        autodetect = next(
            (f for f in ("Containerfile", "Dockerfile") if (ctx / f).is_file()),
            None,
        )
        if autodetect is None:
            raise BrigError(
                f"No Containerfile or Dockerfile in {ctx}",
                suggestion="Add one, or pass --file <relative-path>",
            )
        cfile_arg = []  # Podman auto-detects.

    build_args: list[str] = []
    for ba in getattr(args, "build_arg", None) or []:
        build_args += ["--build-arg", ba]

    patterns = _load_ignore_patterns(ctx)
    if patterns:
        info(f"Honoring {len(patterns)} ignore pattern(s) from "
             f".containerignore/.dockerignore")

    info(f"Building {tag} from {ctx}")
    tar_bytes = _stream_tar_context(ctx, patterns)
    build = subprocess.run(
        [
            "limactl", "shell", "--workdir", "/", "brig", "--",
            "sudo", "podman", "build", "-t", tag, *cfile_arg, *build_args, "-",
        ],
        input=tar_bytes,
        check=False,
    )
    if build.returncode != 0:
        raise BrigError(f"podman build failed (rc={build.returncode})")

    output(f"Built {tag}")
    return 0


def cmd_load(args: Any) -> int:
    """Handle `brig image load <tarball>` — side-load a prebuilt image.

    For the CI-output / air-gapped / vendor-drop case where someone
    has a `podman save` tarball and wants it visible inside the VM's
    rootful podman without going through a registry.
    """
    tarball = Path(args.tarball).resolve()
    if not tarball.is_file():
        raise BrigError(f"Tarball not found: {tarball}")

    info(f"Loading {tarball.name} into VM podman...")
    with tarball.open("rb") as f:
        result = subprocess.run(
            ["limactl", "shell", "--workdir", "/", "brig", "--",
             "sudo", "podman", "load"],
            stdin=f, capture_output=True, text=True, check=False,
        )
    if result.returncode != 0:
        raise BrigError(f"podman load failed: {result.stderr.strip()}")
    # podman load's stdout is "Loaded image: <name:tag>"
    output(result.stdout.strip() or f"Loaded {tarball.name}")
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
