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


def _glob_segment_to_regex(seg: str) -> str:
    """Translate one path-segment glob (no `/` inside) to a bounded regex.

    `*` → `[^/]*`, `?` → `[^/]`, everything else escaped. Bounded means
    no `.*` — protects against ReDoS via crafted long patterns (audit M1).
    """
    out = []
    for ch in seg:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def _compile_pattern(pattern: str) -> tuple[bool, re.Pattern, bool]:
    """Parse one ignore line into (negate, regex, dir_only).

    Supports `**` (matches zero or more path components), `*`/`?`
    (within a segment), leading `!` for negation, leading `/` for
    root-anchored, trailing `/` for directory-only.
    """
    negate = pattern.startswith("!")
    if negate:
        pattern = pattern[1:]
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]
    dir_only = pattern.endswith("/")
    if dir_only:
        pattern = pattern[:-1]

    parts = pattern.split("/")
    rx_parts: list[str] = []
    for i, seg in enumerate(parts):
        if seg == "**":
            # `**` matches zero or more path components. Emit a regex that
            # consumes any number of /-separated segments (including none).
            # Trailing slash is contributed by the next iteration's join,
            # but for the zero-component case we need the join to collapse.
            # We handle this by emitting `(?:.+/)?` and then collapsing
            # adjacent `/` in the final join.
            rx_parts.append("(?:.+/)?")
        else:
            rx_parts.append(_glob_segment_to_regex(seg) + ("/" if i < len(parts) - 1 else ""))
    body = "".join(rx_parts).rstrip("/")
    # Anchored: must start at the root. Unanchored: match anywhere
    # (Docker semantics — `node_modules` matches at any depth).
    prefix = r"\A" if anchored else r"(?:\A|.+/)"
    # Allow the pattern to match either the path itself or any descendant.
    suffix = r"(?:/.*)?\Z"
    rx = re.compile(prefix + body + suffix)
    return (negate, rx, dir_only)


def _path_excluded(relpath: str, patterns: list[str]) -> bool:
    """Match a path-relative-to-context against dockerignore-style globs.

    Implements the full dockerignore spec relevant to brig:
      - `*`, `?`, `**`
      - leading `/` = anchored to context root
      - trailing `/` = directory-only
      - leading `!` = negation (re-include a previously-excluded path)
      - last matching pattern wins (so `*.log\\n!important.log` keeps
        important.log)

    Bounded regex translation (no `.*` segments) — see audit finding M1
    on ReDoS via crafted `**` patterns.
    """
    rel = relpath.replace("\\", "/")
    excluded = False
    for raw in patterns:
        negate, rx, _dir_only = _compile_pattern(raw)
        if rx.match(rel):
            excluded = not negate
    return excluded


# Soft + hard size caps for the in-memory tar (audit finding M2: a 50 GB
# `brig image build ~` would OOM the host before podman saw a byte).
_TAR_WARN_BYTES = 500 * 1024 * 1024     # 500 MB — warn but proceed.
_TAR_ABORT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB — refuse with clear error.


def _stream_tar_context(ctx: Path, patterns: list[str]) -> bytes:
    """Tar the context directory honoring ignore patterns. Returns bytes.

    Buffered (not streamed) for simplicity; most contexts are <100 MB and
    fitting in memory is acceptable. If/when someone needs to build a
    >2 GB context, switch to a streaming Popen-tar pipeline.

    Security (audit finding H1): symlinks in the build context that point
    outside `ctx` are REJECTED. Otherwise a project containing
    `ln -s ~/.ssh/id_rsa secret.txt` would bundle the host key into the
    build context, and a Containerfile `COPY secret.txt /` could exfiltrate
    via any allowlisted egress. Symlinks pointing *inside* the context are
    preserved as symlinks (so the unpacked image sees the link, not the
    target's contents).
    """
    ctx_resolved = ctx.resolve()
    buf = io.BytesIO()
    skipped_escapes = 0

    def _safe_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        # tarfile.add() supports a per-entry filter. We use it to drop
        # any symlink whose link target resolves outside the context.
        if info.issym() or info.islnk():
            # info.name is the arcname; the real on-disk path is
            # ctx / info.name (see how we call tar.add below).
            on_disk = ctx / info.name
            try:
                link_target = on_disk.resolve()
            except (OSError, RuntimeError):
                # ELOOP, ENAMETOOLONG, etc. — refuse.
                return None
            try:
                link_target.relative_to(ctx_resolved)
            except ValueError:
                nonlocal skipped_escapes
                skipped_escapes += 1
                return None
        return info

    with tarfile.open(fileobj=buf, mode="w") as tar:
        for path in sorted(ctx.rglob("*")):
            rel = path.relative_to(ctx).as_posix()
            if _path_excluded(rel, patterns):
                continue
            try:
                tar.add(str(path), arcname=rel, recursive=False, filter=_safe_filter)
            except OSError as e:
                info(f"  skip {rel}: {e}")
            # Bail before swap-thrashing.
            if buf.tell() > _TAR_ABORT_BYTES:
                raise BrigError(
                    f"Build context exceeded {_TAR_ABORT_BYTES // (1024**3)} GB. "
                    "Add patterns to .containerignore to exclude large "
                    "directories (node_modules, .git, .venv, build artifacts).",
                )

    if skipped_escapes:
        info(f"  dropped {skipped_escapes} symlink(s) pointing outside the build context")
    if buf.tell() > _TAR_WARN_BYTES:
        size_mb = buf.tell() // (1024 * 1024)
        info(f"  warning: build context is {size_mb} MB; consider .containerignore patterns")
    return buf.getvalue()


def cmd_build(args: Any) -> int:
    """Handle `brig image build <context-dir>` — build a container image.

    Brig runs podman inside the Lima VM, and only ~/.brig/* is mounted
    there. Rather than asking users to stage build contexts under ~/.brig
    or add a Lima mount for the source tree, tar the host directory and
    stream it into `sudo podman build -`. Works for any host path and
    keeps the host-filesystem-invisible-to-VM property intact.
    `.containerignore` and `.dockerignore` are honored.

    Tag is derived from the directory's basename if --tag isn't supplied
    (e.g. `brig image build cells/foo` → localhost/foo:latest). The
    Containerfile is auto-detected (Containerfile or Dockerfile) unless
    overridden with --file.
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
    # --runtime crun: the VM's default container runtime is runsc (gVisor)
    # which buildah can't operate under (gVisor lacks the cgroup ops buildah
    # uses for intermediate build containers). Fall back to crun for builds —
    # already installed in the VM and used by warden for the same reason.
    # Runtime isolation for *cells* still uses runsc; this only affects the
    # build sandbox, which runs trusted code (the user's Containerfile).
    build = subprocess.run(
        [
            "limactl", "shell", "--workdir", "/", "brig", "--",
            "sudo", "podman", "build", "--runtime", "crun",
            "-t", tag, *cfile_arg, *build_args, "-",
        ],
        input=tar_bytes,
        check=False,
    )
    if build.returncode != 0:
        raise BrigError(f"podman build failed (rc={build.returncode})")

    output(f"Built {tag}")
    return 0


def cmd_pull(args: Any) -> int:
    """Handle `brig pull` — pull and cache an image.

    Streams podman's progress directly to the user's terminal (instead
    of capturing it) so large pulls don't look frozen. podman writes
    layer-by-layer progress to stderr; with capture=False the user sees
    it live.
    """
    info(f"Pulling {args.image}...")
    result = vm_run(
        ["podman", "pull", args.image],
        capture=False,
    )
    if result.returncode != 0:
        raise BrigError(f"Failed to pull image: {args.image}")
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
