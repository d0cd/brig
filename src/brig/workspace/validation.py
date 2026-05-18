"""Workspace path validation — race-free file access for host-side
consumers of cell workspaces.

When a host-side process (e.g. an agent invoked via aitelier on behalf of
a cell) reads files under a cell's workspace, a cell that drops a symlink
into its workspace can trick the consumer into reading host files the
cell itself cannot reach:

    cell$  ln -s /Users/d0c/.ssh/id_rsa /work/innocuous.txt
    # → host reads /work/innocuous.txt → kernel follows symlink → leaks key.

The cell can't read the key directly (gVisor blocks it), but the host
follows the symlink and returns it. Cell just exfiltrated a secret it
could never reach.

# Design — race-free from first principles

The module exposes only file-descriptor-based primitives. There is no
path-returning helper because the path-returning shape is TOCTOU-unsafe:
between validation and the consumer's `open()`, the cell can swap the
inode for a symlink to a host secret. By that point the consumer is the
one calling `open()` on a string the kernel will resolve fresh.

The primary API is `safe_open(cell, relpath, mode)`:
  1. Opens the workspace root as a dirfd with `O_NOFOLLOW | O_DIRECTORY`
     — refuses if the root itself is a symlink.
  2. Walks each intermediate component with `openat(parent, name,
     O_NOFOLLOW | O_DIRECTORY)`.
  3. Opens the final component with `openat(parent, name, O_NOFOLLOW)`.
  4. Returns the opened file as a context manager. The caller never
     touches a path string; there is no window for the cell to swap the
     inode after validation.

Any symlink at any path component raises `WorkspaceEscape`. `..` and
absolute-path-outside-workspace and null bytes are rejected before the
walk even starts.

For consumers that need to do their own openat walk (e.g. listing the
workspace), `safe_dirfd(cell)` returns the workspace dirfd. The caller
owns the fd and must close it.
"""

from __future__ import annotations

import errno
import os
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Iterator

from brig.config import HostPaths


class WorkspaceEscape(Exception):
    """Raised when a request would leave the cell's workspace, OR when
    any path component is a symlink. Always adversarial — refuse the
    operation when you catch it."""


def workspace_root(cell_name: str) -> Path:
    """Absolute host path of a cell's workspace root.

    Does NOT call `.resolve()` — that would follow a symlink at the root,
    which we don't want. The actual `os.open` with `O_NOFOLLOW` catches
    root-symlink attempts.

    Does NOT verify the cell exists or that the workspace directory exists.
    """
    return (HostPaths.STATE_DIR / cell_name / "workspace").expanduser()


def _validate_relpath(relpath: str | Path, root: Path) -> list[str]:
    """Split `relpath` into safe path components relative to `root`.

    Raises `WorkspaceEscape` on `..`, empty path, null bytes, or absolute
    paths that don't sit under `root`.
    """
    s = str(relpath) if isinstance(relpath, Path) else relpath

    if not s or s in (".", "./"):
        raise WorkspaceEscape("empty path is not a valid workspace target")
    if "\0" in s:
        raise WorkspaceEscape("null byte in workspace path")

    path = Path(s)
    if path.is_absolute():
        # Accept absolute paths that the consumer derived from cell.json,
        # but only if they actually sit under the workspace root. Use
        # purely-lexical containment — calling .resolve() here would
        # follow symlinks, defeating the purpose.
        try:
            path = path.relative_to(root)
        except ValueError as e:
            raise WorkspaceEscape(
                f"absolute path {s!r} is outside workspace root {root}"
            ) from e

    parts: list[str] = []
    for part in path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise WorkspaceEscape(f"'..' in path: {s!r}")
        if "/" in part or "\\" in part:
            raise WorkspaceEscape(f"invalid path component {part!r} in {s!r}")
        parts.append(part)

    if not parts:
        raise WorkspaceEscape("empty path is not a valid workspace target")
    return parts


def safe_dirfd(cell_name: str) -> int:
    """Open the cell's workspace root as a directory fd, refusing to
    follow a symlink at the root.

    The caller owns the returned fd and is responsible for closing it
    (or using it as `dir_fd=` in `os.open(..., dir_fd=fd)` chains).

    Raises:
        WorkspaceEscape — workspace dir missing or is itself a symlink.
        OSError         — other filesystem errors.
    """
    root = workspace_root(cell_name)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
    try:
        return os.open(str(root), flags)
    except FileNotFoundError as e:
        raise WorkspaceEscape(
            f"workspace for cell {cell_name!r} does not exist at {root}"
        ) from e
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise WorkspaceEscape(
                f"workspace root {root} is a symlink — refusing"
            ) from e
        raise


def _open_safe_fd(cell_name: str, relpath: str | Path, write: bool) -> int:
    """Walk the path under the workspace root with O_NOFOLLOW at every
    component. Returns an os-level file descriptor."""
    root = workspace_root(cell_name)
    parts = _validate_relpath(relpath, root)
    nofollow_dir = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY

    dirfd = safe_dirfd(cell_name)
    try:
        # Walk intermediate components.
        for part in parts[:-1]:
            try:
                new_dirfd = os.open(part, nofollow_dir, dir_fd=dirfd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise WorkspaceEscape(
                        f"symlink at intermediate component {part!r} "
                        f"in workspace path {relpath!r}"
                    ) from e
                raise
            os.close(dirfd)
            dirfd = new_dirfd

        # Final component — O_NOFOLLOW refuses if it's a symlink.
        # Only ELOOP indicates a symlink here (the parent was already
        # verified as a directory via O_DIRECTORY); other errnos pass through.
        flags = (os.O_WRONLY | os.O_CREAT) if write else os.O_RDONLY
        try:
            fd = os.open(parts[-1], flags | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise WorkspaceEscape(
                    f"final component {parts[-1]!r} is a symlink "
                    f"(workspace path {relpath!r})"
                ) from e
            raise
        return fd
    finally:
        os.close(dirfd)


@contextmanager
def safe_open(
    cell_name: str,
    relpath: str | Path,
    mode: str = "r",
) -> Iterator[IO]:
    """Open a file inside `cell_name`'s workspace race-free.

    Examples:
        with safe_open("hermes", "input.json", "r") as f:
            data = json.load(f)

        with safe_open("hermes", "result.bin", "wb") as f:
            f.write(payload)

    Each path component is opened with `O_NOFOLLOW`. A cell that swaps a
    file for a symlink AFTER the open returns cannot affect the resulting
    fd — by then it's a stable inode reference.

    Raises:
        WorkspaceEscape — `..`, null byte, absolute outside workspace, or
                          any symlink at any component.
        FileNotFoundError — file (or parent dir) doesn't exist.
        PermissionError   — usual filesystem perms.
    """
    write = "w" in mode or "a" in mode or "x" in mode
    fd = _open_safe_fd(cell_name, relpath, write=write)
    with os.fdopen(fd, mode) as f:
        yield f
