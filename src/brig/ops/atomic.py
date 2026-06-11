"""
Atomic file-write helpers for host-side state.

POSIX rename within a filesystem is atomic: readers always see either the old
contents or the new contents, never a partial write. We follow the standard
pattern: tempfile in the same directory, write + flush + fsync, rename, then
fsync the parent directory so the rename itself survives a crash.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def _fsync_dir(directory: Path) -> None:
    """fsync a directory so a rename into it is durable across a crash.

    Best-effort: some platforms/filesystems reject O_RDONLY fsync on a
    directory — the rename's atomicity (torn-read protection) is unaffected
    either way; this only hardens crash durability.
    """
    try:
        dir_fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _atomic_write(path: Path, write_fn: Any, mode: Optional[int] = None) -> None:
    """Atomic-write core: temp file in the same dir, content via `write_fn(file)`,
    optional fchmod-before-rename, fsync, POSIX-atomic rename, parent fsync, and
    unlink-on-error — the skeleton both public helpers share.

    If `mode` is given, permission bits are set BEFORE the rename (fchmod on the
    open fd) so readers racing the rename see the final mode, not mkstemp's 0600;
    a failing chmod raises rather than silently falling through.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            write_fn(f)
            f.flush()
            if mode is not None:
                os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.rename(tmp_path, str(path))
        _fsync_dir(path.parent)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path,
    data: Any,
    indent: Optional[int] = 2,
    mode: Optional[int] = None,
) -> None:
    """Write JSON atomically. Creates parent dirs if missing. See `_atomic_write`
    for the `mode` semantics."""
    _atomic_write(path, lambda f: json.dump(data, f, indent=indent), mode=mode)


def atomic_write_text(path: Path, text: str) -> None:
    """Write text atomically. Creates parent dirs if missing."""
    _atomic_write(path, lambda f: f.write(text))
