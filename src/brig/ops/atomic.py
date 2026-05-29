"""
Atomic file-write helpers for host-side state.

POSIX rename within a filesystem is atomic: readers always see either the old
contents or the new contents, never a partial write. We follow the standard
pattern: tempfile in the same directory, write + flush + fsync, then rename.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def atomic_write_json(
    path: Path,
    data: Any,
    indent: Optional[int] = 2,
    mode: Optional[int] = None,
) -> None:
    """Write JSON atomically. Creates parent dirs if missing.

    If `mode` is given, the file's permission bits are set BEFORE the
    rename (via fchmod on the open fd). This ensures readers that race
    with the rename see the final mode, not the mkstemp default of 0600.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            if mode is not None:
                # fchmod on the fd before fsync+rename — if chmod fails,
                # raise (no silent fallthrough to 0600).
                os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.rename(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str) -> None:
    """Write text atomically. Creates parent dirs if missing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
