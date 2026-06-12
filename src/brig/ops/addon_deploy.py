"""Keep the deployed warden addons in lockstep with the brig package.

Warden loads its addons from HostPaths.ADDONS_DIR (mounted into the container at
/addons). They ship with brig as package-data (`brig/warden_addons/`); the
deployed copy used to be refreshed only by a build step, so editing an addon left
warden running stale code until a manual re-copy. `brig system up` now syncs
them, so the deployed data plane can't silently drift from the installed package.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from brig.config import HostPaths
from brig.ops.logging import debug


def addon_source_dir() -> Path | None:
    """The brig-shipped addon source directory, or None if not locatable.

    Resolved as brig package-data, so it works for both editable and wheel
    installs. Returns None only if the package somehow ships without the addons
    — the sync then no-ops and warden uses whatever was previously staged.
    """
    try:
        from importlib.resources import files
        src = Path(str(files("brig").joinpath("warden_addons")))
    except (ModuleNotFoundError, TypeError, FileNotFoundError, NotADirectoryError):
        return None
    return src if src.is_dir() else None


def _digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def sync_addons() -> bool:
    """Copy changed addon `*.py` from the package into HostPaths.ADDONS_DIR.

    Returns True if any file was written — the caller (cmd_up) bounces warden
    so it reloads, since mitmproxy's script-watcher reliably hot-reloads only
    the entry scripts, not their sibling helper modules. Copy-only (never
    deletes) so an operator-placed file is left alone.
    """
    src = addon_source_dir()
    if src is None:
        debug("addon source dir not found; skipping addon sync")
        return False
    dst = HostPaths.ADDONS_DIR
    dst.mkdir(parents=True, exist_ok=True)
    changed = False
    for f in sorted(src.glob("*.py")):
        target = dst / f.name
        if not target.exists() or _digest(target) != _digest(f):
            shutil.copy2(f, target)
            changed = True
    return changed
