"""
Rate limiting for cell creation.

check_rate_limit is a read-only gate; record_rate_limit reserves a slot.
Splitting them means a run that fails or no-ops (already running, bad image,
rolled-back reconcile) does not burn quota — only an actual creation does.
Fails closed: denies when rate limit state is unreadable.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from brig.config import RATE_LIMIT_FILE, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW
from brig.ops.atomic import atomic_write_json
from brig.ops.locking import locked_file
from brig.ops.logging import debug


def _live_timestamps(rate_limit_file: Path, now: float, window: int) -> list[float]:
    """Read in-window timestamps. Corrupt/missing state reads as empty.

    Lock-free: record_rate_limit replaces the file via atomic rename, so a
    reader always sees a complete old-or-new file, never a partial write.
    """
    if not rate_limit_file.exists():
        return []
    try:
        with open(rate_limit_file) as f:
            data = json.loads(f.read())
    except (json.JSONDecodeError, IOError):
        return []
    # Tolerate any corrupt shape (top-level non-dict, non-numeric timestamps):
    # a tampered/garbage file reads as empty rather than crashing the caller.
    if not isinstance(data, dict):
        return []
    cutoff = now - window
    return [
        ts for ts in (data.get("timestamps") or [])
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > cutoff
    ]


def check_rate_limit(
    rate_limit_file: Path = RATE_LIMIT_FILE,
    max_cells: int = RATE_LIMIT_MAX,
    window: int = RATE_LIMIT_WINDOW,
) -> bool:
    """Return True if a new cell creation is within the rate limit.

    Read-only — it does NOT reserve a slot. Call record_rate_limit() once the
    cell is actually created. Fails closed (False) if state is unreadable.

    The cap is best-effort under concurrency: because the check and the record
    are separate steps with no reservation between them, N simultaneous runs at
    max-1 can all pass and then all record, briefly overshooting the cap. This
    is an intentional trade-off — the rate limit is a soft abuse guard, not a
    hard boundary (the Lima VM is the only hard boundary).
    """
    try:
        return len(_live_timestamps(rate_limit_file, time.time(), window)) < max_cells
    except (IOError, OSError) as e:
        debug(f"Rate limit check failed: {e}")
        return False  # Fail closed on error.


def record_rate_limit(
    rate_limit_file: Path = RATE_LIMIT_FILE,
    window: int = RATE_LIMIT_WINDOW,
) -> None:
    """Record one cell creation timestamp atomically under an exclusive lock.

    Best-effort: a write failure must not fail an already-successful run — the
    rate limit is a soft abuse guard, not a hard boundary.
    """
    try:
        rate_limit_file.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        # Separate lock file so the data file can be atomically replaced.
        lock_path = rate_limit_file.with_suffix(".lock")
        with locked_file(lock_path):
            timestamps = _live_timestamps(rate_limit_file, now, window)
            timestamps.append(now)
            atomic_write_json(rate_limit_file, {"timestamps": timestamps})
    except (IOError, OSError) as e:
        debug(f"Rate limit record failed: {e}")
