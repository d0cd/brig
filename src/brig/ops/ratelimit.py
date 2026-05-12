"""
Rate limiting for cell creation.

Uses file locking to prevent TOCTOU races between concurrent brig invocations.
Fails closed: denies operation when rate limit state is unreadable.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from brig.config import RATE_LIMIT_FILE, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW
from brig.ops.logging import debug


def check_rate_limit(
    rate_limit_file: Path = RATE_LIMIT_FILE,
    max_cells: int = RATE_LIMIT_MAX,
    window: int = RATE_LIMIT_WINDOW,
) -> bool:
    """Check if cell creation is rate limited. Returns True if allowed.

    Args:
        rate_limit_file: Path to rate limit state file.
        max_cells: Maximum cells created per window.
        window: Window in seconds.
    """
    try:
        rate_limit_file.parent.mkdir(parents=True, exist_ok=True)

        now = time.time()

        # Use separate lock file so the data file can be atomically replaced.
        lock_path = rate_limit_file.with_suffix(".lock")
        with open(lock_path, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)

            # Read current data.
            timestamps: list[float] = []
            if rate_limit_file.exists():
                try:
                    with open(rate_limit_file) as f:
                        data = json.loads(f.read())
                        timestamps = data.get("timestamps", [])
                except (json.JSONDecodeError, IOError):
                    timestamps = []

            # Filter to only timestamps within the window.
            cutoff = now - window
            timestamps = [ts for ts in timestamps if ts > cutoff]

            # Check if limit exceeded.
            if len(timestamps) >= max_cells:
                return False

            # Add current timestamp and save atomically.
            timestamps.append(now)
            tmp_path = rate_limit_file.with_suffix(".tmp")
            with open(tmp_path, "w") as tmp:
                json.dump({"timestamps": timestamps}, tmp)
                tmp.flush()
                os.fsync(tmp.fileno())
            tmp_path.rename(rate_limit_file)

        return True
    except (IOError, OSError) as e:
        debug(f"Rate limit check failed: {e}")
        return False  # Fail closed on error.
