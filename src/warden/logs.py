"""
Log management for Warden — age + size pruning with compression.
"""

from __future__ import annotations

import gzip
import shutil
import time
from pathlib import Path

from brig.ops.logging import debug


def prune_logs(log_dir: Path, days: int = 7, size_mb: int | None = None) -> dict:
    """Prune old log files.

    Phase 1: Remove files older than `days`.
    Phase 2: Compress remaining .jsonl files to .gz.
    Phase 3: If size_mb set, remove oldest compressed files until under limit.

    Returns stats dict.
    """
    stats = {"removed": 0, "compressed": 0, "freed_bytes": 0}

    if not log_dir.exists():
        return stats

    cutoff = time.time() - (days * 86400)

    # Phase 1: Remove old files.
    for f in sorted(log_dir.iterdir()):
        if not f.is_file():
            continue
        try:
            if f.stat().st_mtime < cutoff:
                size = f.stat().st_size
                f.unlink()
                stats["removed"] += 1
                stats["freed_bytes"] += size
        except OSError as e:
            debug(f"Failed to remove {f}: {e}")

    # Phase 2: Compress .jsonl files.
    for f in sorted(log_dir.glob("*.jsonl")):
        try:
            gz_path = f.with_suffix(".jsonl.gz")
            with open(f, "rb") as src, gzip.open(gz_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            original_size = f.stat().st_size
            f.unlink()
            stats["compressed"] += 1
            stats["freed_bytes"] += original_size - gz_path.stat().st_size
        except OSError as e:
            debug(f"Failed to compress {f}: {e}")

    # Phase 3: Size-based pruning.
    if size_mb is not None:
        max_bytes = size_mb * 1024 * 1024
        total = sum(f.stat().st_size for f in log_dir.iterdir() if f.is_file())
        if total > max_bytes:
            for f in sorted(log_dir.iterdir(), key=lambda p: p.stat().st_mtime):
                if total <= max_bytes:
                    break
                if f.is_file():
                    size = f.stat().st_size
                    f.unlink()
                    total -= size
                    stats["removed"] += 1
                    stats["freed_bytes"] += size

    return stats
