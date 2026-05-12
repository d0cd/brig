"""
Log management for Warden — pruning, compaction, export.
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import time
from pathlib import Path

from brig.ops.logging import debug, info


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


def export_logs(
    log_dir: Path,
    cell_name: str | None = None,
    format_type: str = "jsonl",
    output_file: str | None = None,
    days: int = 7,
) -> str:
    """Export logs to the specified format.

    Returns the output file path.
    """
    cutoff = time.time() - (days * 86400)

    # Collect matching log files.
    entries: list[dict] = []
    pattern = f"{cell_name}.jsonl*" if cell_name else "*.jsonl*"
    for f in sorted(log_dir.glob(pattern)):
        try:
            if f.stat().st_mtime < cutoff:
                continue
            if f.suffix == ".gz":
                import gzip as gz
                with gz.open(f, "rt") as src:
                    for line in src:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            else:
                with open(f) as src:
                    for line in src:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError as e:
            debug(f"Failed to read {f}: {e}")

    # Write output.
    if output_file is None:
        output_file = f"brig-logs-export.{format_type}"

    if format_type == "jsonl":
        with open(output_file, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
    elif format_type == "csv":
        import csv
        if entries:
            keys = list(entries[0].keys())
            with open(output_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for entry in entries:
                    writer.writerow(entry)
    elif format_type == "json":
        with open(output_file, "w") as f:
            json.dump(entries, f, indent=2)

    return output_file
