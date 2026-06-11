"""Shared advisory file-lock context manager.

Collapses the `open(lock_file) + fcntl.flock + guaranteed-unlock` idiom that the
subnet allocator and ingress route store both use into one place, so the
boilerplate (and the explicit-unlock detail) lives once. POSIX advisory lock on
a dedicated lock file; released on context exit.
"""

from __future__ import annotations

import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO


@contextmanager
def locked_file(lock_file: Path, *, exclusive: bool = True) -> Iterator[IO[str]]:
    """Hold an advisory lock on `lock_file` for the duration of the block.

    `exclusive=True` takes `LOCK_EX` (writers); `exclusive=False` takes `LOCK_SH`
    (concurrent readers). Creates the lock file's parent dir if missing. The
    explicit `LOCK_UN` on exit is belt-and-suspenders — closing the fd releases
    the lock too — but mirrors the prior call sites' behavior exactly.
    """
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield lock
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
