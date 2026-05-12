"""
Simple TTL cache for expensive operations (cell existence, proxy status).
"""

from __future__ import annotations

import time
from typing import Any

from brig.config import CACHE_TTL

# Cache storage: key -> (timestamp, value).
_cache: dict[str, tuple[float, Any]] = {}


def cached(key: str, ttl: float = CACHE_TTL) -> tuple[bool, Any]:
    """Check if a cached value is still valid.

    Returns (hit, value). If hit is False, value is None.
    """
    if key in _cache:
        ts, value = _cache[key]
        if time.time() - ts < ttl:
            return True, value
    return False, None


def set_cache(key: str, value: Any) -> None:
    """Store a value in the cache."""
    _cache[key] = (time.time(), value)


def invalidate_cell_cache(cell_name: str) -> None:
    """Invalidate cache for a specific cell after state changes."""
    _cache.pop(f"cell_exists:{cell_name}", None)
    _cache.pop(f"cell_running:{cell_name}", None)


def clear() -> None:
    """Clear the entire cache. Useful in tests."""
    _cache.clear()
