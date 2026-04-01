"""Pytest configuration for brig tests."""

import sys
from pathlib import Path

# Add src/ to sys.path so tests can import the brig package.
src_dir = str(Path(__file__).parent.parent / "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
