"""
Auto-generated cell names for when --name is not provided.

Format: {adjective}-{noun} — short, readable, unique enough for local use.
"""

from __future__ import annotations

import random

_ADJECTIVES = [
    "quick", "calm", "bold", "warm", "cool", "keen", "fair", "safe",
    "neat", "slim", "wise", "firm", "mild", "deep", "vast", "pure",
    "fast", "slow", "dark", "soft", "loud", "dry", "raw", "flat",
]

_NOUNS = [
    "fox", "owl", "elk", "ant", "bee", "cat", "dog", "bat",
    "ram", "jay", "cod", "eel", "yak", "hen", "koi", "ray",
    "oak", "elm", "fir", "ivy", "bay", "cay", "ore", "gem",
]


def generate_name() -> str:
    """Generate a random cell name like 'quick-fox'."""
    adj = random.choice(_ADJECTIVES)
    noun = random.choice(_NOUNS)
    # Add a short suffix to reduce collisions.
    suffix = random.randint(10, 99)
    return f"{adj}-{noun}-{suffix}"
