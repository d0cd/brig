"""
Configuration constants for Brig.
"""

from pathlib import Path

# Container naming prefix for cells.
CONTAINER_PREFIX = "brig-"

# Default runtime (gVisor).
RUNTIME = "runsc"

# Warden proxy container name.
PROXY_NAME = "warden"

# State directory.
STATE_DIR = Path("/state")

# Per-cell policy directory.
POLICY_DIR = Path("/var/run/brig/policies")

# History log file.
HISTORY_FILE = STATE_DIR / "system" / "history.jsonl"

# Rate limiting configuration.
RATE_LIMIT_FILE = STATE_DIR / "system" / "rate_limit.json"
RATE_LIMIT_MAX = 10  # Max cells created per window.
RATE_LIMIT_WINDOW = 60  # Window in seconds.

# Cache TTL in seconds.
CACHE_TTL = 2.0

# Valid memory suffixes.
MEMORY_PATTERN = r"^\d+[kmgKMG]?[bB]?$"

# Valid domain pattern for policy.
DOMAIN_PATTERN = r"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"

# Suspicious domain patterns that could enable DNS rebinding attacks.
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*",           # Matches everything.
    "*.*",         # Matches all domains.
    "*.local",     # Local network.
    "*.internal",  # Internal domains.
    "*.localhost", # Localhost variants.
    "*.home",      # Home networks.
    "*.lan",       # LAN domains.
    "*.corp",      # Corporate internal.
    "*.private",   # Private domains.
]

# Unsafe file extensions for --sanitize mode.
UNSAFE_EXTENSIONS = {
    ".app", ".command", ".scpt", ".dmg", ".pkg", ".webloc",
    ".jar", ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
}

# Script file extensions.
SCRIPT_EXTENSIONS = {
    ".sh", ".py", ".js", ".rb", ".pl", ".php",
}
