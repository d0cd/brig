"""
Canonical logging implementation for Brig.

This is the ONE copy of colorization, log levels, Spinner, and output helpers.
All other modules import from here. No duplicates.
"""

from __future__ import annotations

import sys
import threading
import time

# Log levels.
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3

# ANSI color codes.
COLORS = {
    "reset": "\033[0m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "gray": "\033[90m",
}

# Runtime state — set by CLI arg parsing, read by all modules.
_state = {
    "debug": False,
    "quiet": False,
    "color": sys.stdout.isatty(),
    "log_level": LOG_LEVEL_INFO,
}


def configure(
    *,
    debug: bool | None = None,
    quiet: bool | None = None,
    color: bool | None = None,
) -> None:
    """Configure logging state. Called once at CLI startup."""
    if debug is not None:
        _state["debug"] = debug
        if debug:
            _state["log_level"] = LOG_LEVEL_DEBUG
    if quiet is not None:
        _state["quiet"] = quiet
    if color is not None:
        _state["color"] = color


def is_debug() -> bool:
    """Return True if debug mode is enabled."""
    return _state["debug"]  # type: ignore[return-value]


def is_quiet() -> bool:
    """Return True if quiet mode is enabled."""
    return _state["quiet"]  # type: ignore[return-value]


def is_color() -> bool:
    """Return True if color output is enabled."""
    return _state["color"]  # type: ignore[return-value]


def colorize(text: str, color: str) -> str:
    """Apply ANSI color to text if colors are enabled."""
    if is_color() and color in COLORS:
        return f"{COLORS[color]}{text}{COLORS['reset']}"
    return text


def status_color(status: str) -> str:
    """Get colorized status string."""
    status_lower = status.lower()
    if status_lower == "running":
        return colorize(status, "green")
    elif status_lower == "paused":
        return colorize(status, "yellow")
    elif status_lower in ("exited", "stopped", "dead"):
        return colorize(status, "red")
    elif status_lower == "created":
        return colorize(status, "blue")
    else:
        return status


def log(level: int, msg: str, level_name: str | None = None) -> None:
    """Log a message at the specified level."""
    if level < _state["log_level"]:
        return
    # In quiet mode, suppress DEBUG and INFO messages.
    if _state["quiet"] and level < LOG_LEVEL_WARN:
        return
    level_names = {
        LOG_LEVEL_DEBUG: "DEBUG",
        LOG_LEVEL_INFO: "INFO",
        LOG_LEVEL_WARN: "WARN",
        LOG_LEVEL_ERROR: "ERROR",
    }
    level_colors = {
        LOG_LEVEL_DEBUG: "gray",
        LOG_LEVEL_INFO: "blue",
        LOG_LEVEL_WARN: "yellow",
        LOG_LEVEL_ERROR: "red",
    }
    name = level_name or level_names.get(level, "INFO")
    color = level_colors.get(level)
    if is_color() and color:
        prefix = colorize(f"[{name}]", color)
    else:
        prefix = f"[{name}]"
    print(f"{prefix} {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    """Print debug message if debug mode is enabled."""
    log(LOG_LEVEL_DEBUG, msg)


def info(msg: str) -> None:
    """Print info message."""
    log(LOG_LEVEL_INFO, msg)


def output(msg: str) -> None:
    """Print output message (respects quiet mode)."""
    if not _state["quiet"]:
        print(msg)


def warn(msg: str) -> None:
    """Print warning message."""
    log(LOG_LEVEL_WARN, msg)


class Spinner:
    """Context manager for showing a spinner during long operations."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str):
        self.message = message
        self.running = False
        self.thread: threading.Thread | None = None

    def _spin(self) -> None:
        idx = 0
        while self.running:
            if sys.stderr.isatty():
                frame = self.FRAMES[idx % len(self.FRAMES)]
                sys.stderr.write(f"\r{frame} {self.message}")
                sys.stderr.flush()
                idx += 1
            time.sleep(0.1)

    def __enter__(self) -> Spinner:
        if sys.stderr.isatty() and not _state["debug"] and not _state["quiet"]:
            self.running = True
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> bool:
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not _state["debug"] and not _state["quiet"]:
            sys.stderr.write("\r" + " " * (len(self.message) + 3) + "\r")
            sys.stderr.flush()
        return False

    def success(self, message: str | None = None) -> None:
        """Show success message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not _state["quiet"]:
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✓', 'green')} {msg}\n")
            sys.stderr.flush()

    def fail(self, message: str | None = None) -> None:
        """Show failure message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✗', 'red')} {msg}\n")
            sys.stderr.flush()
