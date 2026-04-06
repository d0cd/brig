"""
Container management functions for the Brig SDK package.

Note: src/brig.py (the CLI monolith) has its own copies of several functions
defined here (Spinner, cell_exists, etc.). The brig.py versions include QUIET
mode support and strip-based output parsing. Shared constants live in
brig.config to avoid duplication.
"""

import json
import re
import sys
import threading
import time

from .config import CELL_NAME_PATTERN, CONTAINER_PREFIX, POLICY_DIR, PROXY_NAME
from .utils import DEBUG, _cached, _set_cache, colorize, debug, run


class Spinner:
    """Context manager for showing a spinner during long operations."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str):
        self.message = message
        self.running = False
        self.thread = None

    def _spin(self):
        idx = 0
        while self.running:
            if sys.stderr.isatty():
                frame = self.FRAMES[idx % len(self.FRAMES)]
                sys.stderr.write(f"\r{frame} {self.message}")
                sys.stderr.flush()
                idx += 1
            time.sleep(0.1)

    def __enter__(self):
        if sys.stderr.isatty() and not DEBUG:
            self.running = True
            self.thread = threading.Thread(target=self._spin, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty() and not DEBUG:
            sys.stderr.write("\r" + " " * (len(self.message) + 3) + "\r")
            sys.stderr.flush()
        return False

    def success(self, message: str | None = None):
        """Show success message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✓', 'green')} {msg}\n")
            sys.stderr.flush()

    def fail(self, message: str | None = None):
        """Show failure message and stop spinner."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.2)
        if sys.stderr.isatty():
            msg = message or self.message
            sys.stderr.write(f"\r{colorize('✗', 'red')} {msg}\n")
            sys.stderr.flush()


def container_name(cell_name: str) -> str:
    """Get container name from cell name."""
    return f"{CONTAINER_PREFIX}{cell_name}"


def network_name(cell_name: str) -> str:
    """Get network name from cell name."""
    return f"{CONTAINER_PREFIX}{cell_name}"


def cell_exists(cell_name: str) -> bool:
    """Check if a cell container exists (running or stopped)."""
    if not CELL_NAME_PATTERN.match(cell_name):
        return False  # Invalid names can't exist.
    hit, value = _cached(f"cell_exists:{cell_name}")
    if hit:
        return bool(value)

    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={container_name(cell_name)}"],
        check=False, capture=True
    )
    exists = container_name(cell_name) in result.stdout.split()
    _set_cache(f"cell_exists:{cell_name}", exists)
    return exists


def cell_running(cell_name: str) -> bool:
    """Check if a cell container is running."""
    if not CELL_NAME_PATTERN.match(cell_name):
        return False  # Invalid names can't exist.
    hit, value = _cached(f"cell_running:{cell_name}")
    if hit:
        return bool(value)

    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={container_name(cell_name)}"],
        check=False, capture=True
    )
    running = container_name(cell_name) in result.stdout.split()
    _set_cache(f"cell_running:{cell_name}", running)
    return running


def proxy_running() -> bool:
    """Check if the proxy container is running."""
    hit, value = _cached("proxy_running")
    if hit:
        return bool(value)

    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={PROXY_NAME}"],
        check=False, capture=True
    )
    running = PROXY_NAME in result.stdout.split()
    _set_cache("proxy_running", running)
    return running


def get_proxy_ip(network: str) -> str:
    """Get proxy IP address on a specific network."""
    # Validate network name to prevent Go template injection.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', network):
        debug(f"Invalid network name: {network}")
        return ""
    result = run(
        ["podman", "inspect", PROXY_NAME, "--format",
         "{{range $k, $v := .NetworkSettings.Networks}}{{if eq $k \"" + network + "\"}}{{$v.IPAddress}}{{end}}{{end}}"],
        check=False, capture=True
    )
    return str(result.stdout.strip())


def load_cell_policy(cell_name: str) -> dict:
    """Load per-cell network policy if it exists."""
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name: {cell_name}")
    policy_file = POLICY_DIR / f"{cell_name}.json"
    if policy_file.exists():
        try:
            with open(policy_file, "r") as f:
                data: dict = json.load(f)
                return data
        except (json.JSONDecodeError, IOError):
            pass
    return {"allow": [], "deny": []}


def save_cell_policy(cell_name: str, policy: dict) -> None:
    """Save per-cell network policy using atomic write."""
    if not CELL_NAME_PATTERN.match(cell_name):
        raise ValueError(f"Invalid cell name: {cell_name}")
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    policy_file = POLICY_DIR / f"{cell_name}.json"
    tmp_file = policy_file.with_suffix(".tmp")
    with open(tmp_file, "w") as f:
        json.dump(policy, f, indent=2)
    tmp_file.rename(policy_file)  # Atomic on POSIX.


def delete_cell_policy(cell_name: str) -> None:
    """Delete per-cell network policy if it exists."""
    if not CELL_NAME_PATTERN.match(cell_name):
        debug(f"Invalid cell name for policy deletion: {cell_name}")
        return
    policy_file = POLICY_DIR / f"{cell_name}.json"
    try:
        policy_file.unlink()
    except FileNotFoundError:
        pass


def verify_image_signature(image: str) -> tuple[bool, str]:
    """Verify image signature using cosign or podman trust."""
    result = run(["which", "cosign"], check=False, capture=True)
    if result.returncode == 0:
        debug(f"Verifying image with cosign: {image}")
        result = run(
            ["cosign", "verify", "--output", "text", image],
            check=False, capture=True
        )
        if result.returncode == 0:
            return True, "Signature verified with cosign"
        else:
            if "no matching signatures" in result.stderr.lower():
                return False, "Image has no signature"
            return False, f"Signature verification failed: {result.stderr.strip()}"

    debug(f"Verifying image with podman trust: {image}")
    result = run(
        ["podman", "image", "trust", "show"],
        check=False, capture=True
    )
    if result.returncode == 0:
        if "accept" in result.stdout.lower():
            return True, "Image from trusted registry"

    return False, "No signature verification tool available (install cosign for full support)"


def apply_quarantine(path, source_cell: str | None = None) -> bool:
    """Apply macOS quarantine attribute to a file or directory."""
    import platform
    import uuid
    if platform.system() != "Darwin":
        return False

    try:
        ts = int(time.time())
        # Sanitize source_cell to prevent injection into xattr value.
        if source_cell and not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', source_cell):
            source_cell = None
        agent = f"brig:{source_cell}" if source_cell else "brig"
        qattr = f"0082;{ts:x};{agent};{uuid.uuid4()}"

        if path.is_dir():
            for f in path.rglob("*"):
                if f.is_file():
                    run(["xattr", "-w", "com.apple.quarantine", qattr, str(f)],
                        check=False, capture=True)
        else:
            run(["xattr", "-w", "com.apple.quarantine", qattr, str(path)],
                check=False, capture=True)

        debug(f"Applied quarantine to {path}")
        return True
    except Exception as e:
        debug(f"Failed to apply quarantine: {e}")
        return False
