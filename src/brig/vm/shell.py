"""
VM command execution layer.

All podman commands run inside the Lima VM. This module wraps them in
`limactl shell brig -- <command>` so the CLI (which runs on macOS)
can talk to the containerized environment.

Every module that needs to run podman should call vm_run() instead of
subprocess.run() directly.
"""

from __future__ import annotations

import subprocess
from typing import Any

from brig.config import VM_NAME
from brig.ops.logging import debug

# Sensitive flags whose following argument should be redacted in logs.
_SENSITIVE_FLAGS = {"--secret", "--password", "--token", "--key", "--value"}


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments for debug logging."""
    redacted: list[str] = []
    skip_next = False
    for arg in cmd:
        if skip_next:
            redacted.append("***")
            skip_next = False
        elif arg in _SENSITIVE_FLAGS:
            redacted.append(arg)
            skip_next = True
        elif "=" in arg and arg.split("=", 1)[0] in _SENSITIVE_FLAGS:
            redacted.append(f"{arg.split('=', 1)[0]}=***")
        else:
            redacted.append(arg)
    return " ".join(redacted)


def vm_run(
    cmd: list[str],
    check: bool = False,
    capture: bool = True,
    timeout: int | None = 30,
) -> subprocess.CompletedProcess[str]:
    """Run a command inside the Lima VM.

    Wraps the command in `limactl shell <vm> --` so it executes in the VM
    where podman and gVisor are available.

    Args:
        cmd: Command and arguments (e.g. ["podman", "run", ...]).
        check: Raise CalledProcessError on non-zero exit.
        capture: Capture stdout/stderr.
        timeout: Timeout in seconds (None for no timeout).
    """
    # Rootful podman and system commands inside Lima need sudo.
    if cmd and cmd[0] in ("podman", "mkdir", "du"):
        cmd = ["sudo"] + cmd

    full_cmd = ["limactl", "shell", "--workdir", "/", VM_NAME, "--"] + cmd
    debug(f"VM exec: {_redact_cmd(cmd)}")
    try:
        return subprocess.run(
            full_cmd, check=check, capture_output=capture, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(full_cmd, 1, "", "timeout")
    except OSError as e:
        return subprocess.CompletedProcess(full_cmd, 1, "", str(e))


def vm_run_interactive(cmd: list[str]) -> int:
    """Run an interactive command inside the VM (no capture, TTY passthrough).

    Used for: brig exec -it, brig shell, brig attach.
    Returns the exit code.
    """
    if cmd and cmd[0] in ("podman", "mkdir", "du"):
        cmd = ["sudo"] + cmd
    full_cmd = ["limactl", "shell", "--workdir", "/", VM_NAME, "--"] + cmd
    debug(f"VM interactive: {_redact_cmd(cmd)}")
    try:
        return subprocess.run(full_cmd).returncode
    except OSError:
        return 1


def vm_exists() -> bool:
    """Check if the Lima VM exists."""
    result = subprocess.run(
        ["limactl", "list", "--format", "{{.Name}}"],
        check=False, capture_output=True, text=True,
    )
    return VM_NAME in result.stdout.strip().split("\n")


def vm_running() -> bool:
    """Check if the Lima VM is running."""
    result = subprocess.run(
        ["limactl", "list", "--format", "{{.Name}} {{.Status}}"],
        check=False, capture_output=True, text=True,
    )
    for line in result.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == VM_NAME and parts[1] == "Running":
            return True
    return False
