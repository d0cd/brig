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

from brig.config import VM_NAME
from brig.ops.logging import debug

# Sensitive flags whose following argument should be redacted in logs.
_SENSITIVE_FLAGS = {"--secret", "--password", "--token", "--key", "--value"}
# Env-var names whose value should never appear in debug logs. Matches
# common credential patterns (literal or via -e KEY=VALUE / --env KEY=VALUE).
# Substring match — `MYAPP_API_KEY` still redacts because KEY is in the set.
_SENSITIVE_ENV_SUBSTRINGS = (
    "PASSWORD", "PASSWD", "TOKEN", "SECRET", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "BEARER", "AUTH", "CREDENTIAL",
)


def _redact_cmd(cmd: list[str]) -> str:
    """Redact sensitive arguments for debug logging.

    Also redacts the value of env-var assignments whose KEY contains a
    known-credential substring (PASSWORD, TOKEN, SECRET, etc.) — common
    for `podman run -e KEY=VALUE` patterns where a leak through debug
    logs is the most likely accidental disclosure path.
    """
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
        elif "=" in arg and _is_sensitive_env(arg.split("=", 1)[0]):
            # -e PASSWORD=xyz, --env API_KEY=zzz, MYAPP_BEARER=...
            redacted.append(f"{arg.split('=', 1)[0]}=***")
        else:
            redacted.append(arg)
    return " ".join(redacted)


def _is_sensitive_env(name: str) -> bool:
    """True if the env-var name plausibly holds a credential."""
    upper = name.upper()
    return any(s in upper for s in _SENSITIVE_ENV_SUBSTRINGS)


# Single source of truth for which command basenames need sudo inside
# the Lima VM. Rootful podman owns the container store; the mkdir/du/chown/cp/rm
# helpers run against root-owned paths under /state/. Anything not in this
# set runs as the unprivileged lima user.
_AUTOSUDO_COMMANDS = frozenset({"podman", "mkdir", "du", "chown", "cp", "rm"})


def _prepend_sudo(cmd: list[str], sudo: bool | None) -> list[str]:
    """Decide whether to prepend `sudo` based on caller intent.

    `sudo=None` (default) → auto: infer from cmd[0]. Use this for
    podman / standard helpers — keeps the call sites uncluttered.
    `sudo=True` → force sudo. Use when running a command whose basename
    isn't in `_AUTOSUDO_COMMANDS` but still needs root (e.g. `sh -c <script>`
    that writes to a root-owned dir, or `cat /var/log/<root-owned>`).
    `sudo=False` → never sudo. Use to defeat auto-detection for a basename
    that normally auto-sudos but in this call site shouldn't.

    Bare `["sudo", ...]` is rejected — the helper owns sudo placement so
    every call site is consistent and double-sudo can't sneak in.
    """
    if cmd and cmd[0] == "sudo":
        raise ValueError(
            "vm_run: pass sudo=True instead of prefixing the command "
            "with 'sudo' — the helper owns sudo placement."
        )
    if sudo is False:
        return cmd
    if sudo is True:
        return ["sudo"] + cmd
    # Auto.
    if cmd and cmd[0] in _AUTOSUDO_COMMANDS:
        return ["sudo"] + cmd
    return cmd


def vm_run(
    cmd: list[str],
    check: bool = False,
    capture: bool = True,
    timeout: int | None = 30,
    *,
    sudo: bool | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command inside the Lima VM.

    Wraps the command in `limactl shell <vm> --` so it executes in the VM
    where podman and gVisor are available.

    Args:
        cmd: Command and arguments (e.g. ["podman", "run", ...]).
        check: Raise CalledProcessError on non-zero exit.
        capture: Capture stdout/stderr.
        timeout: Timeout in seconds (None for no timeout).
        sudo: None=auto-detect from cmd[0], True=force, False=never.
            See `_prepend_sudo` for the auto-detect set.
    """
    cmd = _prepend_sudo(cmd, sudo)
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


def vm_run_interactive(cmd: list[str], *, sudo: bool | None = None) -> int:
    """Run an interactive command inside the VM (no capture, TTY passthrough).

    Used for: brig exec -it, brig shell, brig attach.
    Returns the exit code. See `vm_run` for the `sudo` flag semantics.
    """
    cmd = _prepend_sudo(cmd, sudo)
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
