"""VM management commands: vm create, start, stop, status, shell, delete."""

import json
import subprocess
import sys

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    VM_NAME,
    colorize,
    error_lima_config_not_found,
    error_lima_not_installed,
    error_unknown_vm_command,
    error_vm_not_created,
    error_vm_not_running,
    info,
    print_error,
    warn,
)


def _lima_installed() -> bool:
    """Check if lima is installed."""
    result = subprocess.run(["which", "limactl"], capture_output=True)
    return result.returncode == 0


def _vm_status() -> dict:
    """Get VM status. Returns dict with 'status' and 'ssh' keys."""
    if not _lima_installed():
        return {"status": "lima_not_installed", "ssh": None}

    result = subprocess.run(
        ["limactl", "list", "--format", "json"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return {"status": "error", "ssh": None}

    try:
        # Lima outputs JSON Lines (one JSON object per line).
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            vm = json.loads(line)
            if vm.get("name") == VM_NAME:
                return {
                    "status": vm.get("status", "unknown"),
                    "ssh": vm.get("sshLocalPort"),
                    "cpus": vm.get("cpus"),
                    "memory": vm.get("memory"),
                    "disk": vm.get("disk"),
                }
        return {"status": "not_created", "ssh": None}
    except json.JSONDecodeError:
        return {"status": "error", "ssh": None}


def cmd_vm_create(args) -> int:
    """Create the brig VM."""
    if not _lima_installed():
        error_lima_not_installed()

    status = _vm_status()
    if status["status"] not in ("not_created", "lima_not_installed"):
        info(f"VM '{VM_NAME}' already exists (status: {status['status']})")
        info("Use 'brig vm delete' to remove it first, or 'brig vm start' to start it.")
        return 0

    lima_yaml = _helpers.BRIG_HOME / "lima.yaml"
    if not lima_yaml.exists():
        error_lima_config_not_found()

    info(f"Creating VM '{VM_NAME}' from {lima_yaml}...")
    cmd = ["limactl", "create", "--name", VM_NAME, str(lima_yaml)]

    if getattr(args, "tty", True) and sys.stdin.isatty():
        # Interactive mode - let user see progress.
        result = subprocess.run(cmd)
    else:
        # Non-interactive.
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print_error(result.stderr.strip(), "Check lima.yaml syntax and try: brig vm status")

    if result.returncode == 0:
        info(f"VM '{VM_NAME}' created successfully.")
        info("Start it with: brig vm start")
    return result.returncode


def cmd_vm_start(args) -> int:
    """Start the brig VM."""
    if not _lima_installed():
        error_lima_not_installed()

    status = _vm_status()
    if status["status"] == "not_created":
        error_vm_not_created()

    if status["status"] == "Running":
        info(f"VM '{VM_NAME}' is already running.")
        return 0

    info(f"Starting VM '{VM_NAME}'...")
    cmd = ["limactl", "start", VM_NAME]

    if getattr(args, "tty", True) and sys.stdin.isatty():
        result = subprocess.run(cmd)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print_error(result.stderr.strip(), "Try: brig vm status")

    if result.returncode == 0:
        info(f"VM '{VM_NAME}' started successfully.")
        info("Start warden with: brig vm shell -- warden start")
    return result.returncode


def cmd_vm_stop(args) -> int:
    """Stop the brig VM."""
    if not _lima_installed():
        error_lima_not_installed()

    status = _vm_status()
    if status["status"] == "not_created":
        error_vm_not_created()

    if status["status"] != "Running":
        info(f"VM '{VM_NAME}' is not running (status: {status['status']})")
        return 0

    force = getattr(args, "force", False)
    info(f"Stopping VM '{VM_NAME}'...")

    cmd = ["limactl", "stop", VM_NAME]
    if force:
        cmd.append("--force")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        info(f"VM '{VM_NAME}' stopped.")
    else:
        print_error(result.stderr.strip(), "Try: brig vm stop --force")
    return result.returncode


def cmd_vm_status(args) -> int:
    """Show VM status."""
    if not _lima_installed():
        warn("Lima is not installed.")
        info("Install with: brew install lima")
        return 1

    status = _vm_status()

    if getattr(args, "json", False):
        print(json.dumps(status, indent=2))
        return 0

    if status["status"] == "not_created":
        info(f"VM '{VM_NAME}' is not created.")
        info("Create it with: brig vm create")
        return 0

    # Colorize status.
    status_str = status["status"]
    if status_str == "Running":
        status_str = colorize(status_str, "green")
    elif status_str == "Stopped":
        status_str = colorize(status_str, "yellow")
    else:
        status_str = colorize(status_str, "red")

    print(f"VM:     {VM_NAME}")
    print(f"Status: {status_str}")
    if status.get("cpus"):
        print(f"CPUs:   {status['cpus']}")
    if status.get("memory"):
        mem_gb = status["memory"] / (1024 ** 3)
        print(f"Memory: {mem_gb:.1f} GB")
    if status.get("disk"):
        disk_gb = status["disk"] / (1024 ** 3)
        print(f"Disk:   {disk_gb:.1f} GB")
    if status.get("ssh"):
        print(f"SSH:    localhost:{status['ssh']}")

    return 0


def cmd_vm_shell(args) -> int:
    """Open a shell in the VM or run a command."""
    if not _lima_installed():
        error_lima_not_installed()

    status = _vm_status()
    if status["status"] != "Running":
        error_vm_not_running()

    cmd = ["limactl", "shell", VM_NAME]

    # If command provided, run it.
    shell_cmd = getattr(args, "shell_cmd", None)
    if shell_cmd:
        cmd.append("--")
        cmd.extend(shell_cmd)

    # Run interactively.
    result = subprocess.run(cmd)
    return result.returncode


def cmd_vm_delete(args) -> int:
    """Delete the brig VM."""
    if not _lima_installed():
        error_lima_not_installed()

    status = _vm_status()
    if status["status"] == "not_created":
        info(f"VM '{VM_NAME}' does not exist.")
        return 0

    force = getattr(args, "force", False)

    # Require confirmation unless force.
    if not force:
        warn(f"This will delete VM '{VM_NAME}' and all data inside it.")
        try:
            response = input("Are you sure? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Aborted.")
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 1

    # Stop if running.
    if status["status"] == "Running":
        info("Stopping VM...")
        subprocess.run(["limactl", "stop", VM_NAME], capture_output=True)

    info(f"Deleting VM '{VM_NAME}'...")
    result = subprocess.run(["limactl", "delete", VM_NAME], capture_output=True, text=True)

    if result.returncode == 0:
        info(f"VM '{VM_NAME}' deleted.")
    else:
        print_error(result.stderr.strip(), "Try: brig vm delete --force")
    return result.returncode


def cmd_vm(args) -> int:
    """VM management dispatcher."""
    vm_commands = {
        "create": cmd_vm_create,
        "start": cmd_vm_start,
        "stop": cmd_vm_stop,
        "status": cmd_vm_status,
        "shell": cmd_vm_shell,
        "delete": cmd_vm_delete,
    }

    vm_cmd = getattr(args, "vm_command", None)
    if not vm_cmd or vm_cmd not in vm_commands:
        error_unknown_vm_command(vm_cmd or "none")

    return vm_commands[vm_cmd](args)
