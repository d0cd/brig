#!/usr/bin/env python3
"""
Brig - Secure workload harness for running untrusted code.

Each cell runs in an isolated network with gVisor sandboxing.
All egress traffic goes through the Warden policy-enforcing proxy.

Usage:
    brig [--debug] <command> [options]

Commands:
    brig run [options] <image> [command...]   Run a new cell
    brig stop <name>                          Gracefully stop a cell
    brig kill <name>                          Immediately kill a cell
    brig wait <name>                          Block until cell exits
    brig rm [-f] <name>                       Remove a cell
    brig start <name>                         Start a stopped cell
    brig pause <name>                         Pause a running cell
    brig unpause <name>                       Unpause a paused cell
    brig list [--format=table|json]           List all cells
    brig logs [-f] [--tail N] <name>          View cell logs
    brig exec <name> [command...]             Execute command in cell
    brig shell <name>                         Open interactive shell
    brig rename <old> <new>                   Rename a cell
    brig attach <name>                        Attach to cell console
    brig inspect <name>                       Show cell details
    brig export <name>                        Export cell as YAML
    brig stats [name]                         Show resource usage
    brig top <name>                           Show processes in cell
    brig diff <name>                          Show filesystem changes
    brig files <name> [path]                  List workspace contents
    brig cat <name> <path>                    View file in workspace
    brig cp <src> <dst>                       Copy files to/from workspace
    brig network <name>                       View network activity
    brig events [name]                        Stream lifecycle events
    brig pull <image>                         Pull and cache image
    brig warmup [--profile <name>]            Pre-pull images for profile
    brig checkpoint <name>                    Checkpoint running cell
    brig restore <checkpoint>                 Restore from checkpoint
    brig diagnose <name>                      Run diagnostic checks
    brig health [--format=table|json]         Check system health
    brig metrics                              Output Prometheus metrics
    brig verify                               Verify security invariants
    brig history [--tail N] [--cell <name>]   Show operation history
    brig tui [--view=dashboard|logs|...]      Interactive terminal UI
    brig upgrade [--dry-run] [--no-backup]    Upgrade state to current schema
    brig config show [key]                    Show configuration
    brig config set <key> <value>             Set configuration value
    brig policy show <name>                   Show cell's policy
    brig policy set <name> [--allow/--deny]   Update cell's policy

Security:
    - Cells run with gVisor (runsc) for syscall isolation.
    - Each cell gets an isolated internal network.
    - Warden proxy enforces domain allowlist on egress.
    - Secrets mounted as files, never in env vars.
"""

import argparse
import signal
import sys

# Re-export all helpers, constants, and command functions for backward
# compatibility.  Tests import brig.py via importlib and access names
# like brig.validate_cell_definition, brig._cache, brig.POLICY_DIR, etc.
from brig.commands import *  # noqa: F401,F403

# These are accessed as brig.SCRIPT_EXTENSIONS, brig.UNSAFE_EXTENSIONS
# by tests, and live in brig.config.
from brig.config import SCRIPT_EXTENSIONS, UNSAFE_EXTENSIONS  # noqa: F401

# OFFICE_EXTENSIONS lives in workspace module but tests access it via brig.
from brig.commands.workspace import OFFICE_EXTENSIONS  # noqa: F401

# Import _helpers and command modules for mutable global forwarding
# and underscore-name proxy.
import brig.commands._helpers as _helpers
import brig.commands.lifecycle as _lifecycle
import brig.commands.policy as _policy
import brig.commands.system as _system
import brig.commands.vm as _vm
import brig.commands.workspace as _workspace
import brig.commands.inspect as _inspect_mod
import brig.commands.network as _network
import brig.commands.config_cmd as _config_cmd
import brig.commands.image as _image
import brig.commands.tui_cmd as _tui_cmd
import brig.commands.dashboard_cmd as _dashboard_cmd

# Command modules to search for underscore-prefixed names.
_COMMAND_MODULES = (
    _helpers, _lifecycle, _policy, _system, _vm,
    _workspace, _inspect_mod, _network, _config_cmd, _image, _tui_cmd, _dashboard_cmd,
)

# Mutable globals live in _helpers.py.  Functions in _helpers read them
# from their own module namespace.  For backward compatibility with tests
# that do `brig.COLOR_ENABLED = True` (via importlib), we need writes
# to propagate to _helpers.  We change this module's __class__ to a
# subclass that forwards writes of mutable globals to _helpers.
import gc as _gc
import types as _types


class _BrigModule(_types.ModuleType):
    """Module subclass that forwards attribute writes to command modules.

    This ensures that @patch.object(brig, 'run') propagates to all
    command modules that imported 'run' from _helpers, and that mutable
    global writes (brig.COLOR_ENABLED = True) reach _helpers.
    """

    # Track original values in command modules so delattr can restore them.
    _originals = {}  # (name, mod_id) -> original_value

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        # Forward to every command module that has this name.
        for mod in _COMMAND_MODULES:
            if name in mod.__dict__:
                key = (name, id(mod))
                if key not in self._originals:
                    self._originals[key] = mod.__dict__[name]
                setattr(mod, name, value)

    def __delattr__(self, name):
        super().__delattr__(name)
        # Restore originals in command modules.
        for mod in _COMMAND_MODULES:
            key = (name, id(mod))
            if key in self._originals:
                setattr(mod, name, self._originals.pop(key))

    def __getattr__(self, name):
        # Proxy names not found on this module to command modules.
        for mod in _COMMAND_MODULES:
            try:
                return getattr(mod, name)
            except AttributeError:
                continue
        raise AttributeError(f"module has no attribute {name!r}")


# Find our own module object (works even via importlib.util loading)
# and change its class to enable mutable global forwarding.
for _referrer in _gc.get_referrers(globals()):
    if isinstance(_referrer, _types.ModuleType) and _referrer.__dict__ is globals():
        _referrer.__class__ = _BrigModule
        break


def main():
    # Install signal handlers for graceful shutdown.
    def signal_handler(signum, frame):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        # Re-raise as KeyboardInterrupt for consistent handling.
        if signum == signal.SIGINT:
            raise KeyboardInterrupt()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        description="Brig - Secure workload harness for cells",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"brig {VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize brig directory structure")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config files")

    # upgrade
    p_upgrade = subparsers.add_parser("upgrade", help="Upgrade brig state to current schema version")
    p_upgrade.add_argument("--dry-run", action="store_true", help="Show pending migrations without applying")
    p_upgrade.add_argument("--no-backup", action="store_true", help="Skip backup before upgrading")

    # vm
    p_vm = subparsers.add_parser("vm", help="Manage the brig Lima VM")
    vm_sub = p_vm.add_subparsers(dest="vm_command", required=True)

    vm_sub.add_parser("create", help="Create the brig VM")

    vm_sub.add_parser("start", help="Start the brig VM")

    p_vm_stop = vm_sub.add_parser("stop", help="Stop the brig VM")
    p_vm_stop.add_argument("-f", "--force", action="store_true", help="Force stop")

    p_vm_status = vm_sub.add_parser("status", help="Show VM status")
    p_vm_status.add_argument("--json", action="store_true", help="Output as JSON")

    p_vm_shell = vm_sub.add_parser("shell", help="Open shell in VM or run command")
    p_vm_shell.add_argument("shell_cmd", nargs="*", help="Command to run (omit for interactive shell)")

    p_vm_delete = vm_sub.add_parser("delete", help="Delete the brig VM")
    p_vm_delete.add_argument("-f", "--force", action="store_true", help="Skip confirmation")

    # run
    p_run = subparsers.add_parser(
        "run",
        help="Run a new cell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Basic:                 brig run --name mycell alpine
  With command:          brig run --name mycell python:3.12 -- python script.py
  Detached:              brig run -d --name mycell alpine -- sleep 3600
  From definition:       brig run -f cell.yaml
  With policy:           brig run --name mycell --policy-allow api.github.com alpine
  With timeout:          brig run --name mycell --timeout 30m alpine
  With secrets:          brig run --name mycell --secret api-key alpine
"""
    )
    p_run.add_argument("--name", "-n", help="Cell name (required unless in definition file)")
    p_run.add_argument("-f", "--file", help="Cell definition file (YAML or JSON)")
    p_run.add_argument("-d", "--detach", action="store_true", help="Run in background")
    p_run.add_argument("--rm", action="store_true", help="Remove container when it exits")
    p_run.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    p_run.add_argument("-e", "--env", action="append", help="Set environment variable")
    p_run.add_argument("--secret", action="append", help="Mount secret file at /run/secrets/")
    p_run.add_argument("--memory", default=None, help="Memory limit (e.g., 512m, 2g; default: 2g)")
    p_run.add_argument("--cpus", default=None, help="CPU limit (e.g., 1, 2; default: 2)")
    p_run.add_argument("--pids-limit", type=int, default=None, help="PID limit (e.g., 256, 512; default: 512)")
    p_run.add_argument("--policy-allow", action="append", help="Allow domain (adds to global policy)")
    p_run.add_argument("--policy-deny", action="append", help="Deny domain (overrides global policy)")
    p_run.add_argument("--verify-image", action="store_true", help="Verify image signature before running")
    p_run.add_argument("--verify-key", help="Path to cosign public key for image verification")
    p_run.add_argument("--verify-keyless", action="store_true",
                        help="Use Fulcio/Rekor keyless verification")
    p_run.add_argument("--certificate-identity",
                        help="Expected certificate identity for keyless verification (email/URI)")
    p_run.add_argument("--certificate-oidc-issuer",
                        help="Expected OIDC issuer URL for keyless verification")
    p_run.add_argument("--seccomp-profile", help="Apply seccomp profile (path to JSON file)")
    p_run.add_argument("--no-seccomp", action="store_true",
                        help="Disable default seccomp profile")
    p_run.add_argument("--workspace-quota",
                        help="Workspace size limit (e.g., 500m, 2g)")
    p_run.add_argument("--timeout", help="Kill cell after duration (e.g., 30m, 2h, 1d)")
    p_run.add_argument("--output", choices=["text", "json"], default="text",
                         help="Output format")
    p_run.add_argument("--network", choices=["default", "none"], default=None,
                         help="Network mode (none for air-gapped cells)")
    p_run.add_argument("--profile", help="Trust profile to apply (e.g., untrusted, supervised, dev)")
    p_run.add_argument("--label", action="append", help="Add label (key=value)")
    p_run.add_argument("--workdir", help="Working directory inside the cell")
    p_run.add_argument("--image-digest", help="Expected OCI image digest (e.g., sha256:abc123...)")
    p_run.add_argument("--tor", action="store_true",
                        help="Route cell through Tor (requires: warden tor start && warden restart)")
    p_run.add_argument("--canary-file", help=argparse.SUPPRESS)
    p_run.add_argument("image", nargs="?", help="Container image")
    p_run.add_argument("container_cmd", nargs="*", help="Command to run")

    # stop
    p_stop = subparsers.add_parser("stop", help="Gracefully stop a cell")
    p_stop.add_argument("name", help="Cell name")

    # kill
    p_kill = subparsers.add_parser("kill", help="Immediately kill a cell")
    p_kill.add_argument("name", help="Cell name")

    # wait
    p_wait = subparsers.add_parser("wait", help="Block until a cell exits")
    p_wait.add_argument("--timeout", help="Maximum time to wait (e.g., 30s, 5m, 2h)")
    p_wait.add_argument("--output", choices=["text", "json"], default="text",
                         help="Output format")
    p_wait.add_argument("name", help="Cell name")

    # rm
    p_rm = subparsers.add_parser("rm", help="Remove a cell")
    p_rm.add_argument("-f", "--force", action="store_true", help="Force remove running cell")
    p_rm.add_argument("--purge", action="store_true", help="Also remove workspace")
    p_rm.add_argument("name", help="Cell name")

    # start
    p_start = subparsers.add_parser("start", help="Start a stopped cell")
    p_start.add_argument("name", help="Cell name")

    # list
    p_list = subparsers.add_parser(
        "list",
        help="List all cells",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Table view:            brig list
  JSON output:           brig list --format json
"""
    )
    p_list.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # logs
    p_logs = subparsers.add_parser(
        "logs",
        help="View cell logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  View all logs:         brig logs mycell
  Follow live:           brig logs -f mycell
  Tail last 50 lines:   brig logs --tail 50 mycell
"""
    )
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_logs.add_argument("--tail", type=int, help="Number of lines to show")
    p_logs.add_argument("name", help="Cell name")

    # exec
    p_exec = subparsers.add_parser(
        "exec",
        help="Execute command in cell",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Run a command:           brig exec mycell ls -la
  Interactive shell:       brig exec -it mycell /bin/sh
  Run Python script:       brig exec mycell python3 script.py
  Check environment:       brig exec mycell env | grep PROXY

Use -it for interactive commands that need a terminal.
"""
    )
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p_exec.add_argument("-t", "--tty", action="store_true", help="Allocate pseudo-TTY")
    p_exec.add_argument("name", help="Cell name")
    p_exec.add_argument("exec_cmd", nargs="*", help="Command to execute")

    # shell (convenience wrapper for exec -it /bin/sh)
    p_shell = subparsers.add_parser("shell", help="Open interactive shell in cell")
    p_shell.add_argument("name", help="Cell name")
    p_shell.add_argument("--sh", default="/bin/sh", dest="shell_cmd",
                         help="Shell to use (default: /bin/sh)")

    # rename
    p_rename = subparsers.add_parser("rename", help="Rename a cell")
    p_rename.add_argument("old_name", help="Current cell name")
    p_rename.add_argument("new_name", help="New cell name")

    # attach
    p_attach = subparsers.add_parser("attach", help="Attach to cell's console")
    p_attach.add_argument("name", help="Cell name")

    # top
    p_top = subparsers.add_parser("top", help="Show processes in cell")
    p_top.add_argument("name", help="Cell name")

    # diff
    p_diff = subparsers.add_parser("diff", help="Show filesystem changes from base image")
    p_diff.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    p_diff.add_argument("name", help="Cell name")

    # stats
    p_stats = subparsers.add_parser("stats", help="Show cell resource usage")
    p_stats.add_argument("--no-stream", action="store_true", help="Disable live updates")
    p_stats.add_argument("--output", choices=["text", "json"], default="text",
                          help="Output format")
    p_stats.add_argument("name", nargs="?", help="Cell name (all cells if omitted)")

    # pause
    p_pause = subparsers.add_parser("pause", help="Pause a running cell")
    p_pause.add_argument("name", help="Cell name")

    # unpause
    p_unpause = subparsers.add_parser("unpause", help="Unpause a paused cell")
    p_unpause.add_argument("name", help="Cell name")

    # files
    p_files = subparsers.add_parser("files", help="List workspace contents")
    p_files.add_argument("name", help="Cell name")
    p_files.add_argument("path", nargs="?", default="", help="Path within workspace")

    # cat
    p_cat = subparsers.add_parser("cat", help="View file in workspace")
    p_cat.add_argument("--lines", "-n", type=int, help="Show only first N lines")
    p_cat.add_argument("--max-size", type=int, default=1, help="Max file size in MB (default: %(default)s)")
    p_cat.add_argument("--force", action="store_true", help="Show binary files")
    p_cat.add_argument("name", help="Cell name")
    p_cat.add_argument("path", help="Path to file within workspace")

    # cp
    p_cp = subparsers.add_parser(
        "cp",
        help="Copy files to/from workspace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Copy local file to cell:     brig cp ./data.csv mycell:/input/
  Copy from cell to local:     brig cp mycell:/output/result.json ./
  Copy with sanitization:      brig cp --sanitize untrusted.zip mycell:/

Paths use cell:path syntax where 'cell' is the cell name and 'path'
is relative to the workspace (/work inside the cell).
"""
    )
    p_cp.add_argument("--sanitize", action="store_true",
                      help="Block unsafe file types (.exe, .bat, .msi, .app, .dmg, etc.), scripts, and office macros")
    p_cp.add_argument("--allow-scripts", action="store_true",
                      help="Allow script files (.sh, .py, .js, etc.) in sanitize mode")
    p_cp.add_argument("--allow-office", action="store_true",
                      help="Allow office files (.docx, .xlsx, etc.) in sanitize mode")
    p_cp.add_argument("src", help="Source path (cell:path or local path)")
    p_cp.add_argument("dst", help="Destination path (cell:path or local path)")

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Show cell details")
    p_inspect.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_inspect.add_argument("name", help="Cell name")

    # export
    p_export = subparsers.add_parser("export", help="Export cell as YAML definition")
    p_export.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")
    p_export.add_argument("name", help="Cell name")

    # network
    p_network = subparsers.add_parser(
        "network",
        help="View cell network activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Recent activity:       brig network mycell
  Follow live:           brig network -f mycell
  Blocked requests only: brig network --blocked mycell
  JSON output:           brig network --json mycell
  Tail last 50 entries:  brig network --tail 50 mycell
"""
    )
    p_network.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_network.add_argument("--blocked", action="store_true", help="Show only blocked requests")
    p_network.add_argument("--json", action="store_true", help="Output raw JSONL")
    p_network.add_argument("--tail", type=int, default=20, help="Number of lines to show (default: %(default)s)")
    p_network.add_argument("name", help="Cell name")

    # events
    p_events = subparsers.add_parser("events", help="Stream cell lifecycle events")
    p_events.add_argument("--output", choices=["text", "json"], default="json",
                           help="Output format (default: json)")
    p_events.add_argument("--since", help="Show events since timestamp (e.g., 2024-01-01T00:00:00)")
    p_events.add_argument("name", nargs="?", help="Cell name (all cells if omitted)")

    # pull
    p_pull = subparsers.add_parser("pull", help="Pull and cache a container image")
    p_pull.add_argument("image", help="Container image to pull")

    # warmup
    p_warmup = subparsers.add_parser("warmup", help="Pre-pull images for a profile")
    p_warmup.add_argument("--profile", help="Pull images commonly used with this profile")
    p_warmup.add_argument("images", nargs="*", help="Additional images to pull")

    # image-verify
    p_verify_image = subparsers.add_parser("image-verify", help="Verify container image signature")
    p_verify_image.add_argument("image", help="Container image to verify")
    p_verify_image.add_argument("--key", help="Path to cosign public key")
    p_verify_image.add_argument("--keyless", action="store_true",
                                 help="Use Fulcio/Rekor keyless verification")
    p_verify_image.add_argument("--certificate-identity",
                                 help="Expected certificate identity (email/URI)")
    p_verify_image.add_argument("--certificate-oidc-issuer",
                                 help="Expected OIDC issuer URL")
    p_verify_image.add_argument("--output", choices=["text", "json"], default="text",
                                 help="Output format")

    # checkpoint
    p_checkpoint = subparsers.add_parser("checkpoint", help="Checkpoint a running cell")
    p_checkpoint.add_argument("--keep", dest="keep_running", action="store_true",
                               help="Keep cell running after checkpoint")
    p_checkpoint.add_argument("--export-name", dest="checkpoint_name",
                               help="Checkpoint name (default: <cell>-checkpoint)")
    p_checkpoint.add_argument("name", help="Cell name")

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore a cell from checkpoint")
    p_restore.add_argument("--name", help="Name for restored cell (default: derived from checkpoint)")
    p_restore.add_argument("checkpoint", help="Checkpoint name")

    # diagnose
    p_diagnose = subparsers.add_parser("diagnose", help="Run diagnostic checks on cell")
    p_diagnose.add_argument("name", help="Cell name")

    # health
    p_health = subparsers.add_parser("health", help="Check system health")
    p_health.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Comprehensive system diagnostic")
    p_doctor.add_argument("--fix", action="store_true", help="Auto-fix issues where safe")
    p_doctor.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # preflight
    p_preflight = subparsers.add_parser("preflight", help="Run preflight validation checks")
    p_preflight.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # metrics
    p_metrics = subparsers.add_parser("metrics", help="Output Prometheus metrics")
    p_metrics.add_argument("--serve", action="store_true", help="Serve metrics via HTTP (for Prometheus scraping)")
    p_metrics.add_argument("--port", type=int, default=9090, help="Port for HTTP server (default: 9090)")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify security invariants")
    p_verify.add_argument("--fix", action="store_true",
                          help="Attempt to auto-fix common issues (restart warden, reconnect networks)")

    # history
    p_history = subparsers.add_parser("history", help="Show operation history")
    p_history.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_history.add_argument("--tail", "-n", type=int, default=20, help="Show last N entries (default: %(default)s)")
    p_history.add_argument("--cell", help="Filter by cell name")

    # config
    p_config = subparsers.add_parser("config", help="Manage brig configuration")
    config_sub = p_config.add_subparsers(dest="config_command", required=True)

    p_config_show = config_sub.add_parser(
        "show",
        help="Show configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Show all config:       brig config show
  Show specific key:     brig config show operation_logging.level
  List available keys:   brig config show --keys
"""
    )
    p_config_show.add_argument("key", nargs="?", help="Config key (e.g., operation_logging.enabled)")
    p_config_show.add_argument("--keys", action="store_true",
                               help="List available config keys with types and defaults")

    p_config_set = config_sub.add_parser(
        "set",
        help="Set configuration value",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Set boolean:           brig config set operation_logging.enabled true
  Set string:            brig config set operation_logging.level mutations
  View available keys:   brig config show --keys
"""
    )
    p_config_set.add_argument("key", help="Config key (e.g., operation_logging.level)")
    p_config_set.add_argument("value", help="Value to set (JSON or string)")

    config_sub.add_parser("reset", help="Reset to default configuration")

    # tui
    p_tui = subparsers.add_parser("tui", help="Launch interactive terminal UI")
    p_tui.add_argument("--view", choices=["dashboard", "logs", "metrics", "policy"],
                       default="dashboard", help="Initial view to display")
    p_tui.add_argument("--cell", metavar="NAME", help="Focus on specific cell")

    # dashboard
    p_dashboard = subparsers.add_parser("dashboard", help="Launch web dashboard")
    p_dashboard.add_argument("--port", type=int, default=8080,
                              help="Port to listen on (default: 8080)")

    # policy
    p_policy = subparsers.add_parser("policy", help="Manage cell network policies")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)

    p_policy_show = policy_sub.add_parser("show", help="Show cell's effective policy")
    p_policy_show.add_argument("name", help="Cell name")

    p_policy_set = policy_sub.add_parser(
        "set",
        help="Update cell's policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  Allow a domain:          brig policy set mycell --allow api.github.com
  Allow wildcard:          brig policy set mycell --allow '*.example.com'
  Deny a domain:           brig policy set mycell --deny evil.com
  Remove from allowlist:   brig policy set mycell --remove-allow old-api.com
  Multiple changes:        brig policy set mycell --allow a.com --allow b.com

Wildcards (*.example.com) match the domain and all subdomains.
Deny rules take precedence over allow rules.
"""
    )
    p_policy_set.add_argument("name", help="Cell name")
    p_policy_set.add_argument("--allow", action="append", help="Add allowed domain")
    p_policy_set.add_argument("--deny", action="append", help="Add denied domain")
    p_policy_set.add_argument("--remove-allow", action="append", help="Remove allowed domain")
    p_policy_set.add_argument("--remove-deny", action="append", help="Remove denied domain")

    p_policy_validate = policy_sub.add_parser("validate", help="Validate policy file syntax")
    p_policy_validate.add_argument("file", nargs="?", help="Policy file (default: /cells/network-policy.json)")

    p_policy_test = policy_sub.add_parser("test", help="Test if domain is allowed for cell")
    p_policy_test.add_argument("name", help="Cell name")
    p_policy_test.add_argument("domain", help="Domain to test")
    p_policy_test.add_argument("--path", default="/", help="Path to test (default: /)")
    p_policy_test.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    p_policy_test.add_argument("-v", "--verbose", action="store_true", help="Show detailed evaluation")

    args = parser.parse_args()

    # Set debug mode and log level.
    _helpers.DEBUG = args.debug
    if args.debug:
        _helpers.LOG_LEVEL = _helpers.LOG_LEVEL_DEBUG

    # Set color mode.
    if args.no_color:
        _helpers.COLOR_ENABLED = False

    # Set quiet mode.
    if args.quiet:
        _helpers.QUIET = True

    # Command dispatch table.
    commands = {
        "init": cmd_init,
        "upgrade": cmd_upgrade,
        "vm": cmd_vm,
        "run": cmd_run,
        "stop": cmd_stop,
        "kill": cmd_kill,
        "wait": cmd_wait,
        "rm": cmd_rm,
        "start": cmd_start,
        "list": cmd_list,
        "logs": cmd_logs,
        "exec": cmd_exec,
        "shell": cmd_shell,
        "rename": cmd_rename,
        "attach": cmd_attach,
        "top": cmd_top,
        "diff": cmd_diff,
        "stats": cmd_stats,
        "pause": cmd_pause,
        "unpause": cmd_unpause,
        "files": cmd_files,
        "cat": cmd_cat,
        "cp": cmd_cp,
        "inspect": cmd_inspect,
        "export": cmd_export,
        "network": cmd_network,
        "events": cmd_events,
        "pull": cmd_pull,
        "warmup": cmd_warmup,
        "image-verify": _image.cmd_verify_image,
        "checkpoint": cmd_checkpoint,
        "restore": cmd_restore,
        "diagnose": cmd_diagnose,
        "health": cmd_health,
        "doctor": cmd_doctor,
        "preflight": cmd_preflight,
        "metrics": cmd_metrics,
        "verify": cmd_verify,
        "history": cmd_history,
        "tui": cmd_tui,
        "dashboard": _dashboard_cmd.cmd_dashboard,
    }

    # Policy subcommands.
    policy_commands = {
        "show": cmd_policy_show,
        "set": cmd_policy_set,
        "validate": cmd_policy_validate,
        "test": cmd_policy_test,
    }

    # Config subcommands.
    config_commands = {
        "show": cmd_config_show,
        "set": cmd_config_set,
        "reset": cmd_config_reset,
    }

    # Determine command name for logging.
    if args.command == "policy":
        cmd_name = f"policy.{args.policy_command}"
        cmd_func = policy_commands.get(args.policy_command)
    elif args.command == "config":
        cmd_name = f"config.{args.config_command}"
        cmd_func = config_commands.get(args.config_command)
    elif args.command == "vm":
        cmd_name = f"vm.{args.vm_command}"
        cmd_func = commands.get("vm")
    else:
        cmd_name = args.command
        cmd_func = commands.get(args.command)

    if not cmd_func:
        error_unknown_command(args.command)

    # Execute command with operation logging.
    op_context = log_operation_start(cmd_name, args)
    exit_code = 0
    error_msg = None

    try:
        exit_code = cmd_func(args)
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl-C.
        error_msg = "Interrupted by user"
        exit_code = 130  # Standard exit code for SIGINT.
        if not _helpers.QUIET:
            print("\nInterrupted", file=sys.stderr)
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        # Sanitize error message to avoid leaking internal paths or secrets.
        raw_msg = str(e)
        sanitized = re.sub(r'(/[^\s:]+)', '<path>', raw_msg)
        error_msg = sanitized
        exit_code = 1
        if _helpers.DEBUG:
            import traceback
            traceback.print_exc()
        else:
            print(f"ERROR: {sanitized}", file=sys.stderr)
    finally:
        log_operation_end(op_context, exit_code, error_msg)

    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Final fallback for any unhandled interrupts.
        sys.exit(130)
