"""
Brig CLI — argparse setup and main entry point.

No _BrigModule metaclass hack. No wildcard imports. Each command dispatches
to a thin handler in brig.commands.*_cmd that calls domain modules.
"""

from __future__ import annotations

import argparse
import re
import signal
import sys

from brig.config import VERSION
from brig.errors import BrigError
from brig.ops.logging import configure as configure_logging
from brig.ops.history import log_operation_start, log_operation_end

# Commands that run on the macOS host without needing the Lima VM.
_HOST_ONLY_COMMANDS = frozenset({
    "init", "config", "history", "image-verify", "up", "profiles", "secrets",
})


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for all brig commands."""
    parser = argparse.ArgumentParser(
        prog="brig",
        description="Brig - Secure workload harness for running untrusted code",
    )
    parser.add_argument("--version", action="version", version=f"brig {VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    sub = parser.add_subparsers(dest="command", required=True)

    # --- Cell lifecycle ---
    p_run = sub.add_parser("run", help="Run a new cell",
        epilog="Examples:\n"
               "  brig run alpine echo hello\n"
               "  brig run --name test --profile untrusted python:3.12 python app.py\n"
               "  brig run --secret api-key alpine -- curl -H @/run/secrets/api-key $URL\n"
               "  brig run --file mycell.yaml\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_run.add_argument("image", nargs="?", help="Container image (must precede 'command'; flags must come before image)")
    p_run.add_argument("container_cmd", nargs=argparse.REMAINDER, metavar="command",
                       help="Command to run (use -- before flags like -la)")
    p_run.add_argument("--name", "-n", help="Cell name (auto-generated if omitted)")
    p_run.add_argument("--env", "-e", action="append", help="Environment variable (KEY=VALUE)")
    p_run.add_argument("--secret", "-s", action="append", help="Secret to mount")
    p_run.add_argument("--memory", "-m", help="Memory limit (e.g. 512m, 2g)")
    p_run.add_argument("--cpus", help="CPU limit")
    p_run.add_argument("--pids-limit", type=int, help="PID limit")
    p_run.add_argument("--network", help="Network mode (default or none)")
    p_run.add_argument("--profile", help="Trust profile")
    p_run.add_argument("--file", "-f", help="Cell definition file (YAML/JSON)")
    p_run.add_argument("--policy-allow", action="append", help="Allowed domains")
    p_run.add_argument("--policy-deny", action="append", help="Denied domains")
    p_run.add_argument("--label", "-l", action="append", help="Labels (key=value)")
    p_run.add_argument("--timeout", help="Container timeout (e.g. 30s, 5m)")
    p_run.add_argument("--workspace-quota", help="Workspace size limit")
    p_run.add_argument("-d", "--detach", action="store_true", help="Run in background")
    p_run.add_argument("--rm", action="store_true", help="Remove on exit")
    p_run.add_argument("--image-digest", help="Expected image digest")
    p_run.add_argument("--workdir", help="Working directory override")

    _LIFECYCLE_HELP = {
        "stop": "Gracefully stop a running cell",
        "kill": "Immediately kill a running cell (SIGKILL)",
        "start": "Start a previously-stopped cell",
        "pause": "Suspend processes in a running cell",
        "unpause": "Resume processes in a paused cell",
        "attach": "Attach stdio to a running cell",
        "shell": "Open an interactive /bin/sh inside a running cell",
    }
    for name, help_text in _LIFECYCLE_HELP.items():
        p = sub.add_parser(name, help=help_text)
        p.add_argument("name", help="Cell name")

    p_wait = sub.add_parser("wait", help="Block until a cell exits, then print its exit code")
    p_wait.add_argument("name", help="Cell name")

    p_rm = sub.add_parser("rm", help="Remove a cell")
    p_rm.add_argument("name", help="Cell name")
    p_rm.add_argument("-f", "--force", action="store_true", help="Force removal")

    p_rename = sub.add_parser("rename", help="Rename a cell")
    p_rename.add_argument("old_name", help="Current name")
    p_rename.add_argument("new_name", help="New name")

    p_exec = sub.add_parser("exec", help="Execute command in cell")
    p_exec.add_argument("name", help="Cell name")
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, metavar="command", help="Command to execute")

    p_list = sub.add_parser("list", help="List all cells")
    p_list.add_argument("--format", choices=["table", "wide", "json"], default="table",
                        help="table (default), wide (more columns), or json")

    # --- Info ---
    p_inspect = sub.add_parser("inspect", help="Show cell details")
    p_inspect.add_argument("name", help="Cell name")

    p_export = sub.add_parser("export", help="Export cell as reusable YAML definition")
    p_export.add_argument("name", help="Cell name")

    # --- Secrets / Policy / Config — registered by their command modules ---
    from brig.commands import secrets_cmd, policy_cmd, config_cmd
    secrets_cmd.register_parser(sub)

    p_files = sub.add_parser("files", help="List workspace contents")
    p_files.add_argument("name", help="Cell name")
    p_files.add_argument("path", nargs="?", default="/work", help="Path inside cell")

    p_logs = sub.add_parser("logs", help="View cell logs")
    p_logs.add_argument("name", help="Cell name")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_logs.add_argument("--tail", type=int, help="Number of lines")

    p_top = sub.add_parser("top", help="Show processes in cell")
    p_top.add_argument("name", help="Cell name")

    p_diff = sub.add_parser("diff", help="Show filesystem changes")
    p_diff.add_argument("name", help="Cell name")

    p_stats = sub.add_parser("stats", help="Show resource usage")
    p_stats.add_argument("name", nargs="?", help="Cell name (optional)")

    # --- Workspace ---
    p_cp = sub.add_parser("cp", help="Copy files to/from cell")
    p_cp.add_argument("src", help="Source path")
    p_cp.add_argument("dst", help="Destination path")

    # --- Network/Events ---
    p_network = sub.add_parser("network", help="View network activity")
    p_network.add_argument("name", help="Cell name")
    p_network.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_network.add_argument("--blocked", action="store_true",
                           help="Show only requests that warden blocked (and why)")

    p_events = sub.add_parser("events", help="Stream lifecycle events")
    p_events.add_argument("name", nargs="?", help="Cell name filter")
    p_events.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_events.add_argument("-f", "--follow", action="store_true",
                          help="Block and print new events as they arrive")

    # --- Image ---
    p_pull = sub.add_parser("pull", help="Pull and cache image")
    p_pull.add_argument("image", help="Image to pull")

    p_warmup = sub.add_parser("warmup", help="Pre-pull images for profile")
    p_warmup.add_argument("--profile", help="Profile name")

    p_imgverify = sub.add_parser("image-verify", help="Verify image signature")
    p_imgverify.add_argument("image", help="Image to verify")
    p_imgverify.add_argument("--key", help="Cosign public key")
    p_imgverify.add_argument("--keyless", action="store_true", help="Keyless verification")


    # --- Convenience ---
    sub.add_parser("up", help="Ensure VM + warden are running (init if needed)")
    p_down = sub.add_parser("down", help="Stop all cells + warden")
    p_down.add_argument("--vm", action="store_true", help="Also stop the VM")
    sub.add_parser("profiles", help="List available trust profiles")
    p_watch = sub.add_parser("watchdog", help="Monitor warden, restart on failure")
    p_watch.add_argument("--interval", type=int, default=30, help="Check interval (seconds)")
    p_watch.add_argument("--max-restarts", type=int, default=5, help="Max restart attempts")

    # --- System ---
    sub.add_parser("init", help="Initialize brig")

    p_verify = sub.add_parser("verify", help="Verify security invariants")
    p_verify.add_argument("--fix", action="store_true", help="Auto-fix issues")

    p_health = sub.add_parser("health", help="Check system health")
    p_health.add_argument("--format", choices=["table", "json"], default="table")

    p_diagnose = sub.add_parser("diagnose", help="Run diagnostic checks")
    p_diagnose.add_argument("name", help="Cell name")

    sub.add_parser("doctor", help="Check environment and report fixable issues")

    sub.add_parser("preflight", help="Run pre-start checks")
    sub.add_parser("metrics", help="Output Prometheus metrics")

    p_history = sub.add_parser("history", help="Show operation history")
    p_history.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_history.add_argument("--cell", help="Filter by cell name")

    policy_cmd.register_parser(sub)
    config_cmd.register_parser(sub)

    return parser


def main() -> None:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    configure_logging(
        debug=args.debug,
        quiet=args.quiet,
        color=not args.no_color,
    )

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(130))

    # Preflight: check Lima is available for commands that need the VM.
    if args.command not in _HOST_ONLY_COMMANDS:
        import shutil
        if not shutil.which("limactl"):
            print("ERROR: limactl not found on PATH", file=sys.stderr)
            print("  Install Lima: brew install lima", file=sys.stderr)
            sys.exit(1)
        from brig.vm.shell import vm_running
        if not vm_running():
            # Allow init-adjacent commands through with a warning.
            if args.command not in {"health", "preflight"}:
                print("ERROR: Brig VM is not running", file=sys.stderr)
                print("  Start it with: limactl start brig", file=sys.stderr)
                print("  Or initialize: brig init && limactl create --name=brig ~/.brig/lima.yaml", file=sys.stderr)
                sys.exit(1)

    # Lazy imports to avoid loading all modules on every invocation.
    from brig.commands import (
        lifecycle_cmd, system_cmd, policy_cmd,
        network_cmd, config_cmd, image_cmd, convenience_cmd,
        secrets_cmd, watchdog_cmd,
    )

    dispatch = {
        "run": lifecycle_cmd.cmd_run,
        "stop": lifecycle_cmd.cmd_stop,
        "kill": lifecycle_cmd.cmd_kill,
        "rm": lifecycle_cmd.cmd_rm,
        "start": lifecycle_cmd.cmd_start,
        "wait": lifecycle_cmd.cmd_wait,
        "pause": lifecycle_cmd.cmd_pause,
        "unpause": lifecycle_cmd.cmd_unpause,
        "exec": lifecycle_cmd.cmd_exec,
        "shell": lifecycle_cmd.cmd_shell,
        "attach": lifecycle_cmd.cmd_attach,
        "rename": lifecycle_cmd.cmd_rename,
        "list": lifecycle_cmd.cmd_list,
        "inspect": lifecycle_cmd.cmd_inspect,
        "export": lifecycle_cmd.cmd_export,
        "files": lifecycle_cmd.cmd_files,
        "logs": lifecycle_cmd.cmd_logs,
        "top": lifecycle_cmd.cmd_top,
        "diff": lifecycle_cmd.cmd_diff,
        "stats": lifecycle_cmd.cmd_stats,
        "cp": lifecycle_cmd.cmd_cp,
        "network": network_cmd.cmd_network,
        "events": network_cmd.cmd_events,
        "pull": image_cmd.cmd_pull,
        "warmup": image_cmd.cmd_warmup,
        "image-verify": image_cmd.cmd_verify_image,
        "init": system_cmd.cmd_init,
        "verify": system_cmd.cmd_verify,
        "health": system_cmd.cmd_health,
        "diagnose": system_cmd.cmd_diagnose,
        "doctor": system_cmd.cmd_doctor,
        "preflight": system_cmd.cmd_preflight,
        "metrics": system_cmd.cmd_metrics,
        "history": system_cmd.cmd_history,
        "up": convenience_cmd.cmd_up,
        "down": convenience_cmd.cmd_down,
        "profiles": convenience_cmd.cmd_profiles,
        "watchdog": watchdog_cmd.cmd_watchdog,
    }

    if args.command == "policy":
        cmd_func = policy_cmd.DISPATCH.get(args.policy_command)
        cmd_name = f"policy.{args.policy_command}"
    elif args.command == "config":
        cmd_func = config_cmd.DISPATCH.get(args.config_command)
        cmd_name = f"config.{args.config_command}"
    elif args.command == "secrets":
        cmd_func = secrets_cmd.DISPATCH.get(args.secrets_command)
        cmd_name = f"secrets.{args.secrets_command}"
    else:
        cmd_func = dispatch.get(args.command)
        cmd_name = args.command

    if cmd_func is None:
        parser.print_help()
        sys.exit(1)

    op_context = log_operation_start(cmd_name, args)
    exit_code = 0
    error_msg = None

    try:
        exit_code = cmd_func(args) or 0
    except BrigError as e:
        error_msg = str(e)
        exit_code = e.returncode
        print(f"ERROR: {e}", file=sys.stderr)
        if e.suggestion:
            print(f"  Suggestion: {e.suggestion}", file=sys.stderr)
    except KeyboardInterrupt:
        error_msg = "Interrupted by user"
        exit_code = 130
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        sanitized = re.sub(r'(/[^\s:]+)', '<path>', str(e))
        error_msg = sanitized
        exit_code = 1
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print(f"ERROR: {sanitized}", file=sys.stderr)
    finally:
        log_operation_end(op_context, exit_code, error_msg)

    sys.exit(exit_code)
