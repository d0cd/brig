"""
Brig CLI — argparse setup and main entry point.

Command shape (since 0.3.0):
  brig run <image> ...                 # primary verb
  brig cell <verb> <name> ...          # per-cell operations
  brig image <verb> ...                # image lifecycle
  brig system <verb> ...               # VM + warden + diagnostics
  brig policy <verb> ...               # network policy
  brig secrets <verb> ...              # secret storage
  brig config <verb> ...               # config file

Hard rename — no aliases for the old flat names.
"""

from __future__ import annotations

import argparse
import signal
import sys

from brig.config import VERSION
from brig.errors import BrigError
from brig.ops.logging import configure as configure_logging, error as log_error
from brig.ops.history import log_operation_start, log_operation_end

# Top-level commands that run on the macOS host without needing the Lima VM.
_HOST_ONLY_TOP = frozenset({"config", "policy", "secrets"})
# `system` subcommands that don't touch the VM.
#   - init / profiles: pure config-file reads.
#   - up: creates+starts the VM; doesn't need it pre-existing.
#   - down: must work even when the VM is broken (idempotent cleanup) — and
#     `brig system down --vm` definitionally has to work without the VM up.
#   - history: reads ~/.brig/state/system/operations.jsonl on host only.
_HOST_ONLY_SYSTEM = frozenset({"init", "profiles", "up", "down", "history"})
# `image` subcommands that don't touch the VM.
_HOST_ONLY_IMAGE = frozenset({"verify"})


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

    _add_run_parser(sub)
    _add_cell_group(sub)
    _add_image_group(sub)
    _add_system_group(sub)

    # External groups registered by their command modules.
    from brig.commands import secrets_cmd, policy_cmd, config_cmd
    secrets_cmd.register_parser(sub)
    policy_cmd.register_parser(sub)
    config_cmd.register_parser(sub)

    return parser


def _add_run_parser(sub: argparse._SubParsersAction) -> None:
    """`brig run` — the primary verb, kept flat to match docker/podman."""
    p = sub.add_parser(
        "run", help="Run a new cell",
        epilog="Examples:\n"
               "  brig run alpine echo hello\n"
               "  brig run --name test --profile untrusted python:3.12 python app.py\n"
               "  brig run --secret api-key alpine -- curl -H @/run/secrets/api-key $URL\n"
               "  brig run --file mycell.yaml\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("image", nargs="?", help="Container image (flags must precede image)")
    p.add_argument("container_cmd", nargs=argparse.REMAINDER, metavar="command",
                   help="Command to run (use -- before flags like -la)")
    p.add_argument("--name", "-n", help="Cell name (auto-generated if omitted)")
    p.add_argument("--env", "-e", action="append", help="Environment variable (KEY=VALUE)")
    p.add_argument("--secret", "-s", action="append", help="Secret to mount")
    p.add_argument("--memory", "-m", help="Memory limit (e.g. 512m, 2g)")
    p.add_argument("--cpus", help="CPU limit")
    p.add_argument("--pids-limit", type=int, help="PID limit")
    p.add_argument("--network", help="Network mode (default or none)")
    p.add_argument("--profile", help="Trust profile")
    p.add_argument("--file", "-f", help="Cell definition file (YAML/JSON)")
    p.add_argument("--policy-allow", action="append", help="Allowed domains")
    p.add_argument("--policy-deny", action="append", help="Denied domains")
    p.add_argument("--label", "-l", action="append", help="Labels (key=value)")
    p.add_argument("--timeout", help="Container timeout (e.g. 30s, 5m)")
    p.add_argument("--workspace-quota", help="Workspace size limit")
    p.add_argument("-d", "--detach", action="store_true", help="Run in background")
    p.add_argument("--rm", action="store_true", help="Remove on exit")
    p.add_argument("--image-digest", help="Expected image digest")
    p.add_argument("--workdir", help="Working directory override")


def _add_cell_group(sub: argparse._SubParsersAction) -> None:
    """`brig cell <verb>` — per-cell operations."""
    p_cell = sub.add_parser("cell", help="Cell lifecycle and inspection")
    cs = p_cell.add_subparsers(dest="cell_command", required=True)

    # One-arg lifecycle verbs.
    _ONE_ARG = {
        "stop": "Gracefully stop a running cell",
        "kill": "Immediately kill a running cell (SIGKILL)",
        "start": "Start a previously-stopped cell",
        "pause": "Suspend processes in a running cell",
        "unpause": "Resume processes in a paused cell",
        "attach": "Attach stdio to a running cell",
        "shell": "Open an interactive /bin/sh inside a running cell",
        "wait": "Block until a cell exits, then print its exit code",
        "inspect": "Show cell details (raw podman inspect JSON)",
        "diagnose": "Run diagnostic checks for a cell",
        "export": "Export cell as reusable YAML definition",
        "top": "Show processes in cell",
        "diff": "Show filesystem changes since image base",
    }
    for name, help_text in _ONE_ARG.items():
        p = cs.add_parser(name, help=help_text)
        p.add_argument("name", help="Cell name")

    p_rm = cs.add_parser("rm", help="Remove a cell")
    p_rm.add_argument("name", help="Cell name")
    p_rm.add_argument("-f", "--force", action="store_true", help="Force removal")

    p_rename = cs.add_parser("rename", help="Rename a cell")
    p_rename.add_argument("old_name", help="Current name")
    p_rename.add_argument("new_name", help="New name")

    p_exec = cs.add_parser("exec", help="Execute command in cell")
    p_exec.add_argument("name", help="Cell name")
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, metavar="command",
                        help="Command to execute")

    p_list = cs.add_parser("list", help="List all cells")
    p_list.add_argument("--format", choices=["table", "wide", "json"], default="table")

    p_files = cs.add_parser("files", help="List workspace contents")
    p_files.add_argument("name", help="Cell name")
    p_files.add_argument("path", nargs="?", default="/work", help="Path inside cell")

    p_logs = cs.add_parser("logs", help="View cell logs")
    p_logs.add_argument("name", help="Cell name")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    p_logs.add_argument("--tail", type=int, help="Number of lines")

    p_stats = cs.add_parser("stats", help="Show resource usage")
    p_stats.add_argument("name", nargs="?", help="Cell name (optional)")

    p_cp = cs.add_parser("cp", help="Copy files to/from cell")
    p_cp.add_argument("src", help="Source path")
    p_cp.add_argument("dst", help="Destination path")

    p_network = cs.add_parser("network", help="View network activity")
    p_network.add_argument("name", help="Cell name")
    p_network.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_network.add_argument("--blocked", action="store_true",
                           help="Show only requests warden blocked (and why)")

    p_events = cs.add_parser("events", help="Stream lifecycle events")
    p_events.add_argument("name", nargs="?", help="Cell name filter")
    p_events.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_events.add_argument("-f", "--follow", action="store_true",
                          help="Block and print new events as they arrive")


def _add_image_group(sub: argparse._SubParsersAction) -> None:
    """`brig image <verb>` — image build / pull / verify."""
    p_image = sub.add_parser("image", help="Image build / pull / verify")
    isub = p_image.add_subparsers(dest="image_command", required=True)

    p_build = isub.add_parser(
        "build", help="Build a container image from a directory",
    )
    p_build.add_argument("context", help="Build-context directory (host path)")
    p_build.add_argument("--tag", "-t",
                         help="Image tag (default: localhost/<dir-basename>:latest)")
    p_build.add_argument("--file", "-f",
                         help="Containerfile path relative to context "
                              "(default: auto-detect Containerfile/Dockerfile)")
    p_build.add_argument("--build-arg", action="append", metavar="KEY=VALUE",
                         help="Build-time variable (passed through to podman)")

    p_pull = isub.add_parser("pull", help="Pull and cache image")
    p_pull.add_argument("image", help="Image to pull")

    p_verify = isub.add_parser("verify", help="Verify image signature (cosign)")
    p_verify.add_argument("image", help="Image to verify")
    p_verify.add_argument("--key", help="Cosign public key")
    p_verify.add_argument("--keyless", action="store_true", help="Keyless verification")

    p_warmup = isub.add_parser("warmup", help="Pre-pull images for a profile")
    p_warmup.add_argument("--profile", help="Profile name")


def _add_system_group(sub: argparse._SubParsersAction) -> None:
    """`brig system <verb>` — VM, warden, diagnostics."""
    p_system = sub.add_parser("system", help="VM, warden, diagnostics")
    ss = p_system.add_subparsers(dest="system_command", required=True)

    ss.add_parser("init", help="Initialize brig (create ~/.brig, default policy)")
    ss.add_parser("up", help="Ensure VM + warden are running")
    p_down = ss.add_parser("down", help="Stop all cells + warden")
    p_down.add_argument("--vm", action="store_true", help="Also stop the VM")
    ss.add_parser("profiles", help="List available trust profiles")
    ss.add_parser("preflight", help="Run pre-start checks")
    ss.add_parser("metrics", help="Output Prometheus metrics")

    p_verify = ss.add_parser("verify", help="Verify security invariants")
    p_verify.add_argument("--fix", action="store_true", help="Auto-fix issues")

    p_doctor = ss.add_parser(
        "doctor", help="Check environment and report fixable issues",
    )
    p_doctor.add_argument(
        "--quick", action="store_true",
        help="Only check the two essentials (proxy + VM).",
    )

    p_watchdog = ss.add_parser("watchdog", help="Monitor warden, restart on failure")
    p_watchdog.add_argument("--interval", type=int, default=30,
                            help="Check interval (seconds)")
    p_watchdog.add_argument("--max-restarts", type=int, default=5,
                            help="Max restart attempts")

    p_prune = ss.add_parser(
        "prune",
        help="Clean up stopped cells, old logs, orphan subnet allocations",
    )
    p_prune.add_argument("--cells", action="store_true",
                         help="Only prune stopped cells (default: all)")
    p_prune.add_argument("--logs", action="store_true",
                         help="Only prune old log files (default: all)")
    p_prune.add_argument("--subnets", action="store_true",
                         help="Only prune orphan subnet allocations (default: all)")
    p_prune.add_argument("--log-days", type=int, default=7,
                         help="Drop rotated logs older than N days (default: 7)")
    p_prune.add_argument("-n", "--dry-run", action="store_true",
                         help="Show what would be removed without acting")

    p_history = ss.add_parser("history", help="Show brig CLI operation history")
    p_history.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_history.add_argument("--cell", help="Filter by cell name")


def _is_host_only(args: argparse.Namespace) -> bool:
    """Whether the command can run without the Lima VM."""
    cmd = args.command
    if cmd in _HOST_ONLY_TOP:
        return True
    if cmd == "system":
        return getattr(args, "system_command", "") in _HOST_ONLY_SYSTEM
    if cmd == "image":
        return getattr(args, "image_command", "") in _HOST_ONLY_IMAGE
    return False


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
    if not _is_host_only(args):
        import shutil
        if not shutil.which("limactl"):
            log_error("limactl not found on PATH")
            log_error("  Install Lima: brew install lima")
            sys.exit(1)
        from brig.vm.shell import vm_running
        if not vm_running():
            # `system doctor` and `system preflight` are diagnostics — let
            # them through so the user can find out *why* the VM isn't up.
            sys_cmd = getattr(args, "system_command", "")
            if not (args.command == "system" and sys_cmd in {"doctor", "preflight"}):
                log_error("Brig VM is not running")
                log_error("  Start it with: brig system up")
                log_error("  Or initialize: brig system init && brig system up")
                sys.exit(1)

    from brig.commands import (
        lifecycle_cmd, system_cmd, policy_cmd,
        network_cmd, config_cmd, image_cmd, convenience_cmd,
        secrets_cmd, watchdog_cmd,
    )

    # Two-level dispatch: keyed by (group, verb) for grouped commands,
    # plain str for top-level commands.
    dispatch: dict = {
        "run": lifecycle_cmd.cmd_run,

        # cell *
        ("cell", "list"): lifecycle_cmd.cmd_list,
        ("cell", "inspect"): lifecycle_cmd.cmd_inspect,
        ("cell", "export"): lifecycle_cmd.cmd_export,
        ("cell", "stop"): lifecycle_cmd.cmd_stop,
        ("cell", "kill"): lifecycle_cmd.cmd_kill,
        ("cell", "start"): lifecycle_cmd.cmd_start,
        ("cell", "pause"): lifecycle_cmd.cmd_pause,
        ("cell", "unpause"): lifecycle_cmd.cmd_unpause,
        ("cell", "attach"): lifecycle_cmd.cmd_attach,
        ("cell", "shell"): lifecycle_cmd.cmd_shell,
        ("cell", "wait"): lifecycle_cmd.cmd_wait,
        ("cell", "rm"): lifecycle_cmd.cmd_rm,
        ("cell", "rename"): lifecycle_cmd.cmd_rename,
        ("cell", "exec"): lifecycle_cmd.cmd_exec,
        ("cell", "files"): lifecycle_cmd.cmd_files,
        ("cell", "logs"): lifecycle_cmd.cmd_logs,
        ("cell", "top"): lifecycle_cmd.cmd_top,
        ("cell", "diff"): lifecycle_cmd.cmd_diff,
        ("cell", "stats"): lifecycle_cmd.cmd_stats,
        ("cell", "cp"): lifecycle_cmd.cmd_cp,
        ("cell", "network"): network_cmd.cmd_network,
        ("cell", "events"): network_cmd.cmd_events,
        ("cell", "diagnose"): system_cmd.cmd_diagnose,

        # image *
        ("image", "build"): image_cmd.cmd_build,
        ("image", "pull"): image_cmd.cmd_pull,
        ("image", "verify"): image_cmd.cmd_verify_image,
        ("image", "warmup"): image_cmd.cmd_warmup,

        # system *
        ("system", "init"): system_cmd.cmd_init,
        ("system", "up"): convenience_cmd.cmd_up,
        ("system", "down"): convenience_cmd.cmd_down,
        ("system", "profiles"): convenience_cmd.cmd_profiles,
        ("system", "verify"): system_cmd.cmd_verify,
        ("system", "doctor"): system_cmd.cmd_doctor,
        ("system", "preflight"): system_cmd.cmd_preflight,
        ("system", "metrics"): system_cmd.cmd_metrics,
        ("system", "prune"): system_cmd.cmd_prune,
        ("system", "watchdog"): watchdog_cmd.cmd_watchdog,
        ("system", "history"): system_cmd.cmd_history,
    }

    if args.command in {"cell", "image", "system"}:
        sub_attr = f"{args.command}_command"
        sub_value = getattr(args, sub_attr)
        cmd_func = dispatch.get((args.command, sub_value))
        cmd_name = f"{args.command}.{sub_value}"
    elif args.command == "policy":
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
        log_error(str(e))
        if e.suggestion:
            log_error(f"  Suggestion: {e.suggestion}")
    except KeyboardInterrupt:
        error_msg = "interrupted"
        exit_code = 130
    except Exception as e:  # noqa: BLE001
        error_msg = repr(e)
        exit_code = 1
        log_error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        log_operation_end(op_context, exit_code=exit_code, error=error_msg)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
