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
#   - watchdog: the supervisor must run in every state — it brings the VM up
#     (via `system up`) when the host slept and dropped it, so it can't be
#     gated on the VM already running.
_HOST_ONLY_SYSTEM = frozenset(
    {"init", "profiles", "up", "down", "history", "watchdog"}
)
# `image` subcommands that don't touch the VM.
_HOST_ONLY_IMAGE = frozenset({"verify"})


# `cell` verb aliases → canonical verb. argparse stores the literal alias the
# user typed, so dispatch (keyed on the canonical verb) normalizes via this map.
_CELL_VERB_ALIASES = {"ls": "list", "status": "inspect"}


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

    # required=False so bare `brig` falls through to our friendly
    # cheat-sheet (_print_quickstart) instead of argparse's
    # "the following arguments are required: command" error.
    sub = parser.add_subparsers(dest="command", required=False)

    _add_run_parser(sub)
    _add_cell_group(sub)
    _add_image_group(sub)
    _add_system_group(sub)

    # Top-level `brig ps` — docker-style shortcut for `brig cell list`.
    p_ps = sub.add_parser("ps", help="List all cells (alias for `cell list`)")
    p_ps.add_argument("--format", choices=["table", "wide", "json"], default="table")

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
               "  brig run --file mycell.yaml\n"
               "\n"
               "Cell yaml notes:\n"
               "  - ingress with auth: token requires a secret named\n"
               "    <cell-name>-ingress-token (preferred) or ingress-token (fallback).\n"
               "    Register it with: brig secrets add <cell-name>-ingress-token.\n"
               "  - policy.tls_passthrough: list hosts to skip warden MITM (SNI-routed).\n"
               "    Each entry must also appear in policy.allow.\n",
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
    p.add_argument(
        "--yes", "-y", action="store_true",
        help="Auto-confirm prompts (e.g. warden restart when adding a new "
             "TCP host_service that needs a listener bound)",
    )


def _add_cell_group(sub: argparse._SubParsersAction) -> None:
    """`brig cell <verb>` — per-cell operations."""
    p_cell = sub.add_parser("cell", help="Cell lifecycle and inspection")
    cs = p_cell.add_subparsers(dest="cell_command", required=True)

    # One-arg lifecycle verbs.
    _ONE_ARG = {
        "stop": "Gracefully stop a running cell",
        "kill": "Immediately kill a running cell (SIGKILL)",
        "start": "Start a previously-stopped cell",
        "restart": "Stop (if running) then start — applies cell yaml changes",
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
    # Convenience aliases for near-universal names (argparse normalizes the
    # stored verb back to the primary, so dispatch needs no extra entries).
    _ALIASES = {"inspect": ["status"]}
    for name, help_text in _ONE_ARG.items():
        p = cs.add_parser(name, aliases=_ALIASES.get(name, []), help=help_text)
        p.add_argument("name", help="Cell name")

    p_rm = cs.add_parser(
        "rm",
        help="Remove a cell (also deletes its workspace dir by default)",
    )
    p_rm.add_argument("name", help="Cell name")
    p_rm.add_argument("-f", "--force", action="store_true",
                      help="Stop the cell first if running")
    p_rm.add_argument("--keep-workspace", action="store_true",
                      help="Preserve ~/.brig/state/<cell>/ (workspace + "
                           "metadata). Use if you want to brig cell cp files "
                           "out later. Without this flag, the cell's "
                           "workspace is deleted to prevent the next cell "
                           "with the same name from inheriting planted files.")

    p_preflight = cs.add_parser(
        "preflight",
        help="Dry-run check: verify a cell yaml's host-side requirements",
    )
    p_preflight.add_argument("file", help="Path to cell yaml/json")

    p_rename = cs.add_parser("rename", help="Rename a cell")
    p_rename.add_argument("old_name", help="Current name")
    p_rename.add_argument("new_name", help="New name")

    p_exec = cs.add_parser(
        "exec", help="Execute command in cell",
        epilog="Flags (-i) must come before the cell name; everything after "
               "the name is the command. Use '--' to pass flags to the command: "
               "brig cell exec -i mycell -- ls -la",
    )
    p_exec.add_argument("name", help="Cell name")
    p_exec.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    p_exec.add_argument("exec_cmd", nargs=argparse.REMAINDER, metavar="command",
                        help="Command to execute (everything after the cell name)")

    p_mscan = cs.add_parser(
        "mount-scan",
        help="Scan a cell's host mounts for symlinks escaping the mounted dir",
    )
    p_mscan.add_argument("name", help="Cell name")
    p_mscan.add_argument("--quarantine", action="store_true",
                         help="Remove escaping symlinks instead of only reporting")

    p_list = cs.add_parser("list", aliases=["ls"], help="List all cells")
    p_list.add_argument("--format", choices=["table", "wide", "json"], default="table")

    p_files = cs.add_parser("files", help="List workspace contents")
    p_files.add_argument("name", help="Cell name")
    p_files.add_argument("path", nargs="?", default="/work", help="Path inside cell")

    p_read = cs.add_parser(
        "read",
        help="Stream a workspace file to stdout (race-free; refuses symlinks)",
    )
    p_read.add_argument("name", help="Cell name")
    p_read.add_argument("path", help="Relative path inside the workspace")

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
    p_network.add_argument("--otel", action="store_true",
                           help="Read from the OTel collector instead of "
                                "per-cell JSONL files")

    p_events = cs.add_parser("events", help="Stream lifecycle events")
    p_events.add_argument("name", nargs="?", help="Cell name filter")
    p_events.add_argument("--tail", type=int, default=20, help="Number of entries")
    p_events.add_argument("-f", "--follow", action="store_true",
                          help="Block and print new events as they arrive")

    p_ingress = cs.add_parser(
        "ingress",
        help="Show reachable ingress URLs (and the token secret) for a cell",
    )
    p_ingress.add_argument("name", help="Cell name")


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
    p_build.add_argument(
        "--use-warden", action="store_true",
        help="Route the build's HTTP(S) traffic through warden. Injects "
             "HTTPS_PROXY/HTTP_PROXY/NO_PROXY build args and mounts the "
             "warden CA at /etc/ssl/certs/warden-ca.crt in the build "
             "container. Requires the Containerfile to forward those "
             "args via ARG+ENV (standard proxy pattern). Same policy "
             "applies as the runtime — eliminates the build/runtime "
             "asymmetry that forces pre-baking binaries.",
    )

    p_pull = isub.add_parser("pull", help="Pull and cache image")
    p_pull.add_argument("image", help="Image to pull")

    p_verify = isub.add_parser("verify", help="Verify image signature (cosign)")
    p_verify.add_argument("image", help="Image to verify")
    p_verify.add_argument(
        "--key", required=True,
        help="Cosign public key to verify against (required). Proves the image "
        "was signed by the holder of this key. (Keyless verification was "
        "removed: without an identity constraint it can't attest WHO signed.)",
    )

    isub.add_parser(
        "warmup",
        help="Pre-pull the warden proxy base image into the VM cache",
    )


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
    ss.add_parser("stats", help="Per-cell summary from the OTel collector")

    ss.add_parser("verify", help="Verify security invariants")

    p_doctor = ss.add_parser(
        "doctor", help="Check environment and report fixable issues",
    )
    p_doctor.add_argument(
        "--quick", action="store_true",
        help="Only check the two essentials (proxy + VM).",
    )

    p_watchdog = ss.add_parser(
        "watchdog",
        help="Monitor warden (restart on failure) and enforce workspace quotas",
    )
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


_QUICKSTART = """\
brig - secure workload harness for running untrusted code

Quickstart:
  brig system up                   # start the VM + warden (once per boot)
  brig run alpine echo hello       # run a cell
  brig cell list                   # see what's running
  brig cell logs <name>            # tail a cell's logs
  brig cell rm <name>              # remove a cell

Common verbs:
  run         Run a new cell                  (brig run --help)
  cell        Per-cell lifecycle + inspection (brig cell --help)
  image       Build, pull, verify, warmup     (brig image --help)
  system      VM + warden + diagnostics       (brig system --help)
  policy      Network policy CRUD             (brig policy --help)
  secrets     Secret storage                  (brig secrets --help)
  config      Config file                     (brig config --help)

Docs:           docs/learning/  (quickstart, concepts, workflows, troubleshooting)
Full reference: brig --help
"""


def _print_quickstart() -> None:
    """Print the categorized cheat-sheet shown when `brig` is run with
    no subcommand. Replaces argparse's bare 'required: command' error
    (which dumped a wall of flags) with a verb-grouped index."""
    sys.stdout.write(_QUICKSTART)


def _stats_dispatch(args):
    """Lazy import — keeps cli.py startup fast on unrelated commands."""
    from brig.observability.stats import cmd_stats
    return cmd_stats(args)


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

    # Bare `brig` with no subcommand: show the cheat-sheet instead of
    # walking into the dispatch table with command=None.
    if args.command is None:
        _print_quickstart()
        sys.exit(0)

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
        lifecycle_run, lifecycle_inspect, lifecycle_control,
        system_cmd, policy_cmd,
        network_cmd, config_cmd, image_cmd, convenience_cmd,
        secrets_cmd, watchdog_cmd,
    )

    # Two-level dispatch: keyed by (group, verb) for grouped commands,
    # plain str for top-level commands. Kept as a table (rather than
    # argparse `set_defaults(func=...)`) so command-module imports stay
    # lazy — `brig --version` / `brig --help` don't pay the import cost.
    dispatch: dict = {
        "run": lifecycle_run.cmd_run,
        "ps": lifecycle_inspect.cmd_list,

        # cell *
        ("cell", "list"): lifecycle_inspect.cmd_list,
        ("cell", "inspect"): lifecycle_inspect.cmd_inspect,
        ("cell", "export"): lifecycle_inspect.cmd_export,
        ("cell", "mount-scan"): lifecycle_inspect.cmd_mount_scan,
        ("cell", "stop"): lifecycle_control.cmd_stop,
        ("cell", "kill"): lifecycle_control.cmd_kill,
        ("cell", "start"): lifecycle_control.cmd_start,
        ("cell", "restart"): lifecycle_control.cmd_restart,
        ("cell", "pause"): lifecycle_control.cmd_pause,
        ("cell", "unpause"): lifecycle_control.cmd_unpause,
        ("cell", "attach"): lifecycle_control.cmd_attach,
        ("cell", "shell"): lifecycle_control.cmd_shell,
        ("cell", "wait"): lifecycle_control.cmd_wait,
        ("cell", "rm"): lifecycle_control.cmd_rm,
        ("cell", "preflight"): lifecycle_inspect.cmd_preflight,
        ("cell", "rename"): lifecycle_control.cmd_rename,
        ("cell", "exec"): lifecycle_control.cmd_exec,
        ("cell", "files"): lifecycle_inspect.cmd_files,
        ("cell", "read"): lifecycle_inspect.cmd_read,
        ("cell", "logs"): lifecycle_inspect.cmd_logs,
        ("cell", "top"): lifecycle_inspect.cmd_top,
        ("cell", "diff"): lifecycle_inspect.cmd_diff,
        ("cell", "stats"): lifecycle_inspect.cmd_stats,
        ("cell", "cp"): lifecycle_inspect.cmd_cp,
        ("cell", "network"): network_cmd.cmd_network,
        ("cell", "events"): network_cmd.cmd_events,
        ("cell", "ingress"): lifecycle_inspect.cmd_ingress,
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
        ("system", "stats"): _stats_dispatch,
        ("system", "prune"): system_cmd.cmd_prune,
        ("system", "watchdog"): watchdog_cmd.cmd_watchdog,
        ("system", "history"): system_cmd.cmd_history,
    }

    if args.command in {"cell", "image", "system"}:
        sub_attr = f"{args.command}_command"
        sub_value = getattr(args, sub_attr)
        # argparse stores the literal alias (e.g. "ls"); map it to the
        # canonical verb the dispatch table is keyed on.
        if args.command == "cell":
            sub_value = _CELL_VERB_ALIASES.get(sub_value, sub_value)
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
