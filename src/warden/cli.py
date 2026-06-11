"""
Warden CLI — argparse setup and main entry point.
"""

from __future__ import annotations

import argparse
import sys

from brig.ops.logging import configure as configure_logging


def _build_parser() -> argparse.ArgumentParser:
    """Build the warden argument parser."""
    parser = argparse.ArgumentParser(
        prog="warden",
        description="Warden - Egress proxy manager for Brig",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--quiet", action="store_true", help="Suppress non-error output")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("start", help="Start the proxy")
    sub.add_parser("stop", help="Stop the proxy")
    sub.add_parser("restart", help="Restart the proxy")
    sub.add_parser("status", help="Show proxy status")
    sub.add_parser("reload", help="Reload proxy policy")
    sub.add_parser("preflight", help="Run preflight checks")

    p_health = sub.add_parser("health", help="Check proxy health")
    p_health.add_argument("--json", action="store_true", help="JSON output")

    p_logs = sub.add_parser("logs", help="View proxy logs")
    p_logs_sub = p_logs.add_subparsers(dest="logs_command")
    p_prune = p_logs_sub.add_parser("prune", help="Prune old logs")
    p_prune.add_argument("--days", type=int, default=7, help="Days to keep")
    p_prune.add_argument("--size", type=int, help="Max total size in MB")

    return parser


def main() -> None:
    """Warden CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    configure_logging(debug=args.debug, quiet=args.quiet)

    from warden import proxy, health
    dispatch = {
        "start": lambda: _cmd_start(proxy),
        "stop": lambda: (proxy.stop(), 0)[1],
        "restart": lambda: (proxy.stop(), _cmd_start(proxy))[1],
        "status": lambda: _cmd_status(proxy),
        "reload": lambda: (0 if proxy.reload_policy() else 1),
        "preflight": lambda: _cmd_preflight(),
        "health": lambda: _cmd_health(args, health),
    }

    if args.command == "logs":
        exit_code = _handle_logs(args)
    elif args.command in dispatch:
        exit_code = dispatch[args.command]()
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


def _cmd_start(proxy_mod: object) -> int:
    """Start the proxy."""
    success = proxy_mod.start()  # type: ignore[attr-defined]
    return 0 if success else 1


def _cmd_status(proxy_mod: object) -> int:
    """Show proxy status."""
    status = proxy_mod.get_status()  # type: ignore[attr-defined]
    if status.get("running"):
        print(f"Proxy: running (networks: {', '.join(status.get('networks', []))})")
    else:
        print("Proxy: not running")
    return 0


def _cmd_preflight() -> int:
    """Run preflight checks."""
    from warden.reconcile import reconcile_subnet_state
    errors = reconcile_subnet_state()
    if errors:
        print("Preflight FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("Preflight checks passed")
    return 0


def _cmd_health(args: object, health_mod: object) -> int:
    """Run health checks."""
    from pathlib import Path
    checks = health_mod.run_all_checks(  # type: ignore[attr-defined]
        policy_file=Path("/cells/network-policy.json"),
        log_dir=Path("/var/log/brig/network"),
    )
    ok = True
    for check in checks:
        status = "[OK]" if check.passed else "[FAIL]"
        print(f"  {status} {check.message}")
        if not check.passed:
            ok = False
    return 0 if ok else 1


def _handle_logs(args: object) -> int:
    """Handle logs subcommands."""
    from pathlib import Path
    from warden.logs import prune_logs
    cmd = getattr(args, "logs_command", None)
    if cmd == "prune":
        days = getattr(args, "days", 7)
        size = getattr(args, "size", None)
        stats = prune_logs(Path("/var/log/brig/network"), days=days, size_mb=size)
        print(f"Removed {stats['removed']} files, compressed {stats['compressed']}")
        return 0
    # Default: tail proxy logs (route through the Lima VM wrapper, since
    # podman runs inside the VM, not on the macOS host).
    from brig.vm.shell import vm_run_interactive
    return vm_run_interactive(["podman", "logs", "-f", "warden"])
