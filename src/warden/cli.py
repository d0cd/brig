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

    p_policy = sub.add_parser("policy", help="Policy management")
    p_policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_validate = p_policy_sub.add_parser("validate", help="Validate policy file")
    p_validate.add_argument("file", nargs="?", help="Policy file path")
    p_test = p_policy_sub.add_parser("test", help="Test a domain against policy")
    p_test.add_argument("domain", help="Domain to test")
    p_test.add_argument("--path", default="/", help="Path to test")
    p_test.add_argument("--method", default="GET", help="HTTP method")

    # Tor subcommands.
    p_tor = sub.add_parser("tor", help="Tor bridge management")
    p_tor_sub = p_tor.add_subparsers(dest="tor_command", required=True)
    p_tor_sub.add_parser("start", help="Start Tor stack")
    p_tor_sub.add_parser("stop", help="Stop Tor stack")
    p_tor_sub.add_parser("status", help="Tor stack status")

    return parser


def main() -> None:
    """Warden CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    configure_logging(debug=args.debug, quiet=args.quiet)

    from warden import proxy, health, tor
    from brig.policy import policy as brig_policy

    dispatch = {
        "start": lambda: _cmd_start(proxy),
        "stop": lambda: (proxy.stop(), 0)[1],
        "restart": lambda: (proxy.stop(), _cmd_start(proxy))[1],
        "status": lambda: _cmd_status(proxy),
        "reload": lambda: (0 if proxy.reload_policy() else 1),
    }

    if args.command == "policy":
        exit_code = _handle_policy(args, brig_policy)
    elif args.command == "tor":
        exit_code = _handle_tor(args, tor)
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


def _handle_policy(args: object, policy_mod: object) -> int:
    """Handle policy subcommands using brig.policy."""
    from pathlib import Path
    cmd = getattr(args, "policy_command", "")
    if cmd == "validate":
        file_path = getattr(args, "file", None)
        policy_path = Path(file_path) if file_path else Path("/cells/network-policy.json")
        try:
            pol = policy_mod.load_policy_file(policy_path)  # type: ignore[attr-defined]
        except (ValueError, FileNotFoundError) as e:
            print(f"ERROR: {e}")
            return 1
        errors = policy_mod.validate_policy(pol)  # type: ignore[attr-defined]
        if errors:
            print("Validation FAILED:")
            for e in errors:
                print(f"  ERROR: {e}")
            return 1
        print("Validation OK")
        return 0
    elif cmd == "test":
        from pathlib import Path
        try:
            pol = policy_mod.load_policy_file(Path("/cells/network-policy.json"))  # type: ignore[attr-defined]
        except (ValueError, FileNotFoundError) as e:
            print(f"ERROR: {e}")
            return 1
        # Simple allow/deny check.
        from brig.network.validation import is_suspicious_domain
        domain = getattr(args, "domain", "")
        for rule in pol.get("deny", []):
            if isinstance(rule, str) and rule == domain:
                print(f"BLOCKED: Denied by rule: {rule}")
                return 1
        for rule in pol.get("allow", []):
            if isinstance(rule, str) and rule == domain:
                print(f"ALLOWED: Matched rule: {rule}")
                return 0
        print("BLOCKED: Not in allowlist")
        return 1
    return 1


def _handle_tor(args: object, tor_mod: object) -> int:
    """Handle tor subcommands."""
    cmd = getattr(args, "tor_command", "")
    if cmd == "stop":
        tor_mod.stop_tor_stack()  # type: ignore[attr-defined]
        return 0
    elif cmd == "status":
        running = tor_mod.is_tor_running()  # type: ignore[attr-defined]
        print(f"Tor: {'running' if running else 'not running'}")
        return 0
    return 1
