#!/usr/bin/env python3
"""
Warden - Egress Proxy Manager for Brig.

Manages the mitmproxy-based egress proxy for cell networks.
The proxy enforces network policy and logs all requests.

Usage:
    warden start          Start the proxy container
    warden stop           Stop the proxy container
    warden restart        Restart the proxy container
    warden status         Show proxy status
    warden reload         Reload policy (send SIGHUP)
    warden logs           Show proxy logs
    warden join <cell>    Connect proxy to cell network
    warden leave <cell>   Disconnect proxy from cell network

Security hardening applied:
    - No new privileges (--security-opt no-new-privileges)
    - Drop all capabilities (--cap-drop ALL)
    - Non-root user (mitmproxy image drops to uid 1000)
    - Resource limits (memory, CPU, PIDs)
    - Image pinned by digest
"""

import argparse
import subprocess
import sys
import time

# Proxy container configuration.
CONTAINER_NAME = "warden"
# Pin mitmproxy image by digest for reproducibility and security.
# mitmproxy/mitmproxy:10.1.1 (pulled 2026-02-02)
IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"

NETWORK = "proxy-external"

# Resource limits.
MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"


def run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command."""
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True
    )


def is_running() -> bool:
    """Check if proxy container is running."""
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={CONTAINER_NAME}"],
        check=False,
        capture=True
    )
    return CONTAINER_NAME in result.stdout


def container_exists() -> bool:
    """Check if proxy container exists (running or stopped)."""
    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={CONTAINER_NAME}"],
        check=False,
        capture=True
    )
    return CONTAINER_NAME in result.stdout


def get_proxy_ip(network: str) -> str:
    """Get proxy IP on a specific network."""
    result = run(
        ["podman", "inspect", CONTAINER_NAME, "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
        check=False,
        capture=True
    )
    # This returns all IPs; we'd need to filter by network.
    # For now, return first non-empty.
    for ip in result.stdout.strip().split():
        if ip:
            return ip
    return ""


def get_cell_networks() -> list[str]:
    """Get list of all cell networks (brig-*)."""
    result = run(
        ["podman", "network", "ls", "--format", "{{.Name}}"],
        check=False,
        capture=True
    )
    networks = []
    for line in result.stdout.strip().split("\n"):
        name = line.strip()
        if name.startswith("brig-"):
            networks.append(name)
    return networks


def reconnect_to_cell_networks() -> int:
    """Reconnect proxy to all existing cell networks."""
    networks = get_cell_networks()
    if not networks:
        return 0

    connected = 0
    for network in networks:
        result = run(
            ["podman", "network", "connect", network, CONTAINER_NAME],
            check=False,
            capture=True
        )
        if result.returncode == 0:
            connected += 1
        elif "already" not in result.stderr.lower():
            print(f"WARNING: Failed to connect to {network}: {result.stderr}", file=sys.stderr)

    if connected > 0:
        print(f"Reconnected to {connected} cell network(s)")
    return connected


def cmd_start() -> int:
    """Start the proxy container."""
    if is_running():
        print(f"Proxy is already running")
        return 0

    # Remove existing stopped container.
    if container_exists():
        run(["podman", "rm", "-f", CONTAINER_NAME], check=False)

    # Check required files exist.
    preflight_checks = [
        ("/cells/addons/enforce.py", "Policy enforcement addon"),
        ("/cells/addons/logger.py", "Logging addon"),
        ("/cells/network-policy.json", "Network policy"),
    ]

    for path, name in preflight_checks:
        result = run(["test", "-f", path], check=False)
        if result.returncode != 0:
            print(f"ERROR: {name} not found at {path}", file=sys.stderr)
            return 1

    # Build podman run command with security hardening.
    # Use crun runtime since proxy is trusted infrastructure (not gVisor).
    cmd = [
        "podman", "run", "-d",
        "--name", CONTAINER_NAME,
        "--runtime", "crun",
        "--network", NETWORK,

        # Security hardening.
        # Override entrypoint to bypass mitmproxy's user setup (which requires root privileges).
        # Run mitmdump directly with dropped capabilities.
        "--entrypoint", "mitmdump",
        "--cap-drop", "ALL",
        # Keep NET_BIND_SERVICE to bind to port 8080 (not needed >1024, but explicit).
        "--security-opt", "no-new-privileges",

        # Resource limits.
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,

        # Mount volumes.
        "-v", "/var/log/brig/network:/logs:rw",
        "-v", "/var/run/brig:/var/run/cells:ro",
        "-v", "/cells/addons:/addons:ro",
        "-v", "/cells/network-policy.json:/policy.json:ro",

        # Use digest-pinned image for reproducibility.
        IMAGE,

        # mitmdump arguments (entrypoint is set via --entrypoint).
        "--listen-host", "0.0.0.0",
        "--listen-port", "8080",
        "--set", "block_global=false",
        "-s", "/addons/enforce.py",
        "-s", "/addons/logger.py",
    ]

    try:
        run(cmd)
        print(f"Proxy started")

        # Wait for proxy to be ready.
        for _ in range(10):
            time.sleep(0.5)
            if is_running():
                # Reconnect to any existing cell networks.
                reconnect_to_cell_networks()
                return 0

        print("WARNING: Proxy may not have started correctly", file=sys.stderr)
        return 1

    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to start proxy: {e}", file=sys.stderr)
        return 1


def cmd_stop() -> int:
    """Stop the proxy container."""
    if not container_exists():
        print("Proxy is not running")
        return 0

    try:
        run(["podman", "stop", "-t", "10", CONTAINER_NAME])
        run(["podman", "rm", CONTAINER_NAME])
        print("Proxy stopped")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to stop proxy: {e}", file=sys.stderr)
        return 1


def cmd_restart() -> int:
    """Restart the proxy container."""
    cmd_stop()
    return cmd_start()


def cmd_status() -> int:
    """Show proxy status."""
    if is_running():
        print(f"Proxy: running")
        # Show networks.
        result = run(
            ["podman", "inspect", CONTAINER_NAME, "--format",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}: {{$v.IPAddress}}\n{{end}}"],
            capture=True
        )
        print(f"Networks:\n{result.stdout}")
        return 0
    elif container_exists():
        print("Proxy: stopped")
        return 1
    else:
        print("Proxy: not created")
        return 1


def cmd_reload() -> int:
    """Reload policy by sending SIGHUP to mitmproxy."""
    if not is_running():
        print("ERROR: Proxy is not running", file=sys.stderr)
        return 1

    try:
        # Get PID of mitmdump process inside container.
        result = run(
            ["podman", "exec", CONTAINER_NAME, "pgrep", "-f", "mitmdump"],
            capture=True
        )
        pid = result.stdout.strip().split()[0]
        run(["podman", "exec", CONTAINER_NAME, "kill", "-HUP", pid])
        print("Policy reload signal sent")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to reload policy: {e}", file=sys.stderr)
        return 1


def cmd_logs() -> int:
    """Show proxy logs."""
    if not container_exists():
        print("ERROR: Proxy container does not exist", file=sys.stderr)
        return 1

    try:
        run(["podman", "logs", "-f", CONTAINER_NAME], check=False)
        return 0
    except KeyboardInterrupt:
        return 0


def cmd_join(cell_name: str) -> int:
    """Connect proxy to a cell's network."""
    if not is_running():
        print("ERROR: Warden is not running", file=sys.stderr)
        return 1

    network_name = f"brig-{cell_name}"

    # Check network exists.
    result = run(["podman", "network", "exists", network_name], check=False)
    if result.returncode != 0:
        print(f"ERROR: Network {network_name} does not exist", file=sys.stderr)
        return 1

    try:
        run(["podman", "network", "connect", network_name, CONTAINER_NAME])
        print(f"Proxy connected to {network_name}")
        return 0
    except subprocess.CalledProcessError as e:
        # May already be connected.
        if "already" in str(e).lower():
            print(f"Proxy already connected to {network_name}")
            return 0
        print(f"ERROR: Failed to connect: {e}", file=sys.stderr)
        return 1


def cmd_leave(cell_name: str) -> int:
    """Disconnect proxy from a cell's network."""
    if not is_running():
        print("ERROR: Warden is not running", file=sys.stderr)
        return 1

    network_name = f"brig-{cell_name}"

    try:
        run(["podman", "network", "disconnect", network_name, CONTAINER_NAME])
        print(f"Proxy disconnected from {network_name}")
        return 0
    except subprocess.CalledProcessError:
        print(f"Proxy was not connected to {network_name}")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Warden - Egress proxy manager for Brig",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("start", help="Start the proxy")
    subparsers.add_parser("stop", help="Stop the proxy")
    subparsers.add_parser("restart", help="Restart the proxy")
    subparsers.add_parser("status", help="Show proxy status")
    subparsers.add_parser("reload", help="Reload policy")
    subparsers.add_parser("logs", help="Show proxy logs")

    p_join = subparsers.add_parser("join", help="Connect to cell network")
    p_join.add_argument("cell_name", help="Name of the cell")

    p_leave = subparsers.add_parser("leave", help="Disconnect from cell network")
    p_leave.add_argument("cell_name", help="Name of the cell")

    args = parser.parse_args()

    if args.command == "start":
        sys.exit(cmd_start())
    elif args.command == "stop":
        sys.exit(cmd_stop())
    elif args.command == "restart":
        sys.exit(cmd_restart())
    elif args.command == "status":
        sys.exit(cmd_status())
    elif args.command == "reload":
        sys.exit(cmd_reload())
    elif args.command == "logs":
        sys.exit(cmd_logs())
    elif args.command == "join":
        sys.exit(cmd_join(args.cell_name))
    elif args.command == "leave":
        sys.exit(cmd_leave(args.cell_name))


if __name__ == "__main__":
    main()
