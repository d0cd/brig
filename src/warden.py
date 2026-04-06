#!/usr/bin/env python3
"""
Warden - Egress Proxy Manager for Brig.

Manages the mitmproxy-based egress proxy for cell networks.
The proxy enforces network policy and logs all requests.

Usage:
    warden start              Start the proxy container
    warden stop               Stop the proxy container
    warden restart            Restart the proxy container
    warden status             Show proxy status
    warden reload             Reload policy (send SIGHUP)
    warden logs               Show proxy logs
    warden logs prune         Clean old log files
    warden join <cell>        Connect proxy to cell network
    warden leave <cell>       Disconnect proxy from cell network
    warden health             Check proxy health
    warden stats [cell]       Show request metrics
    warden policy validate    Validate policy file
    warden policy test        Test if domain is allowed
    warden tor start          Start Tor container
    warden tor stop           Stop Tor container
    warden tor status         Show Tor status

Security hardening applied:
    - No new privileges (--security-opt no-new-privileges)
    - Drop all capabilities (--cap-drop ALL)
    - Non-root user (mitmproxy image drops to uid 1000)
    - Resource limits (memory, CPU, PIDs)
    - Image pinned by digest
"""

import argparse
import fnmatch
import gzip
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from brig.config import CELL_NAME_PATTERN

# Version information.
VERSION = "0.2.0"

# Proxy container configuration.
CONTAINER_NAME = "warden"
# Pin mitmproxy image by digest for reproducibility and security.
# mitmproxy/mitmproxy:10.1.1 (pulled 2026-02-02)
IMAGE = "docker.io/mitmproxy/mitmproxy@sha256:39ef4ec493d10bf07c71189961c7797b24c445e640ee133efba87fea80d19268"

# Tor container configuration.
TOR_CONTAINER_NAME = "warden-tor"
# Pin Tor image by digest for reproducibility and security.
# osminogin/tor-simple - minimal Tor SOCKS5 proxy (~8MB Alpine-based).
TOR_IMAGE = "docker.io/osminogin/tor-simple@sha256:4e64295fbafd856adc73d3ebc402b0d84598ddd278383ec1adaa32e4ecf0bea1"

# Privoxy container configuration (HTTP-to-SOCKS5 bridge for Tor).
PRIVOXY_CONTAINER_NAME = "warden-privoxy"
PRIVOXY_IMAGE = "docker.io/vimagick/privoxy@sha256:6f53634c62a05ee6a12e8c60fabf15a0d2f8e46e0d5fa42a0fa34b5e0d59f090"
PRIVOXY_PORT = 8118
TOR_SOCKS_PORT = 9050
PRIVOXY_CONFIG_HOST = Path.home() / ".brig/cells/addons/privoxy.conf"  # macOS side.

NETWORK = "proxy-external"

# Resource limits — sized for a single mitmproxy instance.
# 1g RAM: mitmproxy with typical request buffering and addon state.
# 1 CPU: proxy is I/O-bound, rarely needs more.
# 256 PIDs: mitmproxy workers + addon processes.
# 2048 FDs: mitmproxy holds concurrent TCP connections (soft 1024, hard 2048).
MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"
FD_LIMIT = "nofile=1024:2048"

# File paths.
POLICY_FILE = Path("/cells/network-policy.json")
LOG_DIR = Path("/var/log/brig/network")
METRICS_SOCKET = Path("/var/run/brig/metrics.sock")

# Blocked IP ranges for policy validation.
BLOCKED_NETWORKS = [
    # RFC1918 private ranges.
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Localhost.
    ipaddress.ip_network("127.0.0.0/8"),
    # Link-local.
    ipaddress.ip_network("169.254.0.0/16"),
    # CGNAT.
    ipaddress.ip_network("100.64.0.0/10"),
    # Benchmarking.
    ipaddress.ip_network("198.18.0.0/15"),
    # Reserved.
    ipaddress.ip_network("240.0.0.0/4"),
    # "This network" (used in SSRF attacks).
    ipaddress.ip_network("0.0.0.0/8"),
    # Multicast.
    ipaddress.ip_network("224.0.0.0/4"),
    # IPv6 equivalents.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # IPv4-mapped IPv6 (bypass for all IPv4 blocked ranges).
    ipaddress.ip_network("::ffff:0:0/96"),
    # Documentation prefix (should never appear in production).
    ipaddress.ip_network("2001:db8::/32"),
    # IPv6 multicast.
    ipaddress.ip_network("ff00::/8"),
]


DEFAULT_TIMEOUT = 30  # Default subprocess timeout in seconds.

def validate_cell_name(name: str) -> bool:
    """Validate cell name against safe pattern."""
    return bool(CELL_NAME_PATTERN.match(name))


# Log levels.
LOG_LEVEL_DEBUG = 0
LOG_LEVEL_INFO = 1
LOG_LEVEL_WARN = 2
LOG_LEVEL_ERROR = 3

# Current log level (set based on --debug flag).
LOG_LEVEL = LOG_LEVEL_INFO

# Quiet mode suppresses DEBUG and INFO messages.
QUIET = False

# Color output.
COLOR_ENABLED = sys.stderr.isatty()


def colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color codes."""
    if not COLOR_ENABLED:
        return text
    colors = {
        "red": "\033[31m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "gray": "\033[90m",
        "green": "\033[32m",
    }
    if color in colors:
        return f"{colors[color]}{text}\033[0m"
    return text


def log(level: int, msg: str, level_name: str = None) -> None:
    """Log a message at the specified level."""
    if level < LOG_LEVEL:
        return
    if QUIET and level < LOG_LEVEL_WARN:
        return
    level_names = {
        LOG_LEVEL_DEBUG: "DEBUG",
        LOG_LEVEL_INFO: "INFO",
        LOG_LEVEL_WARN: "WARN",
        LOG_LEVEL_ERROR: "ERROR",
    }
    level_colors = {
        LOG_LEVEL_DEBUG: "gray",
        LOG_LEVEL_INFO: "blue",
        LOG_LEVEL_WARN: "yellow",
        LOG_LEVEL_ERROR: "red",
    }
    name = level_name or level_names.get(level, "INFO")
    color = level_colors.get(level, None)
    if COLOR_ENABLED and color:
        prefix = colorize(f"[{name}]", color)
    else:
        prefix = f"[{name}]"
    print(f"{prefix} {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    """Print debug message if debug mode is enabled."""
    log(LOG_LEVEL_DEBUG, msg)


def info(msg: str) -> None:
    """Print info message."""
    log(LOG_LEVEL_INFO, msg)


def output(msg: str) -> None:
    """Print output message (respects quiet mode)."""
    if not QUIET:
        print(msg)


def warn(msg: str) -> None:
    """Print warning message."""
    log(LOG_LEVEL_WARN, msg)


def print_error(msg: str, suggestion: str = None) -> None:
    """Print error message to stderr (does not exit)."""
    print(f"ERROR: {msg}", file=sys.stderr)
    if suggestion:
        print(f"  Suggestion: {suggestion}", file=sys.stderr)


def run(cmd: list[str], check: bool = True, capture: bool = False,
        timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a command with timeout protection.

    Args:
        cmd: Command and arguments to run.
        check: Raise CalledProcessError on non-zero exit.
        capture: Capture stdout/stderr.
        timeout: Timeout in seconds. Use None for no timeout.

    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout.
        subprocess.CalledProcessError: If check=True and command fails.
    """
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout
    )


def is_running() -> bool:
    """Check if proxy container is running."""
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name=^{CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    # Exact match to avoid matching warden-tor.
    return CONTAINER_NAME in result.stdout.split()


def container_exists() -> bool:
    """Check if proxy container exists (running or stopped)."""
    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name=^{CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    # Exact match to avoid matching warden-tor.
    return CONTAINER_NAME in result.stdout.split()


def tor_running() -> bool:
    """Check if Tor container is running."""
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name=^{TOR_CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    return TOR_CONTAINER_NAME in result.stdout.split()


def tor_exists() -> bool:
    """Check if Tor container exists (running or stopped)."""
    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name=^{TOR_CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    return TOR_CONTAINER_NAME in result.stdout.split()


def privoxy_running() -> bool:
    """Check if Privoxy container is running."""
    result = run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name=^{PRIVOXY_CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    return PRIVOXY_CONTAINER_NAME in result.stdout.split()


def privoxy_exists() -> bool:
    """Check if Privoxy container exists (running or stopped)."""
    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name=^{PRIVOXY_CONTAINER_NAME}$"],
        check=False,
        capture=True
    )
    return PRIVOXY_CONTAINER_NAME in result.stdout.split()


def _get_container_ip(container_name: str, network: str = NETWORK) -> str:
    """Get container IP on a specific network."""
    # Validate network name to prevent Go template injection.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', network):
        return ""
    result = run(
        ["podman", "inspect", container_name, "--format", "json"],
        check=False,
        capture=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return ""
    try:
        data = json.loads(result.stdout)
        if not data:
            return ""
        networks = data[0].get("NetworkSettings", {}).get("Networks", {})
        net_info = networks.get(network, {})
        return net_info.get("IPAddress", "")
    except (json.JSONDecodeError, IndexError, KeyError):
        return ""


def _is_warden_tor_mode() -> bool:
    """Check if Warden is running with upstream proxy mode (Tor routing)."""
    if not is_running():
        return False
    result = run(
        ["podman", "inspect", CONTAINER_NAME, "--format", "json"],
        check=False,
        capture=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    try:
        data = json.loads(result.stdout)
        if not data:
            return False
        # Check command args for --mode upstream.
        args = data[0].get("Config", {}).get("Cmd", [])
        return any("upstream:" in str(a) for a in args)
    except (json.JSONDecodeError, IndexError, KeyError):
        return False


def get_proxy_ip(network: str) -> str:
    """Get proxy IP on a specific network."""
    # Validate network name to prevent Go template injection.
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', network):
        return ""
    result = run(
        ["podman", "inspect", CONTAINER_NAME, "--format", "json"],
        check=False,
        capture=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return ""
    try:
        data = json.loads(result.stdout)
        if not data:
            return ""
        networks = data[0].get("NetworkSettings", {}).get("Networks", {})
        net_info = networks.get(network, {})
        return net_info.get("IPAddress", "")
    except (json.JSONDecodeError, IndexError, KeyError):
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
            warn(f"Failed to connect to {network}: {result.stderr}")

    if connected > 0:
        info(f"Reconnected to {connected} cell network(s)")
    return connected


def load_policy() -> dict:
    """Load policy from file."""
    if not POLICY_FILE.exists():
        return {}
    try:
        with open(POLICY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print_error(f"Failed to load policy: {e}")
        return {}


def preflight_validate() -> tuple[bool, list[str]]:
    """Validate all prerequisites before starting proxy.

    Returns (success, list of error messages).
    """
    errors = []

    # Check required files exist and are readable.
    required_files = [
        ("/cells/addons/enforce.py", "Policy enforcement addon"),
        ("/cells/addons/logger.py", "Logging addon"),
        ("/cells/network-policy.json", "Network policy"),
    ]

    for path, name in required_files:
        p = Path(path)
        if not p.exists():
            errors.append(f"{name} not found at {path}")
        elif not os.access(path, os.R_OK):
            errors.append(f"{name} at {path} is not readable")

    # Validate policy file is valid JSON.
    if POLICY_FILE.exists():
        try:
            with open(POLICY_FILE, "r") as f:
                json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Network policy is invalid JSON: {e}")
        except IOError as e:
            errors.append(f"Cannot read network policy: {e}")

    # Check log directory exists and is writable.
    if LOG_DIR.exists():
        if not os.access(LOG_DIR, os.W_OK):
            errors.append(f"Log directory {LOG_DIR} is not writable")
    else:
        # Try to create it.
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
        except (IOError, OSError) as e:
            errors.append(f"Cannot create log directory {LOG_DIR}: {e}")

    # Check proxy-external network exists.
    result = run(["podman", "network", "exists", NETWORK], check=False, capture=True)
    if result.returncode != 0:
        errors.append(f"Network '{NETWORK}' does not exist. Create with: podman network create {NETWORK}")

    return len(errors) == 0, errors


def cmd_preflight() -> int:
    """Run preflight validation checks."""
    print("Running preflight validation...")
    success, errors = preflight_validate()

    if success:
        print("All preflight checks passed")
        return 0
    else:
        print("Preflight checks FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1


def cmd_watchdog(interval: int = 30, max_restarts: int = 5) -> int:
    """Run watchdog that monitors and restarts proxy if it crashes.

    Args:
        interval: Check interval in seconds.
        max_restarts: Maximum consecutive restarts before giving up.

    This runs in the foreground and should be run as a background service.
    """
    if interval <= 0:
        print_error("Interval must be positive")
        return 1
    if max_restarts <= 0:
        print_error("Max restarts must be positive")
        return 1

    consecutive_restarts = 0
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        info(f"Watchdog received signal {signum}, shutting down...")
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    info(f"Watchdog started (interval={interval}s, max_restarts={max_restarts})")

    while running:
        try:
            if is_running():
                # Proxy is running, reset restart counter.
                if consecutive_restarts > 0:
                    info("Proxy recovered, resetting restart counter")
                    consecutive_restarts = 0
            else:
                warn(f"Proxy not running! Attempting restart ({consecutive_restarts + 1}/{max_restarts})")

                if consecutive_restarts >= max_restarts:
                    print_error(f"Max restarts ({max_restarts}) exceeded. Giving up.")
                    print_error("Manual intervention required. Check: warden status")
                    return 1

                # Try to start the proxy.
                result = cmd_start()
                if result == 0:
                    info("Proxy restarted successfully")
                else:
                    consecutive_restarts += 1
                    print_error(f"Failed to restart proxy (exit code {result})")

            # Sleep in small increments to allow signal handling.
            for _ in range(interval):
                if not running:
                    break
                time.sleep(1)

        except Exception as e:
            print_error(f"Watchdog error: {e}")
            time.sleep(interval)

    info("Watchdog stopped")
    return 0


def cmd_start() -> int:
    """Start the proxy container."""
    if is_running():
        print("Proxy is already running")
        return 0

    # Remove existing stopped container.
    if container_exists():
        run(["podman", "rm", "-f", CONTAINER_NAME], check=False)

    # Run comprehensive preflight validation.
    success, errors = preflight_validate()
    if not success:
        print_error("Preflight validation failed:")
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print_error("Run 'warden preflight' for detailed diagnostics")
        return 1

    # Check for optional addons.
    optional_addons = [
        "/cells/addons/ratelimit.py",
        "/cells/addons/metrics.py",
        "/cells/addons/health.py",
        "/cells/addons/notifier.py",
        "/cells/addons/canary.py",
    ]

    addon_args = ["-s", "/addons/enforce.py", "-s", "/addons/logger.py"]
    for addon in optional_addons:
        result = run(["test", "-f", addon], check=False)
        if result.returncode == 0:
            addon_name = Path(addon).name
            addon_args.extend(["-s", f"/addons/{addon_name}"])
            info(f"Loading addon: {addon_name}")

    # Build podman run command with security hardening.
    cmd = [
        "podman", "run", "-d",
        "--name", CONTAINER_NAME,
        "--runtime", "crun",
        "--network", NETWORK,

        # Security hardening.
        "--entrypoint", "mitmdump",
        "--cap-drop", "ALL",
        # Note: NET_BIND_SERVICE not needed since 8080 is unprivileged.
        "--security-opt", "no-new-privileges",
        "--read-only",                     # Read-only root filesystem.
        # 64 MB /tmp: mitmproxy uses /tmp for request body buffering.
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        # 32 MB state: mitmproxy certificates and session data.
        "--tmpfs", "/home/mitmproxy/.mitmproxy:rw,noexec,nosuid,size=32m",
        "--user", "mitmproxy",             # Run as non-root user.

        # Resource limits.
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,
        "--ulimit", FD_LIMIT,

        # Mount volumes.
        "-v", "/var/log/brig/network:/logs:rw",
        "-v", "/var/run/brig:/var/run/cells:rw",
        "-v", "/cells/addons:/addons:ro",
        "-v", "/cells/network-policy.json:/policy.json:ro",

        # Use digest-pinned image.
        IMAGE,

        # mitmdump arguments.
        "--listen-host", "0.0.0.0",
        "--listen-port", "8080",     # Standard HTTP proxy port (unprivileged).
        # Disable mitmproxy's built-in global IP blocking; enforce addon
        # handles this with a comprehensive BLOCKED_NETWORKS list covering
        # RFC1918, CGNAT, multicast, IPv4-mapped IPv6, and more.
        "--set", "block_global=false",
    ]

    # Chain through Privoxy->Tor if the Tor stack is running.
    if privoxy_running():
        privoxy_ip = _get_container_ip(PRIVOXY_CONTAINER_NAME)
        if privoxy_ip:
            cmd.extend(["--mode", f"upstream:http://{privoxy_ip}:{PRIVOXY_PORT}"])
            info("Tor routing enabled via Privoxy bridge")

    cmd.extend(addon_args)

    try:
        # 120s timeout: image pull can be slow on first run.
        run(cmd, timeout=120)
        info("Proxy started")

        # Wait up to 5s (10 × 0.5s) for proxy to become ready.
        for _ in range(10):
            time.sleep(0.5)
            if is_running():
                reconnect_to_cell_networks()
                return 0

        warn("Proxy may not have started correctly")
        return 1

    except subprocess.TimeoutExpired:
        print_error("Proxy start timed out (check network and image availability)")
        return 1
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to start proxy: {e}")
        return 1


def cmd_stop() -> int:
    """Stop the proxy container."""
    if not container_exists():
        print("Proxy is not running")
        return 0

    try:
        # -t 10: give mitmproxy 10s to drain connections gracefully.
        # timeout=30: outer deadline covers stop + cleanup overhead.
        run(["podman", "stop", "-t", "10", CONTAINER_NAME], timeout=30)
        run(["podman", "rm", CONTAINER_NAME])
        print("Proxy stopped")
        return 0
    except subprocess.TimeoutExpired:
        print_error("Stop command timed out. Try: podman kill warden")
        return 1
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to stop proxy: {e}")
        return 1


def cmd_restart() -> int:
    """Restart the proxy container."""
    result = cmd_stop()
    if result != 0:
        print_error("Failed to stop proxy, aborting restart")
        return result
    return cmd_start()


def cmd_status() -> int:
    """Show proxy status."""
    if is_running():
        print("Proxy: running")
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
    """Reload policy by sending SIGHUP to mitmproxy.

    Validates the policy file before sending the reload signal.
    If validation fails, the old policy remains in effect.
    """
    if not is_running():
        print_error("Proxy is not running. Start with: warden start")
        return 1

    # Validate policy before reloading to prevent breaking all cells.
    if not POLICY_FILE.exists():
        print_error(f"Policy file not found: {POLICY_FILE}. Create it at ~/.brig/cells/network-policy.json")
        return 1

    try:
        with open(POLICY_FILE, "r") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        print_error(
            f"Policy file contains invalid JSON: {e}",
            "Fix the policy file and try again. Current policy remains in effect."
        )
        return 1
    except IOError as e:
        print_error(f"Cannot read policy file: {e}")
        return 1

    # Basic structural checks.
    if not isinstance(policy, dict):
        print_error(
            "Policy must be a JSON object",
            "Fix the policy file and try again. Current policy remains in effect."
        )
        return 1

    for key in ("allow", "deny"):
        if key in policy and not isinstance(policy[key], list):
            print_error(
                f"Policy '{key}' must be a list",
                "Fix the policy file and try again. Current policy remains in effect."
            )
            return 1

    info("Policy validation passed")

    try:
        # Send SIGHUP to the container's main process (PID 1).
        run(["podman", "kill", "-s", "HUP", CONTAINER_NAME])
        info("Policy reload signal sent")
        return 0
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to reload policy: {e}")
        return 1


def cmd_logs() -> int:
    """Show proxy logs."""
    if not container_exists():
        print_error("Proxy container does not exist")
        return 1

    try:
        # No timeout for log following - user exits with Ctrl+C.
        run(["podman", "logs", "-f", CONTAINER_NAME], check=False, timeout=None)
        return 0
    except KeyboardInterrupt:
        return 0


def cmd_logs_prune(days: int = 7, size_mb: int = None) -> int:
    """Clean old log files.

    Args:
        days: Delete logs older than N days (default 7 — matches logrotate retention).
        size_mb: Target total size in MB. If specified, delete oldest files until under limit.
    """
    if days < 0:
        print_error("Days must be non-negative")
        return 1

    if not LOG_DIR.exists():
        print("No log directory found")
        return 0

    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    compressed = 0
    bytes_freed = 0

    # Collect all log files with metadata.
    all_files = []
    for pattern in ["*.jsonl", "*.jsonl.gz"]:
        for log_file in LOG_DIR.glob(pattern):
            try:
                stat = log_file.stat()
                all_files.append({
                    "path": log_file,
                    "mtime": datetime.fromtimestamp(stat.st_mtime),
                    "size": stat.st_size,
                })
            except (IOError, OSError):
                pass

    # Phase 1: Remove files older than cutoff.
    for f in all_files[:]:
        if f["mtime"] < cutoff:
            try:
                bytes_freed += f["size"]
                f["path"].unlink()
                removed += 1
                all_files.remove(f)
            except (IOError, OSError) as e:
                warn(f"Failed to remove {f['path']}: {e}")

    # Phase 2: Compress files older than 1 day (keep today's logs uncompressed for tailing).
    compress_cutoff = datetime.now() - timedelta(days=1)
    for f in all_files:
        if f["path"].suffix == ".jsonl" and f["mtime"] < compress_cutoff:
            try:
                gz_path = f["path"].with_suffix(".jsonl.gz")
                if not gz_path.exists():
                    tmp_gz = gz_path.with_suffix(".gz.tmp")
                    try:
                        with open(f["path"], "rb") as f_in:
                            with gzip.open(tmp_gz, "wb") as f_out:
                                f_out.writelines(f_in)
                        tmp_gz.rename(gz_path)
                        f["path"].unlink()
                        compressed += 1
                        # Update file info for size calculation.
                        f["path"] = gz_path
                        f["size"] = gz_path.stat().st_size
                    except (IOError, OSError):
                        if tmp_gz.exists():
                            tmp_gz.unlink()
                        raise
            except (IOError, OSError) as e:
                warn(f"Failed to compress {f['path']}: {e}")

    # Phase 3: Size-based pruning if specified.
    if size_mb is not None:
        target_bytes = size_mb * 1024 * 1024
        total_size = sum(f["size"] for f in all_files)

        if total_size > target_bytes:
            # Sort by mtime (oldest first) for deletion.
            all_files.sort(key=lambda f: f["mtime"])

            for f in all_files:
                if total_size <= target_bytes:
                    break
                try:
                    bytes_freed += f["size"]
                    total_size -= f["size"]
                    f["path"].unlink()
                    removed += 1
                except (IOError, OSError) as e:
                    warn(f"Failed to remove {f['path']}: {e}")

            print(f"Size pruning: reduced to {total_size / 1024 / 1024:.1f} MB (target: {size_mb} MB)")

    print(f"Removed {removed} files, compressed {compressed} files")
    if bytes_freed > 0:
        print(f"Freed {bytes_freed / 1024 / 1024:.1f} MB")
    return 0


def cmd_join(cell_name: str) -> int:
    """Connect proxy to a cell's network."""
    if not validate_cell_name(cell_name):
        print_error(f"Invalid cell name: {cell_name}")
        return 1
    if not is_running():
        print_error("Warden is not running")
        return 1

    network_name = f"brig-{cell_name}"

    result = run(["podman", "network", "exists", network_name], check=False)
    if result.returncode != 0:
        print_error(f"Network {network_name} does not exist")
        return 1

    try:
        run(["podman", "network", "connect", network_name, CONTAINER_NAME])
        print(f"Proxy connected to {network_name}")
        return 0
    except subprocess.CalledProcessError as e:
        if "already" in str(e).lower():
            print(f"Proxy already connected to {network_name}")
            return 0
        print_error(f"Failed to connect: {e}")
        return 1


def cmd_leave(cell_name: str) -> int:
    """Disconnect proxy from a cell's network."""
    if not validate_cell_name(cell_name):
        print_error(f"Invalid cell name: {cell_name}")
        return 1
    if not is_running():
        print_error("Warden is not running")
        return 1

    network_name = f"brig-{cell_name}"

    try:
        run(["podman", "network", "disconnect", network_name, CONTAINER_NAME])
        print(f"Proxy disconnected from {network_name}")
        return 0
    except subprocess.CalledProcessError:
        print(f"Proxy was not connected to {network_name}")
        return 0


def cmd_health(format_json: bool = False) -> int:
    """Check proxy health."""
    checks = {}

    # Check 1: Container running.
    checks["container_running"] = is_running()

    # Check 2: mitmproxy responsive (try TCP connect to port 8080).
    checks["mitmproxy_responsive"] = False
    if checks["container_running"]:
        sock = None
        try:
            proxy_ip = get_proxy_ip(NETWORK)
            if proxy_ip:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)  # Health checks should be fast; 2s is generous.
                result = sock.connect_ex((proxy_ip, 8080))
                checks["mitmproxy_responsive"] = result == 0
        except (OSError, socket.error):
            pass
        finally:
            if sock:
                sock.close()

    # Check 3: Policy loaded.
    checks["policy_loaded"] = POLICY_FILE.exists()

    # Check 4: Log directory writable.
    checks["log_writable"] = False
    try:
        test_file = LOG_DIR / ".health_check"
        test_file.touch()
        test_file.unlink()
        checks["log_writable"] = True
    except (IOError, OSError):
        pass

    # Check 5: Metrics socket available.
    checks["metrics_available"] = METRICS_SOCKET.exists()

    # Check 6: Health endpoint responsive (if health addon loaded).
    checks["health_endpoint"] = False
    if checks["container_running"]:
        try:
            proxy_ip = get_proxy_ip(NETWORK)
            if proxy_ip:
                import urllib.request
                # Port 8089: health addon's dedicated HTTP endpoint.
                req = urllib.request.Request(f"http://{proxy_ip}:8089/health")
                with urllib.request.urlopen(req, timeout=2.0) as resp:  # nosec B310
                    if resp.status == 200:
                        checks["health_endpoint"] = True
        except (OSError, urllib.error.URLError, ValueError):
            # Health endpoint is optional.
            pass

    # Overall health.
    critical_checks = ["container_running", "mitmproxy_responsive", "policy_loaded"]
    healthy = all(checks.get(c, False) for c in critical_checks)
    checks["healthy"] = healthy

    if format_json:
        print(json.dumps(checks, indent=2))
    else:
        for check, status in checks.items():
            status_str = "OK" if status else "FAIL"
            print(f"{check}: {status_str}")

    return 0 if healthy else 1


def cmd_stats(cell_name: str = None, format_json: bool = False) -> int:
    """Show request metrics."""
    if not METRICS_SOCKET.exists():
        print_error("Metrics socket not available. Ensure metrics.py addon is loaded.")
        return 1

    # Cap response size to prevent OOM from misbehaving socket.
    # 10 MB is generous: typical metrics for 100 cells is ~200 KB.
    max_response_bytes = 10 * 1024 * 1024

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(METRICS_SOCKET))
        sock.settimeout(5.0)  # Metrics aggregation may take a moment.

        if cell_name:
            sock.sendall(f"cell:{cell_name}".encode("utf-8"))
        else:
            sock.sendall(b"all")

        # Read response in loop to handle large payloads.
        chunks = []
        total_bytes = 0
        while True:
            chunk = sock.recv(65536)  # 64 KB recv buffer — standard socket read size.
            if not chunk:
                break
            if total_bytes + len(chunk) > max_response_bytes:
                print_error("Metrics response exceeds size limit")
                return 1
            total_bytes += len(chunk)
            chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8")

        try:
            data = json.loads(response)
        except json.JSONDecodeError as e:
            print_error(f"Failed to parse metrics response: {e}")
            return 1

        if not isinstance(data, dict):
            print_error("Metrics response must be a JSON object")
            return 1

        if "error" in data:
            error_msg = str(data.get("error", "unknown"))[:500]
            print_error(f"Metrics error: {error_msg}")
            return 1

        if format_json:
            print(json.dumps(data, indent=2))
        else:
            if "cells" in data:
                # All cells.
                for name, metrics in data["cells"].items():
                    print(f"\n{name}:")
                    _print_metrics(metrics)
            elif "metrics" in data:
                # Single cell.
                print(f"\n{data['cell']}:")
                _print_metrics(data["metrics"])

        return 0

    except socket.error as e:
        print_error(f"Failed to connect to metrics socket: {e}")
        return 1
    except json.JSONDecodeError as e:
        print_error(f"Failed to parse metrics response: {e}")
        return 1
    finally:
        sock.close()


def _print_metrics(metrics: dict) -> None:
    """Print metrics in human-readable format."""
    print(f"  Requests:     {metrics.get('total_requests', 0)}")
    print(f"  Blocked:      {metrics.get('blocked_requests', 0)}")
    print(f"  Rate Limited: {metrics.get('rate_limited_requests', 0)}")
    print(f"  Errors:       {metrics.get('error_requests', 0)}")
    print(f"  Bytes In:     {metrics.get('bytes_sent', 0) / 1024:.1f} KB")
    print(f"  Bytes Out:    {metrics.get('bytes_received', 0) / 1024:.1f} KB")
    print(f"  Latency:      p50={metrics.get('latency_p50_ms', 0):.1f}ms "
          f"p95={metrics.get('latency_p95_ms', 0):.1f}ms "
          f"p99={metrics.get('latency_p99_ms', 0):.1f}ms")


def cmd_policy_validate(file_path: str = None) -> int:
    """Validate policy file."""
    policy_path = Path(file_path) if file_path else POLICY_FILE

    if not policy_path.exists():
        print_error(f"Policy file not found: {policy_path}")
        return 1

    try:
        with open(policy_path, "r") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        print_error(f"Invalid JSON: {e}")
        return 1

    errors = []
    warnings = []

    # Validate allow rules.
    allow_rules = policy.get("allow", [])
    if not isinstance(allow_rules, list):
        errors.append("'allow' must be a list")
    else:
        for i, rule in enumerate(allow_rules):
            rule_errors = _validate_rule(rule, f"allow[{i}]")
            errors.extend(rule_errors)

    # Validate deny rules.
    deny_rules = policy.get("deny", [])
    if not isinstance(deny_rules, list):
        errors.append("'deny' must be a list")
    else:
        for i, rule in enumerate(deny_rules):
            rule_errors = _validate_rule(rule, f"deny[{i}]")
            errors.extend(rule_errors)

    # Validate rate limits.
    rate_limits = policy.get("rate_limits", {})
    if rate_limits:
        default = rate_limits.get("default", {})
        if default:
            if "rate" in default and not isinstance(default["rate"], (int, float)):
                errors.append("rate_limits.default.rate must be a number")
            if "burst" in default and not isinstance(default["burst"], int):
                errors.append("rate_limits.default.burst must be an integer")

    # Validate log filter.
    log_filter = policy.get("log_filter", {})
    if log_filter:
        sample_rate = log_filter.get("sample_rate", 1.0)
        if not isinstance(sample_rate, (int, float)):
            errors.append("log_filter.sample_rate must be a number")
        elif not (0 <= sample_rate <= 1):
            errors.append("log_filter.sample_rate must be between 0 and 1")

    # Validate notifications.
    notifications = policy.get("notifications", {})
    if notifications:
        webhook_url = notifications.get("webhook_url", "")
        if webhook_url:
            if not webhook_url.startswith(("http://", "https://")):
                errors.append("notifications.webhook_url must be a valid HTTP(S) URL")
            else:
                from urllib.parse import urlparse
                parsed = urlparse(webhook_url)
                if not parsed.hostname:
                    errors.append("notifications.webhook_url must have a valid hostname")

    # Check for overlapping rules.
    all_domains = []
    for rule in allow_rules:
        if isinstance(rule, str):
            all_domains.append(rule)
        elif isinstance(rule, dict):
            all_domains.append(rule.get("domain", ""))

    for domain in set(all_domains):
        count = all_domains.count(domain)
        if count > 1:
            warnings.append(f"Domain '{domain}' appears {count} times in allow rules")

    # Report results.
    if errors:
        print("Validation FAILED:")
        for error in errors:
            print(f"  ERROR: {error}")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 1
    else:
        print(f"Validation OK: {len(allow_rules)} allow rules, {len(deny_rules)} deny rules")
        # Show rate limit config summary.
        rate_limits = policy.get("rate_limits", {})
        if rate_limits:
            default = rate_limits.get("default", {})
            # Display defaults match DEFAULT_NETWORK_POLICY (100/s, burst 500).
            default_rate = default.get("rate", 100)
            default_burst = default.get("burst", 500)
            print(f"  Rate limits: {default_rate}/s (burst: {default_burst})")
            cells = rate_limits.get("cells", {})
            if cells:
                print(f"  Cell overrides: {len(cells)}")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        return 0


def _validate_rule(rule, context: str) -> list[str]:
    """Validate a single policy rule."""
    errors = []

    if isinstance(rule, str):
        # Simple domain pattern.
        if not rule:
            errors.append(f"{context}: empty domain")
        elif rule.startswith("*."):
            # Wildcard pattern.
            if len(rule) < 3:
                errors.append(f"{context}: invalid wildcard pattern '{rule}'")
    elif isinstance(rule, dict):
        # Complex rule with path/method.
        domain = rule.get("domain", "")
        if not domain:
            errors.append(f"{context}: missing 'domain' field")

        paths = rule.get("paths")
        if paths is not None and not isinstance(paths, list):
            errors.append(f"{context}: 'paths' must be a list")

        methods = rule.get("methods")
        if methods is not None:
            if not isinstance(methods, list):
                errors.append(f"{context}: 'methods' must be a list")
            else:
                valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
                for method in methods:
                    if method.upper() not in valid_methods:
                        errors.append(f"{context}: invalid method '{method}'")
    else:
        errors.append(f"{context}: invalid rule type (must be string or object)")

    return errors


def cmd_policy_test(domain: str, path: str = "/", method: str = "GET") -> int:
    """Test if a domain would be allowed by current policy."""
    policy = load_policy()
    if not policy:
        print_error("Could not load policy")
        return 1

    # Check deny rules first.
    for rule in policy.get("deny", []):
        if _matches_rule(rule, domain, path, method):
            print(f"BLOCKED: Denied by rule: {_rule_str(rule)}")
            return 1

    # Check allow rules.
    for rule in policy.get("allow", []):
        if _matches_rule(rule, domain, path, method):
            print(f"ALLOWED: Matched rule: {_rule_str(rule)}")
            return 0

    # Default deny.
    print("BLOCKED: Not in allowlist")
    return 1


def _matches_rule(rule, domain: str, path: str, method: str) -> bool:
    """Check if request matches a rule."""
    if isinstance(rule, str):
        return _matches_domain(rule, domain)
    elif isinstance(rule, dict):
        if not _matches_domain(rule.get("domain", ""), domain):
            return False

        paths = rule.get("paths")
        if paths is not None:
            if not any(fnmatch.fnmatch(path, p) for p in paths):
                return False

        methods = rule.get("methods")
        if methods is not None:
            if method.upper() not in [m.upper() for m in methods]:
                return False

        return True
    return False


def _matches_domain(pattern: str, domain: str) -> bool:
    """Check if domain matches pattern.

    Wildcard patterns match subdomains only:
        *.example.com matches foo.example.com, NOT example.com itself.
    """
    pattern = pattern.lower()
    domain = domain.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        # Wildcard matches subdomains only, NOT the bare domain.
        # Dot-boundary check prevents "notexample.com" matching ".example.com".
        return domain.endswith(suffix) and len(domain) > len(suffix)
    else:
        return domain == pattern


def _rule_str(rule) -> str:
    """Get string representation of a rule."""
    if isinstance(rule, str):
        return rule
    elif isinstance(rule, dict):
        parts = [rule.get("domain", "")]
        if rule.get("paths"):
            parts.append(f"paths={rule['paths']}")
        if rule.get("methods"):
            parts.append(f"methods={rule['methods']}")
        return " ".join(parts)
    return str(rule)


def cmd_logs_compact(cell_name: str = None, strategy: str = "delete", bucket: str = "hourly",
                     samples_per_hour: int = 10, archive_path: str = None,
                     older_than: str = "7d", model: str = None) -> int:
    # samples_per_hour=10: enough to spot patterns without keeping every request.
    """Compact log files using the specified strategy.

    Strategies:
        delete: Simply delete logs older than retention period.
        aggregate: Aggregate by (host, path, method, status) per time bucket.
        sample: Keep N random samples per time bucket.
        archive: Compress and move to archive location.
        ai: Use Claude API to intelligently summarize while preserving security events.
    """
    import random
    import shutil
    from collections import defaultdict

    if not LOG_DIR.exists():
        print("No log directory found")
        return 0

    # Validate cell name to prevent glob injection.
    if cell_name and not validate_cell_name(cell_name):
        print_error(f"Invalid cell name: {cell_name}")
        return 1

    # Parse older_than duration.
    duration_match = re.match(r"(\d+)([dhm])", older_than)
    if not duration_match:
        print_error(f"Invalid duration format: {older_than}")
        return 1

    duration_val = int(duration_match.group(1))
    if duration_val <= 0:
        print_error("Duration must be positive")
        return 1
    duration_unit = duration_match.group(2)
    if duration_unit == "d":
        cutoff = datetime.now() - timedelta(days=duration_val)
    elif duration_unit == "h":
        cutoff = datetime.now() - timedelta(hours=duration_val)
    elif duration_unit == "m":
        cutoff = datetime.now() - timedelta(minutes=duration_val)

    # Find log files to compact.
    pattern = f"{cell_name}.jsonl" if cell_name else "*.jsonl"
    log_files = list(LOG_DIR.glob(pattern))
    if not log_files:
        print("No log files to compact")
        return 0

    compacted = 0
    entries_processed = 0

    for log_file in log_files:
        try:
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            if mtime >= cutoff:
                continue  # Skip recent files.

            entries = []

            with open(log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            if not entries:
                continue

            entries_processed += len(entries)

            if strategy == "delete":
                log_file.unlink()
                compacted += 1

            elif strategy == "aggregate":
                # Aggregate by time bucket.
                aggregated = defaultdict(lambda: {
                    "count": 0, "blocked_count": 0, "error_count": 0,
                    "total_bytes": 0, "total_ms": 0.0, "latencies": []
                })

                for entry in entries:
                    ts = entry.get("ts", "")
                    if bucket == "hourly":
                        bucket_key = ts[:13] + ":00:00Z"  # YYYY-MM-DDTHH:00:00Z
                    else:  # daily
                        bucket_key = ts[:10] + "T00:00:00Z"

                    key = (bucket_key, entry.get("host", ""), entry.get("method", ""),
                           entry.get("status", 0))
                    agg = aggregated[key]
                    agg["count"] += 1
                    if entry.get("blocked"):
                        agg["blocked_count"] += 1
                    if entry.get("status", 200) >= 400 or entry.get("error"):
                        agg["error_count"] += 1
                    agg["total_bytes"] += entry.get("bytes", 0) + entry.get("request_bytes", 0)
                    agg["total_ms"] += entry.get("ms", 0)
                    agg["latencies"].append(entry.get("ms", 0))

                # Write compact file.
                compact_file = log_file.with_suffix(".compact.jsonl")
                with open(compact_file, "w") as f:
                    for (bucket_ts, host, method, status), agg in aggregated.items():
                        latencies = sorted(agg["latencies"])
                        # 95th percentile — standard SRE latency indicator.
                        p95_idx = int(len(latencies) * 0.95) if latencies else 0
                        compact_entry = {
                            "bucket": bucket_ts,
                            "host": host,
                            "method": method,
                            "status": status,
                            "count": agg["count"],
                            "blocked_count": agg["blocked_count"],
                            "error_count": agg["error_count"],
                            "total_bytes": agg["total_bytes"],
                            "avg_ms": round(agg["total_ms"] / agg["count"], 2) if agg["count"] else 0,
                            "p95_ms": round(latencies[p95_idx], 2) if latencies else 0,
                        }
                        f.write(json.dumps(compact_entry) + "\n")

                log_file.unlink()
                compacted += 1

            elif strategy == "sample":
                # Keep N random samples per hour bucket.
                buckets = defaultdict(list)
                for entry in entries:
                    ts = entry.get("ts", "")
                    bucket_key = ts[:13]  # YYYY-MM-DDTHH
                    buckets[bucket_key].append(entry)

                sample_file = log_file.with_suffix(".sample.jsonl")
                with open(sample_file, "w") as f:
                    for bucket_key, bucket_entries in buckets.items():
                        samples = random.sample(bucket_entries,
                                                min(samples_per_hour, len(bucket_entries)))
                        for entry in samples:
                            f.write(json.dumps(entry) + "\n")

                log_file.unlink()
                compacted += 1

            elif strategy == "archive":
                if not archive_path:
                    print_error("--archive-path required for archive strategy")
                    return 1

                if ".." in archive_path.split("/"):
                    print_error("Archive path must not contain path traversal")
                    return 1
                archive_dir = Path(archive_path)
                try:
                    archive_dir = archive_dir.resolve()
                except OSError:
                    print_error(f"Invalid archive path: {archive_path}")
                    return 1
                if not archive_dir.is_absolute():
                    archive_dir = Path.cwd() / archive_dir
                archive_dir.mkdir(parents=True, exist_ok=True)

                # Compress and move.
                gz_name = f"{log_file.stem}.{datetime.now().strftime('%Y%m%d')}.jsonl.gz"
                gz_path = archive_dir / gz_name

                with open(log_file, "rb") as f_in:
                    with gzip.open(gz_path, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

                log_file.unlink()
                compacted += 1

        except (IOError, OSError) as e:
            warn(f"Failed to process {log_file}: {e}")

    print(f"Compacted {compacted} files ({entries_processed} entries) using '{strategy}' strategy")
    return 0


def cmd_logs_compact_ai(cell_name: str, older_than: str = "24h", model: str = None) -> int:
    """Compact logs using AI-powered summarization.

    Uses Claude API to intelligently summarize logs while preserving
    security-relevant events (blocked, errors, rate-limited, cert issues).

    Requires:
        - API key at /run/secrets/anthropic-key or ANTHROPIC_API_KEY env var
        - Per-cell config in policy file (optional, for customization)
    """
    if not cell_name:
        print_error("Cell name required for AI compaction")
        return 1

    # Parse older_than duration.
    duration_match = re.match(r"(\d+)([dhm])", older_than)
    if not duration_match:
        print_error(f"Invalid duration format: {older_than}")
        return 1

    duration_val = int(duration_match.group(1))
    duration_unit = duration_match.group(2)
    if duration_unit == "d":
        older_than_hours = duration_val * 24
    elif duration_unit == "h":
        older_than_hours = duration_val
    elif duration_unit == "m":
        older_than_hours = max(1, duration_val // 60)

    try:
        # Import summarizer module.
        sys.path.insert(0, str(Path(__file__).parent / "addons"))
        from summarizer import compact_cell_logs

        # Use per-cell policy directory.
        policy_dir = Path("/var/run/brig/policies")

        result = compact_cell_logs(
            cell_name=cell_name,
            log_dir=LOG_DIR,
            policy_dir=policy_dir,
            older_than_hours=older_than_hours,
        )

        if "error" in result:
            print_error(result['error'])
            return 1

        if "message" in result:
            print(result["message"])
            return 0

        print(f"AI Log Compaction for '{cell_name}':")
        print(f"  Compacted entries: {result.get('compacted_entries', 0)}")
        print(f"  Preserved (security): {result.get('preserved_entries', 0)}")
        print(f"  Recent entries kept: {result.get('recent_entries_kept', 0)}")
        print(f"  Summary file: {result.get('summary_file', 'N/A')}")
        print(f"  Archive file: {result.get('archive_file', 'N/A')}")

        if result.get("ai_enabled"):
            if result.get("ai_error"):
                print(f"  AI status: {result['ai_error']}")
            else:
                print("  AI status: Summary generated")
        else:
            print("  AI status: Disabled (enable in cell policy)")

        return 0

    except ImportError as e:
        print_error(f"Failed to import summarizer module: {e}")
        return 1
    except Exception as e:
        print_error(f"AI compaction failed: {e}")
        return 1


def cmd_logs_export(cell_name: str = None, format_type: str = "jsonl",
                    output_file: str = None, days: int = 7) -> int:
    """Export log files in various formats.

    Formats:
        jsonl: Line-delimited JSON (default).
        csv: Comma-separated values.
        parquet: Columnar format for big data tools.
    """
    if not LOG_DIR.exists():
        print("No log directory found")
        return 0

    # Validate cell name to prevent glob injection.
    if cell_name and not validate_cell_name(cell_name):
        print_error(f"Invalid cell name: {cell_name}")
        return 1

    # Find log files.
    pattern = f"{cell_name}.jsonl" if cell_name else "*.jsonl"
    log_files = list(LOG_DIR.glob(pattern))
    if not log_files:
        print("No log files to export")
        return 0

    cutoff = datetime.now() - timedelta(days=days)

    # Collect all entries.
    all_entries = []
    for log_file in log_files:
        try:
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            if mtime < cutoff:
                continue

            with open(log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            all_entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except (IOError, OSError):
            continue

    if not all_entries:
        print("No entries to export")
        return 0

    # Determine output.
    if output_file:
        if ".." in output_file.split("/"):
            print_error("Output path must not contain path traversal")
            return 1
        out_path = Path(output_file).resolve()
    else:
        suffix = {"jsonl": ".jsonl", "csv": ".csv", "parquet": ".parquet"}[format_type]
        out_path = Path(f"warden-logs-export{suffix}")

    if format_type == "jsonl":
        with open(out_path, "w") as f:
            for entry in all_entries:
                f.write(json.dumps(entry) + "\n")

    elif format_type == "csv":
        import csv

        # Flatten entries and get all unique keys.
        flat_entries = []
        all_keys = set()
        for entry in all_entries:
            flat = {}
            for k, v in entry.items():
                if isinstance(v, (dict, list)):
                    flat[k] = json.dumps(v)
                else:
                    flat[k] = v
                all_keys.add(k)
            flat_entries.append(flat)

        # Standard columns first, then extras alphabetically.
        standard_cols = ["ts", "cell", "method", "host", "path", "status", "bytes", "ms", "blocked"]
        columns = [c for c in standard_cols if c in all_keys]
        columns.extend(sorted(all_keys - set(columns)))

        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(flat_entries)

    elif format_type == "parquet":
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            print_error("pyarrow required for parquet export. Install with: pip install pyarrow")
            return 1

        # Convert to columnar format.
        columns = {}
        for entry in all_entries:
            for k, v in entry.items():
                if k not in columns:
                    columns[k] = []

        for entry in all_entries:
            for k in columns:
                val = entry.get(k)
                if isinstance(val, (dict, list)):
                    val = json.dumps(val)
                columns[k].append(val)

        table = pa.table(columns)
        pq.write_table(table, out_path)

    print(f"Exported {len(all_entries)} entries to {out_path}")
    return 0


def _cleanup_tor_stack() -> None:
    """Remove Tor and Privoxy containers and config file."""
    for name in [PRIVOXY_CONTAINER_NAME, TOR_CONTAINER_NAME]:
        run(["podman", "rm", "-f", name], check=False, capture=True)
    try:
        PRIVOXY_CONFIG_HOST.unlink(missing_ok=True)
    except OSError:
        pass


def _wait_for_port(container_name: str, port: int, timeout_secs: int = 30) -> bool:
    """Wait until a TCP port is reachable on a container."""
    for i in range(timeout_secs):
        time.sleep(1)
        ip = _get_container_ip(container_name)
        if ip:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                if sock.connect_ex((ip, port)) == 0:
                    return True
            except (OSError, socket.error):
                pass
            finally:
                if sock:
                    sock.close()
        if i % 5 == 0 and i > 0:
            info(f"Waiting for {container_name}:{port}... ({i}s)")
    return False


def cmd_tor_start() -> int:
    """Start the Tor stack (Tor + Privoxy bridge).

    Architecture: Cell -> Warden (policy) -> Privoxy (HTTP->SOCKS5) -> Tor -> Internet.
    Cells cannot reach Privoxy or Tor directly (different networks).
    """
    # Idempotent: both running means nothing to do.
    if tor_running() and privoxy_running():
        print("Tor stack is already running")
        return 0

    # Recovery: only Tor up but Privoxy down.
    if tor_running() and not privoxy_running():
        info("Tor running, recovering Privoxy bridge")
    else:
        # Remove any stopped containers.
        if tor_exists():
            run(["podman", "rm", "-f", TOR_CONTAINER_NAME], check=False)
        if privoxy_exists():
            run(["podman", "rm", "-f", PRIVOXY_CONTAINER_NAME], check=False)

        # Start Tor container with hardening.
        tor_cmd = [
            "podman", "run", "-d",
            "--name", TOR_CONTAINER_NAME,
            "--runtime", "crun",
            "--network", NETWORK,

            # Security hardening.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--tmpfs", "/var/lib/tor:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/run:rw,noexec,nosuid,size=4m",

            # Resource limits.
            "--memory", "256m",
            "--cpus", "0.5",
            "--pids-limit", "64",

            TOR_IMAGE,
        ]

        try:
            run(tor_cmd, timeout=120)
            info("Tor container started")
        except subprocess.TimeoutExpired:
            print_error("Tor start timed out (check network and image availability)")
            _cleanup_tor_stack()
            return 1
        except subprocess.CalledProcessError as e:
            print_error(f"Failed to start Tor: {e}")
            _cleanup_tor_stack()
            return 1

        # Wait for Tor SOCKS5 port up to 60s for bootstrap.
        if not _wait_for_port(TOR_CONTAINER_NAME, TOR_SOCKS_PORT, timeout_secs=60):
            print_error("Tor did not become ready in 60s")
            _cleanup_tor_stack()
            return 1

        info(f"Tor SOCKS5 is ready on port {TOR_SOCKS_PORT}")

    # Write Privoxy config atomically.
    # Podman DNS resolves 'warden-tor' within proxy-external network.
    privoxy_conf = (
        f"forward-socks5t / {TOR_CONTAINER_NAME}:{TOR_SOCKS_PORT} .\n"
        f"listen-address 0.0.0.0:{PRIVOXY_PORT}\n"
        "toggle 0\n"
    )
    try:
        PRIVOXY_CONFIG_HOST.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = PRIVOXY_CONFIG_HOST.with_suffix(".tmp")
        with open(tmp_file, "w") as f:
            f.write(privoxy_conf)
        tmp_file.rename(PRIVOXY_CONFIG_HOST)
    except (IOError, OSError) as e:
        print_error(f"Failed to write Privoxy config: {e}")
        _cleanup_tor_stack()
        return 1

    # Remove stopped Privoxy container if recovery path.
    if privoxy_exists():
        run(["podman", "rm", "-f", PRIVOXY_CONTAINER_NAME], check=False)

    # Start Privoxy container.
    privoxy_cmd = [
        "podman", "run", "-d",
        "--name", PRIVOXY_CONTAINER_NAME,
        "--runtime", "crun",
        "--network", NETWORK,

        # Security hardening.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/var/log/privoxy:rw,noexec,nosuid,size=16m",
        "--tmpfs", "/var/run/privoxy:rw,noexec,nosuid,size=1m",

        # Mount Privoxy config read-only.
        "-v", f"{PRIVOXY_CONFIG_HOST}:/etc/privoxy/config:ro",

        # Resource limits.
        "--memory", "128m",
        "--cpus", "0.25",
        "--pids-limit", "32",

        PRIVOXY_IMAGE,
    ]

    try:
        run(privoxy_cmd, timeout=60)
        info("Privoxy bridge started")
    except subprocess.TimeoutExpired:
        print_error("Privoxy start timed out")
        _cleanup_tor_stack()
        return 1
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to start Privoxy: {e}")
        _cleanup_tor_stack()
        return 1

    # Wait for Privoxy port (8118) up to 15s.
    if not _wait_for_port(PRIVOXY_CONTAINER_NAME, PRIVOXY_PORT, timeout_secs=15):
        print_error("Privoxy did not become ready in 15s")
        _cleanup_tor_stack()
        return 1

    print("Tor is ready. Restart Warden to route through Tor: warden restart")
    return 0


def cmd_tor_stop() -> int:
    """Stop the Tor stack (Privoxy + Tor)."""
    if not tor_exists() and not privoxy_exists():
        print("Tor stack is not running")
        return 0

    # Stop Privoxy first (depends on Tor).
    if privoxy_exists():
        try:
            run(["podman", "stop", "-t", "5", PRIVOXY_CONTAINER_NAME], timeout=15)
            run(["podman", "rm", PRIVOXY_CONTAINER_NAME])
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            run(["podman", "rm", "-f", PRIVOXY_CONTAINER_NAME], check=False)

    # Stop Tor.
    if tor_exists():
        try:
            run(["podman", "stop", "-t", "10", TOR_CONTAINER_NAME], timeout=30)
            run(["podman", "rm", TOR_CONTAINER_NAME])
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            run(["podman", "rm", "-f", TOR_CONTAINER_NAME], check=False)

    # Delete Privoxy config file.
    try:
        PRIVOXY_CONFIG_HOST.unlink(missing_ok=True)
    except OSError:
        pass

    print("Tor stopped. Restart Warden to disable Tor: warden restart")
    return 0


def cmd_tor_status() -> int:
    """Show Tor stack status."""
    tor_up = tor_running()
    privoxy_up = privoxy_running()
    warden_upstream = _is_warden_tor_mode()

    # Show component status.
    print(f"Tor:     {'running' if tor_up else 'stopped'}")
    print(f"Privoxy: {'running' if privoxy_up else 'stopped'}")
    print(f"Warden:  {'upstream mode (Tor active)' if warden_upstream else 'direct mode'}")

    if tor_up and privoxy_up:
        print(f"\nChain: cell -> warden:8080 -> privoxy:{PRIVOXY_PORT} -> tor:{TOR_SOCKS_PORT} -> internet")

        if not warden_upstream:
            warn("Warden must be restarted to activate Tor routing: warden restart")
        else:
            print("\nVerify with: brig exec <cell> curl https://check.torproject.org/api/ip")

        return 0
    elif tor_up and not privoxy_up:
        warn("Tor is running but Privoxy bridge is down. Run: warden tor start")
        return 1
    elif tor_exists() or privoxy_exists():
        print("\nTor stack: stopped")
        return 1
    else:
        print("\nTor stack: not created")
        print("Start with: warden tor start")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Warden - Egress proxy manager for Brig",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"warden {VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress info messages")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Basic commands.
    subparsers.add_parser("start", help="Start the proxy")
    subparsers.add_parser("stop", help="Stop the proxy")
    subparsers.add_parser("restart", help="Restart the proxy")
    subparsers.add_parser("status", help="Show proxy status")
    subparsers.add_parser("reload", help="Reload policy")
    subparsers.add_parser("preflight", help="Run preflight validation checks")

    # Watchdog command.
    p_watchdog = subparsers.add_parser("watchdog", help="Monitor and auto-restart proxy")
    p_watchdog.add_argument("--interval", type=int, default=30,
                            help="Check interval in seconds (default: 30)")
    p_watchdog.add_argument("--max-restarts", type=int, default=5,
                            help="Max consecutive restarts before giving up (default: 5)")

    # Logs commands.
    p_logs = subparsers.add_parser("logs", help="Show or manage proxy logs")
    logs_sub = p_logs.add_subparsers(dest="logs_command")
    p_logs_prune = logs_sub.add_parser("prune", help="Clean old log files")
    p_logs_prune.add_argument("--days", type=int, default=7, help="Delete logs older than N days")
    p_logs_prune.add_argument("--size", type=int, help="Target total size in MB (delete oldest files until under limit)")

    p_logs_compact = logs_sub.add_parser("compact", help="Compact log files")
    p_logs_compact.add_argument("cell_name", nargs="?", help="Specific cell (required for ai strategy)")
    p_logs_compact.add_argument("--strategy", choices=["delete", "aggregate", "sample", "archive", "ai"],
                                default="delete", help="Compaction strategy (ai uses Claude API)")
    p_logs_compact.add_argument("--bucket", choices=["hourly", "daily"], default="hourly",
                                help="Time bucket for aggregate strategy")
    p_logs_compact.add_argument("--samples-per-hour", type=int, default=10,
                                help="Samples to keep per hour for sample strategy")
    p_logs_compact.add_argument("--archive-path", help="Archive directory for archive strategy")
    p_logs_compact.add_argument("--older-than", default="7d",
                                help="Only compact files older than this (e.g., 7d, 24h)")
    p_logs_compact.add_argument("--model", help="Claude model for ai strategy (default: claude-haiku-3)")

    p_logs_export = logs_sub.add_parser("export", help="Export logs to file")
    p_logs_export.add_argument("cell_name", nargs="?", help="Specific cell (optional)")
    p_logs_export.add_argument("--format", dest="format_type", choices=["jsonl", "csv", "parquet"],
                               default="jsonl", help="Export format")
    p_logs_export.add_argument("--output", "-o", help="Output file path")
    p_logs_export.add_argument("--days", type=int, default=7, help="Export logs from last N days")

    # Network commands.
    p_join = subparsers.add_parser("join", help="Connect to cell network")
    p_join.add_argument("cell_name", help="Name of the cell")

    p_leave = subparsers.add_parser("leave", help="Disconnect from cell network")
    p_leave.add_argument("cell_name", help="Name of the cell")

    # Health and stats.
    p_health = subparsers.add_parser("health", help="Check proxy health")
    p_health.add_argument("--json", dest="format_json", action="store_true", help="Output as JSON")

    p_stats = subparsers.add_parser("stats", help="Show request metrics")
    p_stats.add_argument("cell_name", nargs="?", help="Specific cell (optional)")
    p_stats.add_argument("--json", dest="format_json", action="store_true", help="Output as JSON")

    # Policy commands.
    p_policy = subparsers.add_parser("policy", help="Policy management")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)

    p_policy_validate = policy_sub.add_parser("validate", help="Validate policy file")
    p_policy_validate.add_argument("file", nargs="?", help="Policy file (default: /cells/network-policy.json)")

    p_policy_test = policy_sub.add_parser("test", help="Test if domain is allowed")
    p_policy_test.add_argument("domain", help="Domain to test")
    p_policy_test.add_argument("--path", default="/", help="Path to test")
    p_policy_test.add_argument("--method", default="GET", help="HTTP method")

    # Tor commands.
    p_tor = subparsers.add_parser("tor", help="Tor management")
    tor_sub = p_tor.add_subparsers(dest="tor_command", required=True)
    tor_sub.add_parser("start", help="Start Tor container")
    tor_sub.add_parser("stop", help="Stop Tor container")
    tor_sub.add_parser("status", help="Show Tor status")

    args = parser.parse_args()

    # Configure log level from flags.
    global LOG_LEVEL, QUIET
    if args.debug:
        LOG_LEVEL = LOG_LEVEL_DEBUG
    if args.quiet:
        QUIET = True

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
    elif args.command == "preflight":
        sys.exit(cmd_preflight())
    elif args.command == "watchdog":
        sys.exit(cmd_watchdog(args.interval, args.max_restarts))
    elif args.command == "logs":
        if args.logs_command == "prune":
            sys.exit(cmd_logs_prune(args.days, args.size))
        elif args.logs_command == "compact":
            if args.cell_name and not validate_cell_name(args.cell_name):
                print_error(f"Invalid cell name: {args.cell_name}")
                sys.exit(1)
            if args.strategy == "ai":
                sys.exit(cmd_logs_compact_ai(
                    args.cell_name, args.older_than, args.model
                ))
            else:
                sys.exit(cmd_logs_compact(
                    args.cell_name, args.strategy, args.bucket,
                    args.samples_per_hour, args.archive_path, args.older_than
                ))
        elif args.logs_command == "export":
            if args.cell_name and not validate_cell_name(args.cell_name):
                print_error(f"Invalid cell name: {args.cell_name}")
                sys.exit(1)
            sys.exit(cmd_logs_export(
                args.cell_name, args.format_type, args.output, args.days
            ))
        else:
            sys.exit(cmd_logs())
    elif args.command == "join":
        if not validate_cell_name(args.cell_name):
            print_error(f"Invalid cell name: {args.cell_name}")
            sys.exit(1)
        sys.exit(cmd_join(args.cell_name))
    elif args.command == "leave":
        if not validate_cell_name(args.cell_name):
            print_error(f"Invalid cell name: {args.cell_name}")
            sys.exit(1)
        sys.exit(cmd_leave(args.cell_name))
    elif args.command == "health":
        sys.exit(cmd_health(args.format_json))
    elif args.command == "stats":
        if args.cell_name and not validate_cell_name(args.cell_name):
            print_error(f"Invalid cell name: {args.cell_name}")
            sys.exit(1)
        sys.exit(cmd_stats(args.cell_name, args.format_json))
    elif args.command == "policy":
        if args.policy_command == "validate":
            sys.exit(cmd_policy_validate(args.file))
        elif args.policy_command == "test":
            sys.exit(cmd_policy_test(args.domain, args.path, args.method))
    elif args.command == "tor":
        if args.tor_command == "start":
            sys.exit(cmd_tor_start())
        elif args.tor_command == "stop":
            sys.exit(cmd_tor_stop())
        elif args.tor_command == "status":
            sys.exit(cmd_tor_status())


if __name__ == "__main__":
    main()
