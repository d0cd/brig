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

# Version information.
VERSION = "0.1.0"

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

NETWORK = "proxy-external"

# Resource limits.
MEMORY_LIMIT = "1g"
CPU_LIMIT = "1"
PIDS_LIMIT = "256"

# File paths.
POLICY_FILE = Path("/cells/network-policy.json")
LOG_DIR = Path("/var/log/brig/network")
METRICS_SOCKET = Path("/var/run/brig/metrics.sock")

# Blocked IP ranges for policy validation.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("240.0.0.0/4"),
]


DEFAULT_TIMEOUT = 30  # Default subprocess timeout in seconds.


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
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={TOR_CONTAINER_NAME}"],
        check=False,
        capture=True
    )
    return TOR_CONTAINER_NAME in result.stdout


def tor_exists() -> bool:
    """Check if Tor container exists (running or stopped)."""
    result = run(
        ["podman", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={TOR_CONTAINER_NAME}"],
        check=False,
        capture=True
    )
    return TOR_CONTAINER_NAME in result.stdout


def get_proxy_ip(network: str) -> str:
    """Get proxy IP on a specific network."""
    result = run(
        ["podman", "inspect", CONTAINER_NAME, "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
        check=False,
        capture=True
    )
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


def load_policy() -> dict:
    """Load policy from file."""
    if not POLICY_FILE.exists():
        return {}
    try:
        with open(POLICY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"ERROR: Failed to load policy: {e}", file=sys.stderr)
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
    import signal as sig

    consecutive_restarts = 0
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        print(f"\nWatchdog received signal {signum}, shutting down...")
        running = False

    sig.signal(sig.SIGTERM, handle_signal)
    sig.signal(sig.SIGINT, handle_signal)

    print(f"Watchdog started (interval={interval}s, max_restarts={max_restarts})")

    while running:
        try:
            if is_running():
                # Proxy is running, reset restart counter.
                if consecutive_restarts > 0:
                    print("Proxy recovered, resetting restart counter")
                    consecutive_restarts = 0
            else:
                print(f"Proxy not running! Attempting restart ({consecutive_restarts + 1}/{max_restarts})")

                if consecutive_restarts >= max_restarts:
                    print(f"ERROR: Max restarts ({max_restarts}) exceeded. Giving up.", file=sys.stderr)
                    print("Manual intervention required. Check: warden status", file=sys.stderr)
                    return 1

                # Try to start the proxy.
                result = cmd_start()
                if result == 0:
                    print("Proxy restarted successfully")
                    consecutive_restarts += 1
                else:
                    print(f"Failed to restart proxy (exit code {result})", file=sys.stderr)
                    consecutive_restarts += 1

            # Sleep in small increments to allow signal handling.
            for _ in range(interval):
                if not running:
                    break
                time.sleep(1)

        except Exception as e:
            print(f"Watchdog error: {e}", file=sys.stderr)
            time.sleep(interval)

    print("Watchdog stopped")
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
        print("Preflight validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print("\nRun 'warden preflight' for detailed diagnostics", file=sys.stderr)
        return 1

    # Check for optional addons.
    optional_addons = [
        "/cells/addons/ratelimit.py",
        "/cells/addons/metrics.py",
        "/cells/addons/health.py",
        "/cells/addons/notifier.py",
    ]

    addon_args = ["-s", "/addons/enforce.py", "-s", "/addons/logger.py"]
    for addon in optional_addons:
        result = run(["test", "-f", addon], check=False)
        if result.returncode == 0:
            addon_name = Path(addon).name
            addon_args.extend(["-s", f"/addons/{addon_name}"])
            print(f"Loading addon: {addon_name}")

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
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # Writable /tmp.
        "--tmpfs", "/home/mitmproxy/.mitmproxy:rw,noexec,nosuid,size=32m",  # mitmproxy state.
        "--user", "mitmproxy",             # Run as non-root user.

        # Resource limits.
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,

        # Mount volumes.
        "-v", "/var/log/brig/network:/logs:rw",
        "-v", "/var/run/brig:/var/run/cells:rw",
        "-v", "/cells/addons:/addons:ro",
        "-v", "/cells/network-policy.json:/policy.json:ro",

        # Use digest-pinned image.
        IMAGE,

        # mitmdump arguments.
        "--listen-host", "0.0.0.0",
        "--listen-port", "8080",
        "--set", "block_global=false",
    ]

    # Note: Tor integration is available but requires additional setup.
    # mitmproxy doesn't support SOCKS5 upstream directly.
    # To use Tor, run a HTTP proxy (like privoxy) in front of Tor.
    # See: warden tor status for more info.

    cmd.extend(addon_args)

    try:
        # Podman run with -d returns quickly; use longer timeout for image pull.
        run(cmd, timeout=120)
        print("Proxy started")

        # Wait for proxy to be ready.
        for _ in range(10):
            time.sleep(0.5)
            if is_running():
                reconnect_to_cell_networks()
                return 0

        print("WARNING: Proxy may not have started correctly", file=sys.stderr)
        return 1

    except subprocess.TimeoutExpired:
        print("ERROR: Proxy start timed out (check network and image availability)",
              file=sys.stderr)
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
        # Stop timeout is 10s inside podman, allow extra time for the operation.
        run(["podman", "stop", "-t", "10", CONTAINER_NAME], timeout=30)
        run(["podman", "rm", CONTAINER_NAME])
        print("Proxy stopped")
        return 0
    except subprocess.TimeoutExpired:
        print("ERROR: Stop command timed out. Try: podman kill warden", file=sys.stderr)
        return 1
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
    """Reload policy by sending SIGHUP to mitmproxy."""
    if not is_running():
        print("ERROR: Proxy is not running", file=sys.stderr)
        return 1

    try:
        # Send SIGHUP to the container's main process (PID 1).
        run(["podman", "kill", "-s", "HUP", CONTAINER_NAME])
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
        # No timeout for log following - user exits with Ctrl+C.
        run(["podman", "logs", "-f", CONTAINER_NAME], check=False, timeout=None)
        return 0
    except KeyboardInterrupt:
        return 0


def cmd_logs_prune(days: int = 7, size_mb: int = None) -> int:
    """Clean old log files.

    Args:
        days: Delete logs older than N days.
        size_mb: Target total size in MB. If specified, delete oldest files until under limit.
    """
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
                print(f"WARNING: Failed to remove {f['path']}: {e}", file=sys.stderr)

    # Phase 2: Compress uncompressed files older than 1 day.
    compress_cutoff = datetime.now() - timedelta(days=1)
    for f in all_files:
        if f["path"].suffix == ".jsonl" and f["mtime"] < compress_cutoff:
            try:
                gz_path = f["path"].with_suffix(".jsonl.gz")
                if not gz_path.exists():
                    with open(f["path"], "rb") as f_in:
                        with gzip.open(gz_path, "wb") as f_out:
                            f_out.writelines(f_in)
                    f["path"].unlink()
                    compressed += 1
                    # Update file info for size calculation.
                    f["path"] = gz_path
                    f["size"] = gz_path.stat().st_size
            except (IOError, OSError) as e:
                print(f"WARNING: Failed to compress {f['path']}: {e}", file=sys.stderr)

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
                    print(f"WARNING: Failed to remove {f['path']}: {e}", file=sys.stderr)

            print(f"Size pruning: reduced to {total_size / 1024 / 1024:.1f} MB (target: {size_mb} MB)")

    print(f"Removed {removed} files, compressed {compressed} files")
    if bytes_freed > 0:
        print(f"Freed {bytes_freed / 1024 / 1024:.1f} MB")
    return 0


def cmd_join(cell_name: str) -> int:
    """Connect proxy to a cell's network."""
    if not is_running():
        print("ERROR: Warden is not running", file=sys.stderr)
        return 1

    network_name = f"brig-{cell_name}"

    result = run(["podman", "network", "exists", network_name], check=False)
    if result.returncode != 0:
        print(f"ERROR: Network {network_name} does not exist", file=sys.stderr)
        return 1

    try:
        run(["podman", "network", "connect", network_name, CONTAINER_NAME])
        print(f"Proxy connected to {network_name}")
        return 0
    except subprocess.CalledProcessError as e:
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


def cmd_health(format_json: bool = False) -> int:
    """Check proxy health."""
    checks = {}

    # Check 1: Container running.
    checks["container_running"] = is_running()

    # Check 2: mitmproxy responsive (try TCP connect to port 8080).
    checks["mitmproxy_responsive"] = False
    if checks["container_running"]:
        try:
            proxy_ip = get_proxy_ip(NETWORK)
            if proxy_ip:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((proxy_ip, 8080))
                sock.close()
                checks["mitmproxy_responsive"] = result == 0
        except Exception:
            pass

    # Check 3: Policy loaded.
    checks["policy_loaded"] = POLICY_FILE.exists()

    # Check 4: Log directory writable.
    checks["log_writable"] = False
    try:
        test_file = LOG_DIR / ".health_check"
        test_file.touch()
        test_file.unlink()
        checks["log_writable"] = True
    except Exception:
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
                req = urllib.request.Request(f"http://{proxy_ip}:8089/health")
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if resp.status == 200:
                        checks["health_endpoint"] = True
        except Exception:
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
        print("ERROR: Metrics socket not available. Ensure metrics.py addon is loaded.",
              file=sys.stderr)
        return 1

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(METRICS_SOCKET))
        sock.settimeout(5.0)

        if cell_name:
            sock.send(f"cell:{cell_name}".encode("utf-8"))
        else:
            sock.send(b"all")

        # Read response in loop to handle large payloads.
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        response = b"".join(chunks).decode("utf-8")

        data = json.loads(response)

        if "error" in data:
            print(f"ERROR: {data['error']}", file=sys.stderr)
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
        print(f"ERROR: Failed to connect to metrics socket: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse metrics response: {e}", file=sys.stderr)
        return 1


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
        print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
        return 1

    try:
        with open(policy_path, "r") as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
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
        if not (0 <= sample_rate <= 1):
            errors.append("log_filter.sample_rate must be between 0 and 1")

    # Validate notifications.
    notifications = policy.get("notifications", {})
    if notifications:
        webhook_url = notifications.get("webhook_url", "")
        if webhook_url and not webhook_url.startswith(("http://", "https://")):
            errors.append("notifications.webhook_url must be a valid HTTP(S) URL")

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
        print("ERROR: Could not load policy", file=sys.stderr)
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
    """Check if domain matches pattern."""
    pattern = pattern.lower()
    domain = domain.lower()

    if pattern.startswith("*."):
        suffix = pattern[1:]  # Keep the dot.
        return domain.endswith(suffix) or domain == pattern[2:]
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
    """Compact log files using the specified strategy.

    Strategies:
        delete: Simply delete logs older than retention period.
        aggregate: Aggregate by (host, path, method, status) per time bucket.
        sample: Keep N random samples per time bucket.
        archive: Compress and move to archive location.
        ai: Use Claude API to intelligently summarize while preserving security events.
    """
    from collections import defaultdict
    import random
    import shutil

    if not LOG_DIR.exists():
        print("No log directory found")
        return 0

    # Parse older_than duration.
    duration_match = re.match(r"(\d+)([dhm])", older_than)
    if not duration_match:
        print(f"ERROR: Invalid duration format: {older_than}", file=sys.stderr)
        return 1

    duration_val = int(duration_match.group(1))
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

            cell = log_file.stem
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
                    print("ERROR: --archive-path required for archive strategy", file=sys.stderr)
                    return 1

                archive_dir = Path(archive_path)
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
            print(f"WARNING: Failed to process {log_file}: {e}", file=sys.stderr)

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
        print("ERROR: Cell name required for AI compaction", file=sys.stderr)
        return 1

    # Parse older_than duration.
    duration_match = re.match(r"(\d+)([dhm])", older_than)
    if not duration_match:
        print(f"ERROR: Invalid duration format: {older_than}", file=sys.stderr)
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
        from summarizer import compact_cell_logs, SummarizationConfig, LogSummarizer

        # Use per-cell policy directory.
        policy_dir = Path("/var/run/brig/policies")

        result = compact_cell_logs(
            cell_name=cell_name,
            log_dir=LOG_DIR,
            policy_dir=policy_dir,
            older_than_hours=older_than_hours,
        )

        if "error" in result:
            print(f"ERROR: {result['error']}", file=sys.stderr)
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
        print(f"ERROR: Failed to import summarizer module: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: AI compaction failed: {e}", file=sys.stderr)
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
        out_path = Path(output_file)
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
            print("ERROR: pyarrow required for parquet export. Install with: pip install pyarrow",
                  file=sys.stderr)
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


def cmd_tor_start() -> int:
    """Start Tor container."""
    if tor_running():
        print("Tor is already running")
        return 0

    # Remove existing stopped container.
    if tor_exists():
        run(["podman", "rm", "-f", TOR_CONTAINER_NAME], check=False)

    cmd = [
        "podman", "run", "-d",
        "--name", TOR_CONTAINER_NAME,
        "--runtime", "crun",
        "--network", NETWORK,

        # Security hardening.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",

        # Resource limits.
        "--memory", "256m",
        "--cpus", "0.5",
        "--pids-limit", "64",

        # Use digest-pinned image.
        TOR_IMAGE,
    ]

    try:
        # Allow extra time for image pull.
        run(cmd, timeout=120)
        print("Tor started")

        # Wait for Tor to be ready (check if SOCKS5 port is listening).
        for i in range(30):
            time.sleep(1)
            if tor_running():
                # Get Tor container IP on proxy-external network.
                result = run(
                    ["podman", "inspect", TOR_CONTAINER_NAME, "--format",
                     "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                    check=False, capture=True
                )
                tor_ip = result.stdout.strip()
                if tor_ip:
                    # Check if port 9050 is reachable.
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2.0)
                        if sock.connect_ex((tor_ip, 9050)) == 0:
                            sock.close()
                            print(f"Tor is ready at {tor_ip}:9050")
                            print("Restart warden to use Tor: warden restart")
                            return 0
                        sock.close()
                    except Exception:
                        pass
            if i % 5 == 0 and i > 0:
                print(f"Waiting for Tor to bootstrap... ({i}s)")

        print("WARNING: Tor may not have started correctly", file=sys.stderr)
        return 1

    except subprocess.TimeoutExpired:
        print("ERROR: Tor start timed out (check network and image availability)",
              file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to start Tor: {e}", file=sys.stderr)
        return 1


def cmd_tor_stop() -> int:
    """Stop Tor container."""
    if not tor_exists():
        print("Tor is not running")
        return 0

    try:
        run(["podman", "stop", "-t", "10", TOR_CONTAINER_NAME], timeout=30)
        run(["podman", "rm", TOR_CONTAINER_NAME])
        print("Tor stopped. Restart warden to disable Tor: warden restart")
        return 0
    except subprocess.TimeoutExpired:
        print("ERROR: Stop command timed out. Try: podman kill warden-tor", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to stop Tor: {e}", file=sys.stderr)
        return 1


def cmd_tor_status() -> int:
    """Show Tor status."""
    if tor_running():
        print("Tor: running")

        # Get Tor network info.
        result = run(
            ["podman", "inspect", TOR_CONTAINER_NAME, "--format",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}: {{$v.IPAddress}}\n{{end}}"],
            check=False, capture=True
        )
        if result.returncode == 0:
            print(f"Networks:\n{result.stdout}")

        # Show usage instructions.
        result = run(
            ["podman", "inspect", TOR_CONTAINER_NAME, "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
            check=False, capture=True
        )
        tor_ip = result.stdout.strip()
        if tor_ip:
            print("Usage: Cells can use Tor directly via SOCKS5:")
            print(f"  export ALL_PROXY=socks5://{tor_ip}:9050")
            print(f"  curl --proxy socks5://{tor_ip}:9050 https://check.torproject.org/api/ip")

        return 0
    elif tor_exists():
        print("Tor: stopped")
        return 1
    else:
        print("Tor: not created")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Warden - Egress proxy manager for Brig",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"warden {VERSION}")
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
            sys.exit(cmd_logs_export(
                args.cell_name, args.format_type, args.output, args.days
            ))
        else:
            sys.exit(cmd_logs())
    elif args.command == "join":
        sys.exit(cmd_join(args.cell_name))
    elif args.command == "leave":
        sys.exit(cmd_leave(args.cell_name))
    elif args.command == "health":
        sys.exit(cmd_health(args.format_json))
    elif args.command == "stats":
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
