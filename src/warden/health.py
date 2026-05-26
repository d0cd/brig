"""
Health check logic for Warden proxy.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from brig.vm.shell import vm_run



@dataclass
class HealthCheck:
    """Result of a single health check."""
    name: str
    passed: bool
    message: str


def check_container_running(container_name: str = "warden") -> HealthCheck:
    """Check if the proxy container is running."""
    result = vm_run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={container_name}"],
    )
    running = container_name in result.stdout.strip().split("\n")
    return HealthCheck(
        "container_running", running,
        "Proxy container is running" if running else "Proxy container is not running",
    )


def check_mitmproxy_responsive(proxy_ip: str, port: int = 8080) -> HealthCheck:
    """Check if mitmproxy is responding on its listen port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        conn_result = sock.connect_ex((proxy_ip, port))
        if conn_result == 0:
            return HealthCheck("mitmproxy_responsive", True, f"mitmproxy listening on {proxy_ip}:{port}")
        return HealthCheck("mitmproxy_responsive", False, f"mitmproxy not responding on port {port}")
    except Exception as e:
        return HealthCheck("mitmproxy_responsive", False, f"Connection check failed: {e}")
    finally:
        sock.close()


def check_policy_loaded(policy_file: Path) -> HealthCheck:
    """Check if the policy file exists and is valid JSON."""
    if not policy_file.exists():
        return HealthCheck("policy_loaded", False, f"Policy file not found: {policy_file}")
    try:
        import json
        with open(policy_file) as f:
            json.load(f)
        return HealthCheck("policy_loaded", True, "Policy file loaded successfully")
    except (json.JSONDecodeError, IOError) as e:
        return HealthCheck("policy_loaded", False, f"Policy file invalid: {e}")


def check_log_writable(log_dir: Path) -> HealthCheck:
    """Check if the log directory exists and is writable."""
    if not log_dir.exists():
        return HealthCheck("log_writable", False, f"Log directory not found: {log_dir}")
    if not log_dir.is_dir():
        return HealthCheck("log_writable", False, f"Log path is not a directory: {log_dir}")
    # Test writability.
    test_file = log_dir / ".health_check"
    try:
        test_file.write_text("ok")
        test_file.unlink()
        return HealthCheck("log_writable", True, "Log directory is writable")
    except OSError as e:
        return HealthCheck("log_writable", False, f"Log directory not writable: {e}")


def run_all_checks(
    proxy_ip: str | None = None,
    policy_file: Path | None = None,
    log_dir: Path | None = None,
) -> list[HealthCheck]:
    """Run all health checks and return results."""
    checks = [check_container_running()]
    if proxy_ip:
        checks.append(check_mitmproxy_responsive(proxy_ip))
    if policy_file:
        checks.append(check_policy_loaded(policy_file))
    if log_dir:
        checks.append(check_log_writable(log_dir))
    return checks
