"""
Tor/Privoxy bridge lifecycle management.

Manages the Tor SOCKS5 proxy and Privoxy HTTP-to-SOCKS bridge
containers for anonymous egress.
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

from brig.ops.logging import debug, info
from brig.vm.shell import vm_run

TOR_CONTAINER_NAME = "warden-tor"
TOR_IMAGE = "docker.io/osminogin/tor-simple@sha256:4e64295fbafd856adc73d3ebc402b0d84598ddd278383ec1adaa32e4ecf0bea1"
TOR_SOCKS_PORT = 9050

PRIVOXY_CONTAINER_NAME = "warden-privoxy"
PRIVOXY_IMAGE = "docker.io/vimagick/privoxy@sha256:6f53634c62a05ee6a12e8c60fabf15a0d2f8e46e0d5fa42a0fa34b5e0d59f090"
PRIVOXY_PORT = 8118

NETWORK = "proxy-external"


def _get_container_ip(container_name: str) -> str:
    """Get a container's IP address."""
    result = vm_run(
        ["podman", "inspect", container_name, "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _wait_for_port(container_name: str, port: int, timeout_secs: int = 30) -> bool:
    """Wait for a TCP port to become responsive in a container."""
    ip = _get_container_ip(container_name)
    if not ip:
        return False
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            if sock.connect_ex((ip, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            sock.close()
        time.sleep(1)
    return False


def _is_container_running(name: str) -> bool:
    """Check if a container is running."""
    result = vm_run(
        ["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={name}"],
    )
    return name in result.stdout.strip().split("\n")


def is_tor_running() -> bool:
    """Check if the Tor container is running."""
    return _is_container_running(TOR_CONTAINER_NAME)


def is_privoxy_running() -> bool:
    """Check if the Privoxy container is running."""
    return _is_container_running(PRIVOXY_CONTAINER_NAME)


def stop_tor_stack() -> bool:
    """Stop both Privoxy and Tor containers."""
    success = True
    for name in [PRIVOXY_CONTAINER_NAME, TOR_CONTAINER_NAME]:
        result = vm_run(
            ["podman", "stop", name],
        )
        vm_run(
            ["podman", "rm", name],
        )
        if result.returncode != 0:
            debug(f"Failed to stop {name}: {result.stderr}")
            success = False
    return success
