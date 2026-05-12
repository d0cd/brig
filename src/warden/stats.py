"""
Metrics query for Warden proxy via Unix socket.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


def query_metrics(
    metrics_socket: Path,
    cell_name: str | None = None,
) -> dict[str, Any] | None:
    """Query metrics from the proxy via Unix socket.

    Returns metrics dict or None on failure.
    """
    if not metrics_socket.exists():
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(str(metrics_socket))

        request = {"type": "metrics"}
        if cell_name:
            request["cell"] = cell_name

        sock.sendall(json.dumps(request).encode() + b"\n")
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk

        return json.loads(data.decode())
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        sock.close()
