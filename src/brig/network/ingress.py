"""
Ingress route management — register/deregister cell ingress endpoints.

Routes are stored in a JSON file that the Warden ingress addon watches.
File writes are atomic (write-to-temp, rename) and locked to prevent
concurrent modification when multiple cells start/stop simultaneously.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path

from brig.config import HostPaths
from brig.ops.atomic import atomic_write_json
from brig.ops.logging import debug, info


def _load_routes(path: Path) -> dict:
    """Load routes file, returning empty structure if missing."""
    if not path.exists():
        return {"routes": []}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "routes" not in data:
            return {"routes": []}
        return data
    except (json.JSONDecodeError, IOError):
        return {"routes": []}


def _hash_token(token: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a token with salted SHA-256 for storage.

    Returns (hash_hex, salt_hex). The raw token is never stored.
    Salt prevents rainbow table attacks if the routes file is read
    from the untrusted macOS filesystem (invariant 4).
    """
    if salt is None:
        salt = os.urandom(16).hex()
    salted = salt + token
    token_hash = hashlib.sha256(salted.encode("utf-8")).hexdigest()
    return token_hash, salt


def register_ingress(
    cell_name: str,
    cell_ip: str,
    ingress_spec: list[dict],
    auth_token: str,
) -> None:
    """Register ingress routes for a cell.

    Args:
        cell_name: Cell name.
        cell_ip: Cell's IP on its network (from podman inspect).
        ingress_spec: List of ingress entries from CellSpec.
        auth_token: Raw bearer token for authentication.
    """
    if not ingress_spec:
        return

    routes_file = HostPaths.INGRESS_ROUTES_FILE
    lock_file = routes_file.with_suffix(".lock")
    routes_file.parent.mkdir(parents=True, exist_ok=True)

    token_hash, token_salt = _hash_token(auth_token)

    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            data = _load_routes(routes_file)

            # Remove any existing routes for this cell (idempotent).
            data["routes"] = [
                r for r in data["routes"] if r.get("cell") != cell_name
            ]

            # Add new routes.
            for entry in ingress_spec:
                data["routes"].append({
                    "cell": cell_name,
                    "cell_ip": cell_ip,
                    "name": entry["name"],
                    "port": entry["port"],
                    "path_prefix": entry["path_prefix"],
                    "auth": entry["auth"],
                    "auth_secret_hash": token_hash,
                    "auth_salt": token_salt,
                })

            atomic_write_json(routes_file, data)
            info(f"Registered {len(ingress_spec)} ingress routes for '{cell_name}'")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def deregister_ingress(cell_name: str) -> None:
    """Remove all ingress routes for a cell."""
    routes_file = HostPaths.INGRESS_ROUTES_FILE
    lock_file = routes_file.with_suffix(".lock")

    if not routes_file.exists():
        return

    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            data = _load_routes(routes_file)
            before = len(data["routes"])
            data["routes"] = [
                r for r in data["routes"] if r.get("cell") != cell_name
            ]
            after = len(data["routes"])

            if before != after:
                atomic_write_json(routes_file, data)
                debug(f"Deregistered {before - after} ingress routes for '{cell_name}'")
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
