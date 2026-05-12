"""
Canary token detection addon for mitmproxy.

Scans outbound HTTP requests for canary token values that were injected
into cells. When a canary is detected in egress traffic, the request is
blocked and the cell is killed immediately.

Canary tokens are loaded from per-cell policy files where they are stored
under the "canary_tokens" key. The SDK writes canary values via tempfile
to avoid exposing them in process arguments.

Usage:
    mitmdump -s canary.py
"""

import ipaddress
import json
import re
import subprocess
import threading
from pathlib import Path
from typing import Optional

from mitmproxy import ctx, http


# Subnet map for cell identification (same as enforce.py).
SUBNET_MAP_FILE = Path("/var/run/cells/subnet-map.json")

# Per-cell policy directory (canary tokens stored here).
CELL_POLICY_DIR = Path("/var/run/cells/policies")


class CanaryDetector:
    """mitmproxy addon that scans egress traffic for canary token values."""

    def __init__(self):
        self.cell_canaries: dict[str, dict[str, str]] = {}  # cell -> {label: value}
        self.subnet_map: dict[str, str] = {}  # subnet -> cell_name
        self._subnet_map_mtime = 0.0
        self._policy_mtimes: dict[str, float] = {}
        self._reload_pending = False

    def load(self, loader):
        """Called when addon is loaded."""
        self._load_subnet_map()
        self._load_canaries()
        ctx.log.info(
            f"CanaryDetector: Loaded canary tokens for "
            f"{len(self.cell_canaries)} cells"
        )

    def configure(self, updated):
        """Reload when files change."""
        self._reload_pending = True

    def _do_reload(self):
        """Reload all config (called on next request after SIGHUP)."""
        self._subnet_map_mtime = 0.0
        self._policy_mtimes.clear()
        self._load_subnet_map()
        self._load_canaries()

    def _load_subnet_map(self):
        """Load subnet-to-cell mapping."""
        try:
            if not SUBNET_MAP_FILE.exists():
                return
            mtime = SUBNET_MAP_FILE.stat().st_mtime
            if mtime == self._subnet_map_mtime:
                return
            with open(SUBNET_MAP_FILE, "r") as f:
                self.subnet_map = json.load(f)
            self._subnet_map_mtime = mtime
        except (json.JSONDecodeError, IOError, OSError) as e:
            ctx.log.error(f"CanaryDetector: Failed to load subnet map: {e}")

    def _load_canaries(self):
        """Load canary tokens from per-cell policy files."""
        try:
            if not CELL_POLICY_DIR.exists():
                return
            for policy_file in CELL_POLICY_DIR.glob("*.json"):
                cell_name = policy_file.stem
                mtime = policy_file.stat().st_mtime
                if self._policy_mtimes.get(cell_name) == mtime:
                    continue
                try:
                    with open(policy_file, "r") as f:
                        data = json.load(f)
                    canary_tokens = data.get("canary_tokens", {})
                    if canary_tokens:
                        self.cell_canaries[cell_name] = canary_tokens
                    elif cell_name in self.cell_canaries:
                        del self.cell_canaries[cell_name]
                    self._policy_mtimes[cell_name] = mtime
                except (json.JSONDecodeError, IOError) as e:
                    ctx.log.error(
                        f"CanaryDetector: Failed to load policy for {cell_name}: {e}"
                    )
        except OSError as e:
            ctx.log.error(f"CanaryDetector: Failed to scan policy dir: {e}")

    def _identify_cell_ip(self, client_ip: str) -> Optional[str]:
        """Resolve client IP to cell name via subnet map."""
        try:
            ip = ipaddress.ip_address(client_ip)
            for subnet_str, cell_name in self.subnet_map.items():
                try:
                    subnet = ipaddress.ip_network(subnet_str, strict=False)
                    if ip in subnet:
                        return cell_name
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    def _scan_for_canaries(self, cell: str, text: str) -> list[str]:
        """Scan text for canary values. Returns list of matched labels."""
        canaries = self.cell_canaries.get(cell, {})
        if not canaries:
            return []
        matched = []
        for label, value in canaries.items():
            if value and isinstance(value, str) and value in text:
                matched.append(label)
        return matched

    def request(self, flow: http.HTTPFlow) -> None:
        """mitmproxy hook: scan outbound requests for canary values."""
        # Check for deferred SIGHUP reload.
        if self._reload_pending:
            self._reload_pending = False
            self._do_reload()

        # Reload maps if needed.
        self._load_subnet_map()
        self._load_canaries()

        # Identify the cell.
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        cell_name = flow.metadata.get("cell") or self._identify_cell_ip(client_ip)
        if not cell_name or cell_name not in self.cell_canaries:
            return  # No canaries for this cell.

        # Build text to scan: URL + headers + body.
        parts = [flow.request.url]
        for k, v in flow.request.headers.items():
            parts.append(f"{k}: {v}")
        # Scan entire body to prevent evasion via tokens placed in the middle.
        content = flow.request.get_content()
        if content:
            body = content.decode("utf-8", errors="ignore")
            parts.append(body)
        scan_text = "\n".join(parts)

        # Scan for canary values.
        matched = self._scan_for_canaries(cell_name, scan_text)
        if matched:
            labels = ", ".join(matched)
            ctx.log.warn(
                f"CanaryDetector: CANARY DETECTED in cell '{cell_name}': "
                f"labels={labels}, host={flow.request.host}"
            )
            # Block the request.
            flow.response = http.Response.make(
                403, b"Request blocked", {"Content-Type": "text/plain"}
            )
            flow.metadata["canary_detected"] = matched
            # Kill the cell.
            self._kill_cell(cell_name)

    def _kill_cell(self, cell_name: str):
        """Kill a cell that triggered canary detection.

        Runs in a background thread to avoid blocking the mitmproxy event
        loop (which would stall traffic for all cells).
        """
        # Validate cell name to prevent argument injection.
        # Must match the canonical CELL_NAME_PATTERN from brig.config.
        if not cell_name or not re.match(r"^[a-z0-9][a-z0-9._-]{0,62}$", cell_name):
            ctx.log.error(f"CanaryDetector: Invalid cell name '{cell_name}'")
            return
        # Non-daemon thread ensures kill completes even during shutdown.
        t = threading.Thread(
            target=self._kill_cell_sync,
            args=(cell_name,),
            daemon=False,
        )
        t.start()

    def _kill_cell_sync(self, cell_name: str):
        """Synchronous cell kill (runs in background thread)."""
        try:
            subprocess.run(
                ["podman", "kill", "--", f"brig-{cell_name}"],
                check=False, capture_output=True, timeout=10,
            )
            ctx.log.warn(f"CanaryDetector: Killed cell '{cell_name}'")
        except (subprocess.TimeoutExpired, OSError) as e:
            ctx.log.error(f"CanaryDetector: Failed to kill cell '{cell_name}': {e}")


addons = [CanaryDetector()]
