"""
Cell specification — dataclass and loading.

A CellSpec describes the desired state of a cell. It is the input to the
reconciler, which computes the actions needed to make reality match.

`validate_cell_definition` is re-exported from `brig.cell.validators`
below so existing callers (and tests) don't need to change imports.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from brig.config import CELL_NAME_PATTERN

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Size units for parse_size.
_SIZE_UNITS = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(size_str: str) -> int:
    """Parse a human-readable size string to bytes (e.g. '500m', '2g')."""
    size_str = size_str.strip().lower()
    if not size_str:
        raise ValueError("Empty size string")
    if size_str[-1] in _SIZE_UNITS:
        try:
            # OverflowError: float('inf')/'1e400' make int() overflow; the
            # callers' contract is ValueError, so normalize it here.
            return int(float(size_str[:-1]) * _SIZE_UNITS[size_str[-1]])
        except (ValueError, OverflowError):
            raise ValueError(f"Invalid size: {size_str}")
    try:
        return int(size_str)
    except ValueError:
        raise ValueError(f"Invalid size: {size_str}")


def parse_duration(duration_str: str) -> int | None:
    """Parse a duration string into seconds (e.g. '30s', '5m', '2h', '1d').

    Returns None if format is invalid.
    """
    duration_str = duration_str.strip()
    if duration_str.isdigit():
        return int(duration_str)
    match = re.match(r"^(\d+)([smhd])$", duration_str)
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class CellSpec:
    """Desired state of a cell."""
    name: str
    image: str
    command: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 512
    network: str = "default"  # "default" (per-cell isolated) or "none" (airgapped)
    policy_allow: list[str] = field(default_factory=list)
    policy_deny: list[str] = field(default_factory=list)
    # Hosts where Warden tunnels TLS without decrypting (no MITM). Each
    # entry must also appear in policy_allow — passthrough is a TLS-handling
    # override, NEVER an allow shortcut. Operators opt in here when a host's
    # TLS stack (HPKP/ECH/Cloudflare bot-fp) refuses mitmproxy's relayed
    # handshake. The security trade-off is explicit: passthrough flows lose
    # per-URL audit + body inspection, gain handshake compat + credential
    # confidentiality. See docs/INVARIANTS.md invariant 11.
    policy_passthrough_tls: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    timeout: str | None = None
    workspace_quota: str | None = None
    # Where the per-cell workspace is mounted inside the cell. Default /work
    # matches existing cells; agent-delegation scenarios may prefer the host
    # path basename (e.g. /workspace) so the in-cell and on-host paths agree.
    workspace_mount: str = "/work"
    # Cell rootfs writability. Default False (safe): podman runs the cell
    # with --read-only, plus sized tmpfs at /tmp and /run. The cell can
    # still write to /work (the workspace) — that's its persistence path.
    # A hostile cell with the rootfs writable could (a) DoS the shared
    # VM disk by filling its writable layer, and (b) hide state across
    # stop/start outside the workspace where the user wouldn't think to
    # look. The opt-out exists for images whose entrypoint genuinely
    # needs to write outside /work, /tmp, /run (legacy daemons that
    # write to /var/log, dev images that build at runtime, etc.).
    writable_rootfs: bool = False
    detach: bool = False
    rm: bool = False
    seccomp_profile: str | None = None
    workdir: str | None = None
    image_digest: str | None = None
    profile: str | None = None
    ingress: list[dict[str, Any]] = field(default_factory=list)
    # host_services — HTTP-only forwarding from cell to a macOS host
    # port, through Warden. Each entry: {name, port}. Cell reaches
    # <name>.host.brig and Warden rewrites to (host_ip, port).
    # Declaring in yaml IS the grant — there is no separate global
    # registry. See cell.validators._v_host_services.
    host_services: list[dict[str, Any]] = field(default_factory=list)
    # mounts — bind-mount an operator-chosen host directory into the cell.
    # Each entry: {name, host_path, mount_point, mode?}. host_path must
    # resolve under a declared config.mount_roots() entry; ro default, rw
    # opt-in. Bypasses Warden by design; rejected on the untrusted profile.
    # See cell.validators._v_mounts and docs/design/host-mounts.md.
    mounts: list[dict[str, Any]] = field(default_factory=list)
    # Trust Warden's MITM CA out of the box. When true (default), brig
    # stages a combined bundle (system roots + Warden CA) inside the VM
    # and mounts it at /run/brig/ca-bundle.crt, plus sets SSL_CERT_FILE /
    # REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / NODE_EXTRA_CA_CERTS to point
    # at it (only when the cell didn't already set them). Set to false
    # for cells with strict cert pinning or that manage their own trust
    # store. See brig.cell.ca_bundle.
    trust_warden_ca: bool = True
    # restart — "no" (default) or "always". An "always" cell is re-launched by
    # `brig system up` whenever its container is gone (e.g. a VM restart drops
    # every container). brig persists the full spec at run time to replay it.
    # An *exited* cell (still present, e.g. `brig cell stop`) is left alone — but
    # a VM restart drops the container, so a stopped restart:always cell DOES
    # relaunch on the next up; use `brig cell rm` to keep one down for good.
    restart: str = "no"
    # user — podman --user (uid[:gid] or name[:group]); default is the image's
    # USER. gVisor presents virtiofs host mounts (and /work) as owned by 0:0
    # inside the cell, so only a cell running as root (user: "0") can fully own
    # a rw `mounts:` dir (read/write/rewrite). Writes still land owned by the
    # operator on macOS, so readback is unaffected. Running as root *inside* the
    # gVisor+VM sandbox is not a host-privilege change (the VM is the boundary).
    user: str | None = None

    def __post_init__(self) -> None:
        """Validate inputs at construction time — the system boundary.

        Coerces string-typed numeric fields. Yaml authors naturally write
        `cpus: 4` (parsed as int) but `cpus` is declared `str` because
        podman accepts fractional values. Without coercion, the int slips
        through and crashes downstream when the subprocess args are
        scanned (`"=" in <int>` raises).
        """
        if not CELL_NAME_PATTERN.match(self.name):
            raise ValueError(
                f"Invalid cell name '{self.name}': must match {CELL_NAME_PATTERN.pattern}"
            )
        # Coerce numeric-yaml inputs on str-typed fields.
        for fname in ("cpus", "memory"):
            v = getattr(self, fname)
            if isinstance(v, (int, float)):
                object.__setattr__(self, fname, str(v))

    @property
    def is_airgapped(self) -> bool:
        """True if cell has no network access."""
        return self.network == "none"


# Re-export the validator entry point so existing imports
# `from brig.cell.spec import validate_cell_definition` keep working.
from brig.cell.validators import validate_cell_definition  # noqa: E402,F401


def load_cell_definition(path: str) -> dict[str, Any]:
    """Load a cell definition from a JSON or YAML file.

    Raises BrigError on failure.
    """
    from brig.errors import BrigError

    p = Path(path)
    if not p.exists():
        raise BrigError(f"Cell definition file not found: {path}")

    content = p.read_text()
    suffix = p.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not YAML_AVAILABLE:
            raise BrigError(
                "YAML support requires pyyaml",
                suggestion="Install with: pip install pyyaml",
            )
        try:
            result = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise BrigError(
                f"Failed to parse YAML: {e}",
                suggestion="Check the YAML syntax and try again",
            )
    else:
        try:
            result = json.loads(content)
        except json.JSONDecodeError as e:
            raise BrigError(
                f"Failed to parse JSON: {e}",
                suggestion="Check the JSON syntax. Validate with: python -m json.tool FILE",
            )

    if not isinstance(result, dict):
        raise BrigError(f"Cell definition must be a mapping, got {type(result).__name__}")
    return result
