"""macOS-side launchd bridge for host_sockets.

Each declared host_socket needs a long-running process that listens on
the bridge socket at ~/.brig/state/system/host-sockets/<cell>/<name>.sock
and forwards bytes to the operator's host_path. We use socat under
launchd because:
  - socat is dead simple (UNIX-LISTEN,fork → UNIX-CONNECT)
  - launchd handles restart-on-crash without us writing a supervisor
  - one process per declared socket; debugging means looking at one PID

Lifecycle:
  - `brig run` calls start_cell_bridges(spec.name, spec.host_sockets)
    BEFORE the reconciler attempts the cell start. The runtime check
    in the reconciler then sees the bridge socket and proceeds.
  - `brig stop` / `brig rm` calls stop_cell_bridges(spec.name) to
    bootout the launchd jobs and remove plist files.

Threat surface: socat now sits on the trust path between cell and host
service. It's a pinned brew install and a small, well-audited program;
the alternative (writing our own forwarder) would be larger surface.
"""

from __future__ import annotations

import os
import shutil
import stat as _stat
import subprocess
import time
from pathlib import Path
from typing import Any

from brig.config import HOST_SOCKET_ENGINE_DENYLIST, HostPaths
from brig.errors import BrigError
from brig.ops.logging import debug, info

# Per-user LaunchAgents directory. brig is single-user so this is
# always the operator's home — we don't write to /Library/LaunchDaemons
# (that needs root and runs in a different context).
PLIST_DIR = Path.home() / "Library" / "LaunchAgents"

LABEL_PREFIX = "com.brig.host-socket."

# How long to wait for the bridge socket to appear after launchctl
# load. socat is fast; this is generous to handle slow CI macOS hosts.
_BRIDGE_READY_TIMEOUT_S = 5.0
_BRIDGE_READY_POLL_S = 0.05


def _find_socat() -> str | None:
    """Locate the socat binary. Returns absolute path or None."""
    return shutil.which("socat")


def _launchctl(args: list[str]) -> subprocess.CompletedProcess:
    """Run launchctl with the given args. Single seam for test mocking."""
    return subprocess.run(
        ["launchctl", *args],
        capture_output=True, text=True, check=False,
    )


def _wait_for_socket(path: Path, timeout: float = _BRIDGE_READY_TIMEOUT_S) -> bool:
    """Poll until `path` exists and is a unix socket, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            st = path.lstat()
            if _stat.S_ISSOCK(st.st_mode):
                return True
        except FileNotFoundError:
            pass
        time.sleep(_BRIDGE_READY_POLL_S)
    return False


def _label_for(cell_name: str, socket_name: str) -> str:
    return f"{LABEL_PREFIX}{cell_name}.{socket_name}"


def _plist_path(cell_name: str, socket_name: str) -> Path:
    return PLIST_DIR / f"{_label_for(cell_name, socket_name)}.plist"


def _bridge_dir_for_cell(cell_name: str) -> Path:
    return HostPaths.HOST_SOCKETS_DIR / cell_name


def _bridge_path(cell_name: str, socket_name: str) -> Path:
    return _bridge_dir_for_cell(cell_name) / f"{socket_name}.sock"


def generate_plist(
    label: str, socat_bin: str, bridge_path: str, target_path: str,
) -> str:
    """Render the launchd plist XML for one socat bridge.

    socat creates the bridge socket on listen; the parent dir must
    exist (we ensure that in start_cell_bridges).
    """
    # XML attribute values aren't user-controllable except via plist
    # paths (which we construct from validated names). Still escape
    # defensively to keep the XML well-formed.
    def esc(s: str) -> str:
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{esc(label)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{esc(socat_bin)}</string>
    <string>UNIX-LISTEN:{esc(bridge_path)},fork,mode=0600</string>
    <string>UNIX-CONNECT:{esc(target_path)}</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/tmp/{esc(label)}.err.log</string>
</dict>
</plist>
"""


def _validate_target(host_path: str) -> None:
    """Runtime guard: reject engine sockets and non-socket targets.

    Defense in depth:
      - Realpath-resolve to defeat symlinks at ANY level (parent dir
        symlinks would otherwise sneak past a leaf-only lstat check).
      - Re-check the engine denylist against the realpath basename so
        a /tmp/postgres.sock → /var/run/docker.sock symlink fails on
        the denylist, not just on the symlink ban.
      - Then lstat() the original path; reject leaf symlinks too.
        Realpath alone would silently follow them.
    """
    if not host_path or not isinstance(host_path, str):
        raise BrigError("host_socket host_path must be a non-empty string")

    # Realpath walks the entire chain. We do this BEFORE the lstat ban
    # so the denylist check sees the true target. os.path.realpath
    # doesn't raise on missing components; we follow with lstat which
    # does the existence check explicitly.
    real = os.path.realpath(host_path)
    real_basename = real.rsplit("/", 1)[-1]
    literal_basename = host_path.rsplit("/", 1)[-1]
    if real_basename in HOST_SOCKET_ENGINE_DENYLIST or \
       literal_basename in HOST_SOCKET_ENGINE_DENYLIST:
        raise BrigError(
            f"refusing to bridge to engine socket "
            f"'{real_basename}' — granting access is root-equivalent on the host",
        )

    try:
        st = os.lstat(host_path)
    except FileNotFoundError:
        raise BrigError(
            f"host_socket target not found: {host_path}",
            suggestion="Is the service that provides this socket running?",
        )
    if _stat.S_ISLNK(st.st_mode):
        raise BrigError(
            f"host_socket target {host_path} is a symlink — "
            f"refusing to bridge through a symlink",
        )
    # Realpath canonicalizes the entire ancestor chain — any symlink
    # at any level gets resolved here, so a post-validation swap of a
    # parent directory can't redirect us to attacker-controlled
    # storage. We then stat (NOT lstat) the realpath: realpath already
    # collapsed any symlinks; we just want S_ISSOCK on the canonical
    # path. A normal /tmp → /private/tmp Mac-ism is fine; what we
    # reject is a final-target that isn't actually a socket.
    real = os.path.realpath(host_path)
    try:
        real_st = os.stat(real)
    except FileNotFoundError:
        raise BrigError(
            f"host_socket target {host_path} resolves to {real} "
            f"which does not exist",
        )
    if not _stat.S_ISSOCK(real_st.st_mode):
        raise BrigError(
            f"host_socket target {host_path} is not a unix socket "
            f"(realpath={real}, mode={oct(real_st.st_mode)})",
        )


def start_cell_bridges(
    cell_name: str, host_sockets: list[dict[str, Any]],
) -> None:
    """Start a launchd bridge for each declared host_socket. No-op
    if `host_sockets` is empty.

    Order of operations matters: we validate everything, then write
    plists, then load them, then wait for sockets to appear. If any
    step fails, we tear down what we started so the cell doesn't
    end up half-bridged.
    """
    if not host_sockets:
        return

    socat = _find_socat()
    if not socat:
        raise BrigError(
            "socat is required for host_sockets but was not found",
            suggestion="brew install socat",
        )

    # Validate every target up front so we don't half-bridge.
    for entry in host_sockets:
        _validate_target(entry["host_path"])

    bridge_dir = _bridge_dir_for_cell(cell_name)
    bridge_dir.mkdir(parents=True, exist_ok=True)
    PLIST_DIR.mkdir(parents=True, exist_ok=True)

    started: list[str] = []  # labels we loaded, for rollback on failure
    try:
        for entry in host_sockets:
            sock_name = entry["name"]
            target = entry["host_path"]
            label = _label_for(cell_name, sock_name)
            bridge = _bridge_path(cell_name, sock_name)
            plist = _plist_path(cell_name, sock_name)

            # Clean stale bridge socket from a prior crashed run before
            # socat tries to bind (socat will EADDRINUSE otherwise).
            if bridge.exists():
                bridge.unlink()

            xml = generate_plist(
                label=label, socat_bin=socat,
                bridge_path=str(bridge), target_path=target,
            )
            plist.write_text(xml)
            plist.chmod(0o644)

            # bootstrap is the modern verb; load is the legacy fallback.
            # We try bootstrap first; if launchctl rejects it (older
            # macOS), fall back to load.
            uid = os.getuid()
            res = _launchctl([
                "bootstrap", f"gui/{uid}", str(plist),
            ])
            if res.returncode != 0:
                debug(f"launchctl bootstrap failed: {res.stderr}; trying load")
                res = _launchctl(["load", str(plist)])
                if res.returncode != 0:
                    raise BrigError(
                        f"launchctl could not load bridge for '{sock_name}': "
                        f"{res.stderr.strip()}",
                    )

            if not _wait_for_socket(bridge):
                raise BrigError(
                    f"bridge socket for '{sock_name}' did not appear at "
                    f"{bridge} within {_BRIDGE_READY_TIMEOUT_S}s — "
                    f"check /tmp/{label}.err.log",
                )

            started.append(label)
            info(f"host_socket bridge started: {sock_name} → {target}")
    except Exception:
        for label in started:
            # Best-effort cleanup; ignore errors here so the original
            # exception propagates with its real message.
            sock_name = label[len(LABEL_PREFIX) + len(cell_name) + 1:]
            _stop_one_bridge(cell_name, sock_name)
        raise


def _stop_one_bridge(cell_name: str, socket_name: str) -> None:
    """Bootout one bridge and remove its plist. Idempotent."""
    label = _label_for(cell_name, socket_name)
    plist = _plist_path(cell_name, socket_name)
    if plist.exists():
        uid = os.getuid()
        # bootout / unload — try modern verb first.
        res = _launchctl(["bootout", f"gui/{uid}/{label}"])
        if res.returncode != 0:
            _launchctl(["unload", str(plist)])
        try:
            plist.unlink()
        except OSError as e:
            debug(f"could not remove plist {plist}: {e}")
    bridge = _bridge_path(cell_name, socket_name)
    if bridge.exists():
        try:
            bridge.unlink()
        except OSError as e:
            debug(f"could not remove bridge socket {bridge}: {e}")


def stop_cell_bridges(cell_name: str) -> None:
    """Stop all launchd bridges for a cell. Idempotent — no-op if the
    cell never had any bridges."""
    prefix = f"{LABEL_PREFIX}{cell_name}."
    if not PLIST_DIR.exists():
        return
    for plist in PLIST_DIR.iterdir():
        if not plist.name.startswith(prefix) or not plist.name.endswith(".plist"):
            continue
        # Recover the socket_name from the filename.
        label = plist.stem  # strip .plist
        socket_name = label[len(prefix):]
        _stop_one_bridge(cell_name, socket_name)
    # Clean up the cell's bridge directory if empty.
    bridge_dir = _bridge_dir_for_cell(cell_name)
    if bridge_dir.exists():
        try:
            bridge_dir.rmdir()
        except OSError:
            pass  # not empty or perms issue; harmless
