"""
Workspace file operations with safety checks.

Handles file copy to/from cells with:
  - Path validation (no traversal)
  - Extension blocking (unsafe macOS executables)
  - Symlink validation (no escaping workspace tree)
  - macOS quarantine xattr marking
  - Workspace quota enforcement
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from brig.config import UNSAFE_EXTENSIONS, VMPaths, container_name
from brig.errors import BrigError
from brig.ops.logging import warn
from brig.vm.shell import vm_run


def copy_out(cell_name: str, src: str, dst: str, sanitize: bool = False) -> None:
    """Copy files from cell workspace to host.

    Args:
        cell_name: Cell name.
        src: Source path inside cell (relative to /work).
        dst: Destination path on host.
        sanitize: If True, validate file types and apply quarantine.
    """
    cn = container_name(cell_name)

    # Remember whether the destination existed before the copy. If it did,
    # `podman cp` copied INTO it, so on a sanitize failure we must not delete it
    # (that would destroy the user's pre-existing host files).
    dst_path = Path(dst)
    dst_preexisted = dst_path.exists()

    result = vm_run(["podman", "cp", f"{cn}:{src}", dst])
    if result.returncode != 0:
        raise BrigError(f"Copy failed: {result.stderr.strip()}")

    if sanitize:
        try:
            if dst_path.is_dir():
                _sanitize_tree(dst_path)
            elif dst_path.is_symlink():
                # A single-file copy-out that landed as a symlink is a
                # confused-deputy risk (it can point at a host file outside the
                # destination, e.g. ~/.ssh/id_rsa). The tree path already prunes
                # escaping symlinks; refuse the single-file case too.
                dst_path.unlink()
                raise BrigError(f"Refusing copied-out symlink: {dst}")
            else:
                _sanitize_file(dst_path)
        except BrigError:
            # Only clean up what THIS copy created. If the destination
            # pre-existed, podman cp merged into it and we can't tell copied
            # files from the user's own — removing it would be destructive, so
            # leave it and surface that unsafe files may remain.
            if not dst_preexisted:
                import shutil
                if dst_path.is_dir():
                    shutil.rmtree(dst_path, ignore_errors=True)
                elif dst_path.exists():
                    dst_path.unlink(missing_ok=True)
            else:
                warn(
                    f"Sanitize failed; unsafe files may remain under {dst} "
                    f"(pre-existing destination not removed to avoid data loss)"
                )
            raise
        # Quarantine only what THIS copy produced. If dst pre-existed as a
        # directory, podman merged INTO it, so recursively marking dst_path
        # would xattr the user's own pre-existing files — mark just the copied
        # entry (dst/<basename>) instead.
        quarantine_target = dst_path
        if dst_preexisted and dst_path.is_dir():
            copied = dst_path / Path(src).name
            if copied.exists():
                quarantine_target = copied
        _apply_quarantine(quarantine_target)


def copy_in(cell_name: str, src: str, dst: str, quota: str | None = None) -> None:
    """Copy files from host into cell workspace.

    Args:
        cell_name: Cell name.
        src: Source path on host.
        dst: Destination path inside cell.
        quota: Workspace quota (e.g. "500m"). Checked before copy.
    """
    cn = container_name(cell_name)

    if quota:
        from brig.cell.spec import parse_size
        max_bytes = parse_size(quota)
        current = _get_workspace_size(cell_name)
        if current is None:
            # Fail closed: can't prove the copy stays under quota.
            raise BrigError(
                f"Cannot verify workspace quota for '{cell_name}': "
                f"failed to measure current workspace size",
                suggestion="Retry, or check the VM/cell state",
            )
        src_size = _get_path_size(Path(src))
        if current + src_size > max_bytes:
            raise BrigError(
                f"Workspace quota exceeded: {current + src_size} bytes would exceed {quota}",
                suggestion="Free space or increase --workspace-quota",
            )

    result = vm_run(["podman", "cp", src, f"{cn}:{dst}"])
    if result.returncode != 0:
        raise BrigError(f"Copy failed: {result.stderr.strip()}")


def _sanitize_tree(root: Path) -> None:
    """Walk a directory tree and sanitize each file."""
    root_resolved = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        # Directory symlinks land in `dirnames`; os.walk (followlinks=False)
        # doesn't descend into them, but a symlinked dir escaping the tree
        # (e.g. `out -> ~/.ssh`) would otherwise be left live in the copied-out
        # destination. Prune those before they reach the host.
        for dirname in list(dirnames):
            dpath = Path(dirpath) / dirname
            if dpath.is_symlink():
                try:
                    dpath.resolve().relative_to(root_resolved)
                except ValueError:
                    warn(f"Removing dir symlink escaping tree: {dpath}")
                    dpath.unlink()
                    dirnames.remove(dirname)
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.is_symlink():
                # Reject symlinks pointing outside the tree.
                try:
                    filepath.resolve().relative_to(root_resolved)
                except ValueError:
                    warn(f"Removing symlink escaping tree: {filepath}")
                    filepath.unlink()
                    continue
            _sanitize_file(filepath)


def _sanitize_file(filepath: Path) -> None:
    """Check a single file for unsafe extensions and remove execute bits."""
    ext = filepath.suffix.lower()
    if ext in UNSAFE_EXTENSIONS:
        raise BrigError(
            f"Unsafe file type blocked: {filepath.name}",
            suggestion=f"Files with {ext} extension are not allowed for safety",
        )
    # Remove executable bits.
    try:
        mode = filepath.stat().st_mode
        filepath.chmod(mode & ~0o111)
    except OSError:
        pass


def _apply_quarantine(path: Path) -> None:
    """Apply macOS quarantine xattr to mark files from untrusted cells.

    This triggers Gatekeeper checks when the user tries to open the file.
    Recurses into directories (-r) so every copied-out file is marked, not just
    the top entry — Gatekeeper checks the xattr on the file being opened, so a
    tree with only its root marked would leave the payloads unquarantined.
    """
    cmd = ["xattr", "-w", "com.apple.quarantine", "0083;00000000;Brig;", str(path)]
    if path.is_dir():
        cmd.insert(1, "-r")
    try:
        subprocess.run(cmd, check=False, capture_output=True)
    except OSError:
        pass  # Not on macOS or xattr unavailable.


def _get_workspace_size(cell_name: str) -> int | None:
    """Workspace directory size in bytes (measured inside the VM).

    Returns None if the measurement fails (du error/timeout or unparseable
    output) so callers can distinguish "empty" from "unknown" and fail closed
    rather than treating an unmeasurable workspace as 0 bytes (quota bypass).
    """
    result = vm_run(
        ["du", "-sb", str(VMPaths.STATE_DIR / cell_name / "workspace")],
        timeout=10,
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.split()[0])
    except (IndexError, ValueError):
        return None


def _get_path_size(path: Path) -> int:
    """Get size of a local path in bytes."""
    if path.is_file():
        return path.stat().st_size
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except OSError:
                pass
    return total


def find_escaping_symlinks(root: Path) -> list[tuple[Path, Path]]:
    """Walk `root` and return (symlink, resolved_target) for every symlink
    whose realpath escapes `root`.

    Host-side guard for `mounts:` — an untrusted cell with a rw mount can plant
    a symlink pointing out of the shared folder (e.g. -> ~/.ssh/id_rsa); a host
    consumer that follows it escapes the folder. Same escaping-symlink check
    the copy-out sanitizer applies, surfaced as a standalone scan. Does not
    follow directory symlinks while walking.
    """
    root_resolved = root.resolve()
    escaping: list[tuple[Path, Path]] = []

    def _escapes(p: Path) -> bool:
        try:
            p.resolve().relative_to(root_resolved)
            return False
        except (ValueError, OSError):
            return True

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            p = Path(dirpath) / name
            if p.is_symlink() and _escapes(p):
                escaping.append((p, Path(os.path.realpath(p))))
            # Don't descend into symlinked dirs (followlinks=False already
            # prevents os.walk from doing so).
    return escaping


def quarantine_escaping_symlinks(root: Path) -> list[Path]:
    """Remove symlinks under `root` whose realpath escapes it; return the
    removed paths."""
    removed: list[Path] = []
    for link, _target in find_escaping_symlinks(root):
        try:
            link.unlink()
            removed.append(link)
        except OSError as e:
            warn(f"Could not remove escaping symlink {link}: {e}")
    return removed
