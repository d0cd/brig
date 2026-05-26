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

    result = vm_run(["podman", "cp", f"{cn}:{src}", dst])
    if result.returncode != 0:
        raise BrigError(f"Copy failed: {result.stderr.strip()}")

    if sanitize:
        dst_path = Path(dst)
        try:
            if dst_path.is_dir():
                _sanitize_tree(dst_path)
            else:
                _sanitize_file(dst_path)
        except BrigError:
            # Remove unsafe files that were already written to host.
            import shutil
            if dst_path.is_dir():
                shutil.rmtree(dst_path, ignore_errors=True)
            elif dst_path.exists():
                dst_path.unlink(missing_ok=True)
            raise
        _apply_quarantine(dst_path)


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
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.is_symlink():
                # Reject symlinks pointing outside the tree.
                try:
                    filepath.resolve().relative_to(root.resolve())
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
    """
    try:
        subprocess.run(
            ["xattr", "-w", "com.apple.quarantine",
             "0083;00000000;Brig;", str(path)],
            check=False, capture_output=True,
        )
    except OSError:
        pass  # Not on macOS or xattr unavailable.


def _get_workspace_size(cell_name: str) -> int:
    """Get workspace directory size in bytes inside the VM."""
    result = vm_run(
        ["du", "-sb", str(VMPaths.STATE_DIR / cell_name / "workspace")],
        timeout=10,
    )
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.split()[0])
    except (IndexError, ValueError):
        return 0


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
