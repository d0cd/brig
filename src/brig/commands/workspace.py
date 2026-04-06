"""Workspace commands: files, cat, cp."""

import os
import time

from pathlib import Path

import brig.commands._helpers as _helpers
from brig.commands._helpers import (
    cell_exists,
    debug,
    error,
    error_cell_not_found,
    info,
    output,
    run,
    validate_cell_name,
    validate_workspace_path,
    warn,
)
from brig.config import SCRIPT_EXTENSIONS, UNSAFE_EXTENSIONS

OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".odt", ".ods", ".odp",
}


def cmd_files(args) -> int:
    """List contents of a cell's workspace."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    workspace_dir = _helpers.STATE_DIR / cell_name / "workspace"
    if not workspace_dir.exists():
        info(f"No workspace for {cell_name}")
        return 0

    # Build path within workspace.
    target_path = workspace_dir
    if args.path:
        target_path = validate_workspace_path(workspace_dir, args.path)

    if not target_path.exists():
        error(
            f"Path does not exist: {args.path}",
            f"List workspace contents with: brig files {cell_name}"
        )

    if target_path.is_file():
        # Show single file info.
        stat = target_path.stat()
        print(f"{target_path.name}  {stat.st_size} bytes")
    else:
        # List directory.
        cmd = ["ls", "-la", str(target_path)]
        run(cmd, check=False)

    return 0


def cmd_cat(args) -> int:
    """View contents of a file in cell's workspace."""
    cell_name = args.name
    validate_cell_name(cell_name)

    if not cell_exists(cell_name):
        error_cell_not_found(cell_name)

    workspace_dir = _helpers.STATE_DIR / cell_name / "workspace"
    if not workspace_dir.exists():
        error(
            f"No workspace for cell '{cell_name}'",
            f"Check cell status with: brig inspect {cell_name}"
        )

    # Validate path (no traversal).
    file_path = validate_workspace_path(workspace_dir, args.path)

    if not file_path.exists():
        error(
            f"File not found: {args.path}",
            f"List workspace contents with: brig files {cell_name}"
        )

    if file_path.is_dir():
        error(
            f"Cannot cat directory: {args.path}",
            f"List directory contents with: brig files {cell_name} {args.path}"
        )

    # Check file size limit (default 1MB).
    max_size = args.max_size * 1024 * 1024  # Convert MB to bytes.
    stat = file_path.stat()
    if stat.st_size > max_size:
        error(
            f"File too large ({stat.st_size} bytes)",
            "Use --max-size to increase the limit"
        )

    # Check for binary content.
    try:
        with open(file_path, "rb") as f:
            sample = f.read(8192)
        if b"\x00" in sample:
            if not args.force:
                error(
                    "File appears to be binary",
                    "Use --force to display anyway"
                )
    except IOError as e:
        error(
            f"Cannot read file: {e}",
            f"Check file permissions with: brig files {cell_name} {args.path}"
        )

    # Display file contents.
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            if args.lines:
                # Show only first N lines.
                for i, line in enumerate(f):
                    if i >= args.lines:
                        print(f"... (truncated at {args.lines} lines)")
                        break
                    print(line, end="")
            else:
                print(f.read())
    except IOError as e:
        error(
            f"Cannot read file: {e}",
            f"Check file permissions with: brig files {cell_name} {args.path}"
        )

    return 0


def apply_quarantine(path: Path, source_cell: str | None = None) -> bool:
    """Apply macOS quarantine attribute to a file or directory.

    This marks files as coming from an untrusted source, triggering
    Gatekeeper warnings if the user tries to execute them.

    Returns True if quarantine was applied successfully.
    """
    import platform
    if platform.system() != "Darwin":
        return False  # Only applies to macOS.

    try:
        # Quarantine attribute format: flags;timestamp;agent;uuid
        # 0x0082 = downloaded from internet, user confirmed
        import uuid
        ts = int(time.time())
        agent = f"brig:{source_cell}" if source_cell else "brig"
        qattr = f"0082;{ts:x};{agent};{uuid.uuid4()}"

        if path.is_dir():
            # Apply to all files in directory.
            for f in path.rglob("*"):
                if f.is_file():
                    run(["xattr", "-w", "com.apple.quarantine", qattr, str(f)],
                        check=False, capture=True)
        else:
            run(["xattr", "-w", "com.apple.quarantine", qattr, str(path)],
                check=False, capture=True)

        debug(f"Applied quarantine to {path}")
        return True
    except Exception as e:
        debug(f"Failed to apply quarantine: {e}")
        return False


def cmd_cp(args) -> int:
    """Copy files to/from a cell's workspace."""
    src = args.src
    dst = args.dst

    # Parse cell:path format.
    src_cell = None
    dst_cell = None

    if ":" in src and not src.startswith("/"):
        parts = src.split(":", 1)
        src_cell = parts[0]
        validate_cell_name(src_cell)
        src_path = parts[1]
    else:
        src_path = src

    if ":" in dst and not dst.startswith("/"):
        parts = dst.split(":", 1)
        dst_cell = parts[0]
        validate_cell_name(dst_cell)
        dst_path = parts[1]
    else:
        dst_path = dst

    # Validate: exactly one side must be a cell.
    if src_cell and dst_cell:
        error(
            "Cannot copy between cells directly",
            "Copy to local first, then copy into the destination cell"
        )
    if not src_cell and not dst_cell:
        error(
            "At least one path must be a cell",
            "Use cell:path syntax (e.g., brig cp mycell:/app/output.txt ./output.txt)"
        )

    # Get workspace paths with traversal validation.
    if src_cell:
        if not cell_exists(src_cell):
            error_cell_not_found(src_cell)
        workspace = _helpers.STATE_DIR / src_cell / "workspace"
        src_full = validate_workspace_path(workspace, src_path)
        dst_full = Path(dst_path)
    else:
        if not cell_exists(dst_cell):
            error_cell_not_found(dst_cell)
        workspace = _helpers.STATE_DIR / dst_cell / "workspace"
        src_full = Path(src_path)
        dst_full = validate_workspace_path(workspace, dst_path)

    # Check source exists.
    if not src_full.exists():
        error(
            f"Source not found: {src_full}",
            f"List workspace contents with: brig files {src_cell or dst_cell}"
        )

    # Sanitize mode checks.
    if args.sanitize and src_full.is_file():
        ext = src_full.suffix.lower()
        if ext in UNSAFE_EXTENSIONS:
            error(
                f"Blocked unsafe file type: {ext}",
                "This file type is always blocked for safety"
            )
        if ext in SCRIPT_EXTENSIONS and not args.allow_scripts:
            warn(f"Script file {src_full.name} - use --allow-scripts to permit")
            error(
                f"Blocked script file: {ext}",
                "Use --allow-scripts to permit script files"
            )
        if ext in OFFICE_EXTENSIONS and not args.allow_office:
            warn(f"Office file {src_full.name} - use --allow-office to permit")
            error(
                f"Blocked office file: {ext}",
                "Use --allow-office to permit office documents"
            )
    elif args.sanitize and src_full.is_dir():
        # Sanitize mode for directories: check all files in tree.
        for root, dirs, files in os.walk(src_full):
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in UNSAFE_EXTENSIONS:
                    error(
                        f"Sanitize: blocked unsafe file '{fname}' in directory copy",
                        "This file type is always blocked for safety"
                    )
                    return 1
                if ext in SCRIPT_EXTENSIONS and not getattr(args, "allow_scripts", False):
                    error(
                        f"Sanitize: blocked script '{fname}' in directory copy",
                        "Remove scripts from the directory or use --allow-scripts to permit"
                    )
                    return 1

    # Enforce workspace quota when copying INTO a cell.
    if dst_cell:
        within, current, max_bytes = _helpers.check_workspace_quota(dst_cell)
        if max_bytes is not None:
            # Estimate copy size.
            if src_full.is_dir():
                copy_size = sum(
                    f.stat().st_size for f in src_full.rglob("*") if f.is_file()
                )
            else:
                copy_size = src_full.stat().st_size
            if current + copy_size > max_bytes:
                error(
                    f"Copy would exceed workspace quota ({_helpers.format_size(current + copy_size)} / {_helpers.format_size(max_bytes)})",
                    f"Free space with: brig workspace clean {dst_cell}"
                )

    # Perform copy.
    import shutil
    try:
        if src_full.is_dir():
            # Never preserve symlinks from cell workspaces — a compromised cell
            # could create symlinks pointing outside the workspace.
            shutil.copytree(src_full, dst_full, symlinks=False)
        else:
            dst_full.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_full, dst_full)

        # Apply quarantine when copying FROM a cell (to local filesystem).
        if src_cell:
            if apply_quarantine(dst_full, src_cell):
                output(f"Copied {src} -> {dst} (quarantined)")
            else:
                output(f"Copied {src} -> {dst}")
        else:
            output(f"Copied {src} -> {dst}")

        return 0
    except Exception as e:
        error(
            f"Copy failed: {e}",
            "Check file permissions and disk space"
        )
    return 1
