"""
CLI handlers for secret management. Includes argparse registration so cli.py
doesn't have to know about the secrets subcommand structure.

Secrets are plain files in ~/.brig/secrets/. Each file is one secret.
When mounted into a cell:
  - File mounted read-only at /run/secrets/<name>
  - Env var set: <NAME>_FILE=/run/secrets/<name>
    (name uppercased, hyphens to underscores, extension stripped)

Example:
  brig secrets add api-key          # prompts for value or reads stdin
  brig run --secret api-key alpine  # mounts as /run/secrets/api-key
                                    # sets API_KEY_FILE=/run/secrets/api-key
"""

from __future__ import annotations

import os
import sys
from typing import Any

from brig.config import HostPaths
from brig.errors import BrigError
from brig.ops.logging import info, output, warn


def register_parser(sub) -> None:
    """Register the `brig secrets` subcommand tree."""
    p = sub.add_parser("secrets", help="Manage secrets")
    s = p.add_subparsers(dest="secrets_command", required=True)
    s.add_parser("list", help="List all secrets")
    p_add = s.add_parser("add", help="Add a secret")
    p_add.add_argument("name", help="Secret name")
    p_add.add_argument("--value", help="Secret value (insecure — prefer stdin)")
    p_add.add_argument("--from-file", help="Read value from file")
    p_add.add_argument("--force", action="store_true", help="Overwrite existing")
    p_rm = s.add_parser("rm", help="Remove a secret")
    p_rm.add_argument("name", help="Secret name")
    p_rm.add_argument("-y", "--yes", action="store_true",
                      help="Skip the confirmation prompt")


DISPATCH = {}  # Populated below after handlers are defined.


def cmd_secrets_list(args: Any) -> int:
    """Handle `brig secrets list`."""
    secrets_dir = HostPaths.SECRETS_DIR
    if not secrets_dir.exists():
        output("No secrets directory. Run: brig init")
        return 0

    secrets = sorted(f.name for f in secrets_dir.iterdir() if f.is_file())
    if not secrets:
        output("No secrets stored")
        output("")
        output("Add one with: brig secrets add <name>")
        return 0

    output(f"{'NAME':<30} {'SIZE':<10} {'MOUNT PATH'}")
    output("-" * 70)
    for name in secrets:
        path = secrets_dir / name
        size = path.stat().st_size
        env_name = name.rsplit(".", 1)[0].upper().replace("-", "_") + "_FILE"
        output(f"{name:<30} {size:<10} /run/secrets/{name}")
        output(f"{'':30} {'':10} {env_name}=/run/secrets/{name}")

    output("")
    output(f"Secrets directory: {secrets_dir}")
    return 0


def cmd_secrets_add(args: Any) -> int:
    """Handle `brig secrets add <name>`.

    Reads value from:
      1. --value flag
      2. --file flag (copy file contents)
      3. stdin (if piped)
      4. interactive prompt (if TTY)
    """
    secrets_dir = HostPaths.SECRETS_DIR
    secrets_dir.mkdir(parents=True, exist_ok=True)
    secrets_dir.chmod(0o700)

    name = args.name
    # Validate name.
    if "/" in name or ".." in name:
        raise BrigError("Secret name must not contain / or ..")

    path = secrets_dir / name
    if path.exists() and not getattr(args, "force", False):
        raise BrigError(
            f"Secret '{name}' already exists",
            suggestion="Use --force to overwrite",
        )

    # Get value.
    value_source = getattr(args, "value", None)
    file_source = getattr(args, "from_file", None)

    if value_source:
        value = value_source
    elif file_source:
        from pathlib import Path
        src = Path(file_source)
        if not src.exists():
            raise BrigError(f"File not found: {file_source}")
        value = src.read_text()
    elif not sys.stdin.isatty():
        # Piped input.
        value = sys.stdin.read()
    else:
        # Interactive prompt.
        import getpass
        value = getpass.getpass(f"Enter value for '{name}': ")

    # Write with restrictive permissions.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)

    env_name = name.rsplit(".", 1)[0].upper().replace("-", "_") + "_FILE"
    info(f"Secret '{name}' saved")
    output(f"  Mount: /run/secrets/{name}")
    output(f"  Env:   {env_name}=/run/secrets/{name}")
    return 0


def cmd_secrets_rm(args: Any) -> int:
    """Handle `brig secrets rm <name>`.

    Requires --yes for non-interactive use, or an interactive y/N confirmation,
    because secret deletion is irreversible and a typo at the prompt
    permanently destroys credentials.
    """
    path = HostPaths.SECRETS_DIR / args.name
    if not path.exists():
        raise BrigError(f"Secret '{args.name}' not found")

    if not getattr(args, "yes", False):
        if not sys.stdin.isatty():
            raise BrigError(
                f"Refusing to delete secret '{args.name}' without confirmation",
                suggestion="Pass --yes to skip the prompt in non-interactive use",
            )
        try:
            answer = input(
                f"Delete secret '{args.name}'? This cannot be undone. [y/N]: "
            )
        except (EOFError, KeyboardInterrupt):
            output("")
            raise BrigError("Aborted")
        if answer.strip().lower() not in ("y", "yes"):
            output("Aborted")
            return 1

    path.unlink()
    info(f"Secret '{args.name}' removed")
    return 0


DISPATCH = {
    "list": cmd_secrets_list,
    "add": cmd_secrets_add,
    "rm": cmd_secrets_rm,
}
