"""
Secret path validation.

Defends against symlink-based path traversal out of the secrets directory
(e.g. ln -s /etc/passwd ~/.brig/secrets/legit).
"""

from __future__ import annotations

from pathlib import Path


def validate_secret_path(secret_name: str, secrets_dir: Path) -> Path:
    """Resolve secrets_dir/secret_name and verify it stays within secrets_dir.

    Returns the resolved Path. Raises:
      - ValueError if the resolved path is outside secrets_dir.
      - FileNotFoundError if the secret does not exist after resolution.
    """
    secret_path = secrets_dir / secret_name
    resolved = secret_path.resolve()
    try:
        resolved.relative_to(secrets_dir.resolve())
    except ValueError:
        raise ValueError(
            f"Secret path escapes secrets directory: {secret_name}"
        )
    if not resolved.exists():
        raise FileNotFoundError(
            f"Secret not found: {secret_name}"
        )
    return resolved
