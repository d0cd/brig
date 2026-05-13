"""
Error types for Brig.

CLI entry points catch BrigError and call sys.exit() with the appropriate code.
"""


class BrigError(Exception):
    """Base error for brig operations."""

    def __init__(
        self,
        message: str,
        returncode: int = 1,
        stderr: str = "",
        suggestion: str | None = None,
    ):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        self.suggestion = suggestion
