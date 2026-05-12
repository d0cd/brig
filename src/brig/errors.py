"""
Error types and error helper functions for Brig.

All error helpers raise BrigError so SDK consumers get a catchable exception.
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


def error(msg: str, suggestion: str | None = None) -> None:
    """Raise BrigError with message and optional suggestion."""
    raise BrigError(msg, suggestion=suggestion)


def error_cell_not_found(cell_name: str) -> None:
    """Error helper for cell not found."""
    raise BrigError(
        f"Cell '{cell_name}' does not exist",
        suggestion="Use 'brig list' to see available cells, or 'brig run' to create one",
    )


def error_cell_not_running(cell_name: str) -> None:
    """Error helper for cell not running."""
    raise BrigError(
        f"Cell '{cell_name}' is not running",
        suggestion=f"Use 'brig start {cell_name}' to start it",
    )


def error_proxy_not_running() -> None:
    """Error helper for proxy not running."""
    raise BrigError(
        "Warden proxy is not running",
        suggestion="Start the proxy with: warden start",
    )
