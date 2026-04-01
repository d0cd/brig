"""TUI launcher command."""

from brig.commands._helpers import error


def cmd_tui(args) -> int:
    """Launch interactive terminal UI."""
    # Import here to avoid loading textual unless needed.
    run_tui = None
    try:
        from tui import run_tui
    except ImportError:
        try:
            from src.tui import run_tui
        except ImportError:
            pass

    if run_tui is None:
        error(
            "TUI module not found",
            "Install with: pip install brig[tui]"
        )

    view = getattr(args, "view", "dashboard")
    cell = getattr(args, "cell", None)

    return run_tui(view=view, cell=cell)
