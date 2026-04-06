"""TUI launcher command."""

from brig.commands._helpers import error


def cmd_tui(args) -> int:
    """Launch interactive terminal UI."""
    # Import here to avoid loading textual unless needed.
    run_tui_fn = None
    try:
        from tui import run_tui as _run_tui
        run_tui_fn = _run_tui
    except ImportError:
        try:
            from src.tui import run_tui as _run_tui  # type: ignore[no-redef]
            run_tui_fn = _run_tui
        except ImportError:
            pass

    if run_tui_fn is None:
        error(
            "TUI module not found",
            "Install with: pip install brig[tui]"
        )
        return 1

    view = getattr(args, "view", "dashboard")
    cell = getattr(args, "cell", None)

    return int(run_tui_fn(view=view, cell=cell))
