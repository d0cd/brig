"""TUI launcher command."""

import importlib

from brig.commands._helpers import error


def cmd_tui(args) -> int:
    """Launch interactive terminal UI."""
    run_tui = None
    for module_name in ("tui", "src.tui"):
        try:
            mod = importlib.import_module(module_name)
            run_tui = getattr(mod, "run_tui", None)
            if run_tui:
                break
        except ImportError:
            continue

    if run_tui is None:
        error(
            "TUI module not found",
            "Install with: pip install brig[tui]"
        )
        return 1

    view = getattr(args, "view", "dashboard")
    cell = getattr(args, "cell", None)

    return int(run_tui(view=view, cell=cell))
