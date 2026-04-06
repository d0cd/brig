"""Web dashboard launcher command."""

import importlib

from brig.commands._helpers import error


def cmd_dashboard(args) -> int:
    """Launch web dashboard."""
    run_dashboard = None
    for module_name in ("dashboard", "src.dashboard"):
        try:
            mod = importlib.import_module(module_name)
            run_dashboard = getattr(mod, "run_dashboard", None)
            if run_dashboard:
                break
        except ImportError:
            continue

    if run_dashboard is None:
        error(
            "Dashboard module not found",
            "Ensure brig is installed correctly"
        )
        return 1

    port = getattr(args, "port", 8080)
    return int(run_dashboard(port=port))
