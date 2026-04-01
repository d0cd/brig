"""Web dashboard launcher command."""

from brig.commands._helpers import error


def cmd_dashboard(args) -> int:
    """Launch web dashboard."""
    run_dashboard = None
    try:
        from dashboard import run_dashboard
    except ImportError:
        try:
            from src.dashboard import run_dashboard
        except ImportError:
            pass

    if run_dashboard is None:
        error(
            "Dashboard module not found",
            "Ensure brig is installed correctly"
        )

    port = getattr(args, "port", 8080)
    return run_dashboard(port=port)
