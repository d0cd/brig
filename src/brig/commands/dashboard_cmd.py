"""Web dashboard launcher command."""

from brig.commands._helpers import error


def cmd_dashboard(args) -> int:
    """Launch web dashboard."""
    run_dashboard_fn = None
    try:
        from dashboard import run_dashboard as _run_dashboard
        run_dashboard_fn = _run_dashboard
    except ImportError:
        try:
            from src.dashboard import run_dashboard as _run_dashboard  # type: ignore[no-redef]
            run_dashboard_fn = _run_dashboard
        except ImportError:
            pass

    if run_dashboard_fn is None:
        error(
            "Dashboard module not found",
            "Ensure brig is installed correctly"
        )
        return 1

    port = getattr(args, "port", 8080)
    return int(run_dashboard_fn(port=port))
