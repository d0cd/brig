"""
Brig CLI commands.
"""

from .run import cmd_run
from .lifecycle import cmd_stop, cmd_kill, cmd_rm, cmd_start, cmd_pause, cmd_unpause
from .inspect import cmd_list, cmd_logs, cmd_exec, cmd_attach, cmd_top, cmd_stats
from .inspect import cmd_inspect, cmd_export, cmd_diff
from .files import cmd_files, cmd_cat, cmd_cp
from .network import cmd_network, cmd_diagnose
from .admin import cmd_verify, cmd_health, cmd_metrics, cmd_history
from .policy import cmd_policy_show, cmd_policy_set

__all__ = [
    "cmd_run",
    "cmd_stop", "cmd_kill", "cmd_rm", "cmd_start", "cmd_pause", "cmd_unpause",
    "cmd_list", "cmd_logs", "cmd_exec", "cmd_attach", "cmd_top", "cmd_stats",
    "cmd_inspect", "cmd_export", "cmd_diff",
    "cmd_files", "cmd_cat", "cmd_cp",
    "cmd_network", "cmd_diagnose",
    "cmd_verify", "cmd_health", "cmd_metrics", "cmd_history",
    "cmd_policy_show", "cmd_policy_set",
]
