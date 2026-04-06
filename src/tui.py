#!/usr/bin/env python3
"""
Terminal UI for Brig.

Provides an interactive dashboard for monitoring and managing cells.

Views:
    - Dashboard: Overview of all cells with status
    - Cell Detail: Deep dive into single cell
    - Logs: Real-time log streaming
    - Metrics: Live request metrics
    - Policy: View/edit allow/deny rules

Usage:
    brig tui              # Launch full dashboard
    brig tui --view logs  # Jump to logs view
    brig tui --cell foo   # Focus on specific cell

Keyboard shortcuts:
    j/k or arrows: Navigate
    Enter: Select/expand
    q: Quit or back
    r: Refresh
    /: Search
    ?: Help
"""

import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

from brig.config import CELL_NAME_PATTERN

# Check for textual availability.
try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
    from textual.reactive import reactive
    from textual.screen import Screen
    from textual.timer import Timer
    from textual.widgets import (
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        ListItem,
        ListView,
        Log,
        Placeholder,
        Static,
        TabbedContent,
        TabPane,
        Tree,
    )
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from brig.config import CONTAINER_PREFIX, PROXY_NAME

# Metrics socket path.
METRICS_SOCKET = Path("/var/run/cells/metrics.sock")

# Policy directory.
POLICY_DIR = Path("/var/run/brig/policies")

# Refresh interval in seconds.
REFRESH_INTERVAL = 2.0


def get_cells() -> list[dict]:
    """Fetch list of all cells from podman."""
    try:
        result = subprocess.run(
            ["podman", "ps", "-a", "--format", "json", "--filter", f"name={CONTAINER_PREFIX}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        containers = []
        if result.stdout.strip():
            containers = json.loads(result.stdout)

        cells = []
        for c in containers:
            name = c.get("Names", [""])[0]
            if name.startswith(CONTAINER_PREFIX) and name != PROXY_NAME:
                cell_name = name[len(CONTAINER_PREFIX):]
                cells.append({
                    "name": cell_name,
                    "status": c.get("State", "unknown"),
                    "image": c.get("Image", "unknown"),
                    "created": c.get("Created", "unknown"),
                })
        return cells
    except Exception:
        return []


def _validate_tui_cell_name(cell_name: str) -> bool:
    """Validate cell name before use in subprocess calls."""
    return bool(cell_name and CELL_NAME_PATTERN.match(cell_name))


def get_cell_stats(cell_name: str) -> dict:
    """Fetch resource stats for a specific cell."""
    if not _validate_tui_cell_name(cell_name):
        return {}
    try:
        result = subprocess.run(
            ["podman", "stats", "--no-stream", "--format", "json",
             f"{CONTAINER_PREFIX}{cell_name}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            stats = json.loads(result.stdout)
            if stats:
                result_dict: dict = stats[0]
                return result_dict
    except Exception:
        pass
    return {}


def get_metrics() -> dict:
    """Fetch metrics from warden via Unix socket."""
    if not METRICS_SOCKET.exists():
        return {}

    # Cap response at 10MB to prevent unbounded memory use.
    max_response = 10 * 1024 * 1024
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(5.0)
        sock.connect(str(METRICS_SOCKET))
        sock.sendall(b"all")
        # Read response in loop to handle payloads larger than buffer.
        chunks = []
        total = 0
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_response:
                return {}
            chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8")
        data: dict = json.loads(response)
        return data
    except Exception:
        return {}
    finally:
        sock.close()


def get_cell_policy(cell_name: str) -> dict:
    """Load policy for a specific cell."""
    # Validate cell name to prevent path traversal.
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,62}$", cell_name):
        return {"allow": [], "deny": []}

    policy_file = POLICY_DIR / f"{cell_name}.json"
    # Ensure resolved path stays under POLICY_DIR.
    try:
        policy_file.resolve().relative_to(POLICY_DIR.resolve())
    except ValueError:
        return {"allow": [], "deny": []}

    if not policy_file.exists():
        return {"allow": [], "deny": []}

    try:
        with open(policy_file, "r") as f:
            data: dict = json.load(f)
            return data
    except Exception:
        return {"allow": [], "deny": []}


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences and other terminal control codes."""
    # Remove ANSI CSI sequences (e.g., colors, cursor movement).
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    # Remove OSC sequences (e.g., title setting, hyperlinks).
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', text)
    # Remove other escape sequences (SS2, SS3, DCS, PM, APC).
    text = re.sub(r'\x1b[NOPXn^_][^\x1b]*(?:\x1b\\)?', '', text)
    # Remove bare escape + single char sequences.
    text = re.sub(r'\x1b[^[\]NOPXn^_]', '', text)
    # Remove remaining control characters except newline and tab.
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


def get_cell_logs(cell_name: str, tail: int = 50) -> str:
    """Fetch recent logs for a cell."""
    if not _validate_tui_cell_name(cell_name):
        return ""
    try:
        result = subprocess.run(
            ["podman", "logs", "--tail", str(tail), f"{CONTAINER_PREFIX}{cell_name}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # Sanitize to prevent terminal escape injection from untrusted containers.
            return _strip_ansi(result.stdout + result.stderr)
    except Exception:
        pass
    return ""


def is_warden_running() -> bool:
    """Check if warden proxy is running."""
    try:
        result = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Running}}", PROXY_NAME],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception:
        return False


def run_cell_action(cell_name: str, action: str) -> tuple[bool, str]:
    """Execute an action on a cell. Returns (success, message)."""
    if not _validate_tui_cell_name(cell_name):
        return False, f"Invalid cell name: {cell_name}"
    cmd_map = {
        "stop": ["podman", "stop", f"{CONTAINER_PREFIX}{cell_name}"],
        "start": ["podman", "start", f"{CONTAINER_PREFIX}{cell_name}"],
        "kill": ["podman", "kill", f"{CONTAINER_PREFIX}{cell_name}"],
        "pause": ["podman", "pause", f"{CONTAINER_PREFIX}{cell_name}"],
        "unpause": ["podman", "unpause", f"{CONTAINER_PREFIX}{cell_name}"],
        "rm": ["podman", "rm", "-f", f"{CONTAINER_PREFIX}{cell_name}"],
    }

    if action not in cmd_map:
        return False, f"Unknown action: {action}"

    try:
        result = subprocess.run(
            cmd_map[action],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, f"{action.capitalize()} successful"
        else:
            return False, result.stderr.strip() or f"{action} failed"
    except subprocess.TimeoutExpired:
        return False, f"{action} timed out"
    except Exception as e:
        return False, str(e)


# Only define textual classes if available.
if TEXTUAL_AVAILABLE:

    class CellsTable(DataTable):
        """Table showing all cells with status."""

        def __init__(self):
            super().__init__()
            self.cursor_type = "row"

        def on_mount(self) -> None:
            """Set up table columns."""
            self.add_column("Name", key="name", width=20)
            self.add_column("Status", key="status", width=12)
            self.add_column("Image", key="image", width=30)
            self.add_column("Requests", key="requests", width=10)
            self.add_column("Blocked", key="blocked", width=10)

        def refresh_cells(self, cells: list[dict], metrics: dict) -> None:
            """Update table with current cell data."""
            self.clear()

            cell_metrics = metrics.get("cells", {})

            for cell in cells:
                name = cell["name"]
                status = cell["status"]
                image = cell["image"]
                if len(image) > 28:
                    image = image[:25] + "..."

                # Get metrics for this cell.
                m = cell_metrics.get(name, {})
                requests = str(m.get("total_requests", 0))
                blocked = str(m.get("blocked_requests", 0))

                self.add_row(name, status, image, requests, blocked, key=name)
                # Color the status cell.
                row_key = name
                try:
                    self.update_cell(row_key, "status", status, update_width=False)
                except Exception:
                    pass

    class StatusBar(Static):
        """Status bar showing warden and cell counts."""

        def __init__(self):
            super().__init__()

        def update_status(self, warden_running: bool, cell_count: int, running_count: int) -> None:
            """Update status bar content."""
            warden_status = "[green]Running[/]" if warden_running else "[red]Stopped[/]"
            self.update(
                f"Warden: {warden_status} | "
                f"Cells: {cell_count} total, {running_count} running | "
                f"Press [bold]?[/] for help"
            )

    class CellDetailPanel(Vertical):
        """Panel showing detailed info for selected cell."""

        def __init__(self):
            super().__init__()
            self.cell_name: Optional[str] = None

        def compose(self) -> ComposeResult:
            yield Label("Select a cell to view details", id="detail-header")
            yield Static("", id="detail-stats")
            yield Static("", id="detail-metrics")
            yield Static("", id="detail-policy")

        def update_cell(self, cell_name: str, stats: dict, metrics: dict, policy: dict) -> None:
            """Update panel with cell information."""
            self.cell_name = cell_name

            # Header.
            header = self.query_one("#detail-header", Label)
            header.update(f"[bold]{cell_name}[/]")

            # Stats.
            stats_widget = self.query_one("#detail-stats", Static)
            if stats:
                stats_text = (
                    f"[bold]Resources[/]\n"
                    f"  CPU: {stats.get('CPUPerc', 'N/A')}\n"
                    f"  Memory: {stats.get('MemUsage', 'N/A')} ({stats.get('MemPerc', 'N/A')})\n"
                    f"  PIDs: {stats.get('Pids', 'N/A')}"
                )
            else:
                stats_text = "[bold]Resources[/]\n  (not running)"
            stats_widget.update(stats_text)

            # Metrics.
            metrics_widget = self.query_one("#detail-metrics", Static)
            cell_metrics = metrics.get("cells", {}).get(cell_name, {})
            if cell_metrics:
                metrics_text = (
                    f"[bold]Metrics[/]\n"
                    f"  Total requests: {cell_metrics.get('total_requests', 0)}\n"
                    f"  Blocked: {cell_metrics.get('blocked_requests', 0)}\n"
                    f"  Rate limited: {cell_metrics.get('rate_limited_requests', 0)}\n"
                    f"  Errors: {cell_metrics.get('error_requests', 0)}\n"
                    f"  Bytes sent: {cell_metrics.get('bytes_sent', 0)}\n"
                    f"  Bytes received: {cell_metrics.get('bytes_received', 0)}\n"
                    f"  Latency p50: {cell_metrics.get('latency_p50_ms', 0):.1f}ms\n"
                    f"  Latency p95: {cell_metrics.get('latency_p95_ms', 0):.1f}ms\n"
                    f"  Latency p99: {cell_metrics.get('latency_p99_ms', 0):.1f}ms"
                )
            else:
                metrics_text = "[bold]Metrics[/]\n  (no data)"
            metrics_widget.update(metrics_text)

            # Policy.
            policy_widget = self.query_one("#detail-policy", Static)
            allow_count = len(policy.get("allow", []))
            deny_count = len(policy.get("deny", []))
            policy_text = (
                f"[bold]Policy[/]\n"
                f"  Allow rules: {allow_count}\n"
                f"  Deny rules: {deny_count}"
            )
            policy_widget.update(policy_text)

    class LogsPanel(ScrollableContainer):
        """Panel showing logs for a cell."""

        def __init__(self):
            super().__init__()
            self.cell_name: Optional[str] = None

        def compose(self) -> ComposeResult:
            yield Log(id="logs-output", highlight=True, auto_scroll=True)

        def update_logs(self, cell_name: str, logs: str) -> None:
            """Update logs display."""
            self.cell_name = cell_name
            log_widget = self.query_one("#logs-output", Log)
            log_widget.clear()
            for line in logs.split("\n"):
                log_widget.write_line(line)

    class HelpScreen(Screen):
        """Help screen showing keyboard shortcuts."""

        BINDINGS = [
            Binding("escape", "dismiss", "Close"),
            Binding("q", "dismiss", "Close"),
        ]

        def compose(self) -> ComposeResult:
            yield Container(
                Static(
                    "[bold]Brig TUI Help[/]\n\n"
                    "[bold]Navigation[/]\n"
                    "  j / ↓     Move down\n"
                    "  k / ↑     Move up\n"
                    "  Enter    Select / expand\n"
                    "  Tab      Next pane\n"
                    "  q        Quit or back\n\n"
                    "[bold]Actions[/]\n"
                    "  s        Stop selected cell\n"
                    "  S        Start selected cell\n"
                    "  K        Kill selected cell\n"
                    "  p        Pause selected cell\n"
                    "  u        Unpause selected cell\n"
                    "  x        Shell into cell\n\n"
                    "[bold]Views[/]\n"
                    "  1        Dashboard view\n"
                    "  2        Logs view\n"
                    "  3        Metrics view\n"
                    "  4        Policy view\n\n"
                    "[bold]Other[/]\n"
                    "  r        Refresh\n"
                    "  /        Search\n"
                    "  ?        This help\n\n"
                    "Press [bold]q[/] or [bold]Escape[/] to close",
                    id="help-content",
                ),
                id="help-container",
            )

        def action_dismiss(self) -> None:
            """Close help screen."""
            self.app.pop_screen()

    class BrigTUI(App):
        """Main Brig TUI application."""

        CSS = """
        Screen {
            background: $surface;
        }

        #main-container {
            layout: grid;
            grid-size: 2 1;
            grid-columns: 2fr 1fr;
        }

        #cells-table {
            height: 100%;
            border: solid $primary;
        }

        #detail-panel {
            height: 100%;
            border: solid $secondary;
            padding: 1;
        }

        #status-bar {
            dock: bottom;
            height: 1;
            background: $primary;
            color: $text;
            padding: 0 1;
        }

        #help-container {
            align: center middle;
            width: 60;
            height: auto;
            border: thick $primary;
            background: $surface;
            padding: 2;
        }

        #help-content {
            width: 100%;
        }

        #logs-output {
            height: 100%;
        }

        TabbedContent {
            height: 100%;
        }

        TabPane {
            padding: 1;
        }

        .notification {
            dock: bottom;
            height: 1;
            background: $warning;
            color: $text;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("?", "help", "Help"),
            Binding("r", "refresh", "Refresh"),
            Binding("s", "stop_cell", "Stop", show=False),
            Binding("S", "start_cell", "Start", show=False),
            Binding("K", "kill_cell", "Kill", show=False),
            Binding("p", "pause_cell", "Pause", show=False),
            Binding("u", "unpause_cell", "Unpause", show=False),
            Binding("x", "shell_cell", "Shell", show=False),
            Binding("1", "view_dashboard", "Dashboard", show=False),
            Binding("2", "view_logs", "Logs", show=False),
            Binding("3", "view_metrics", "Metrics", show=False),
            Binding("4", "view_policy", "Policy", show=False),
            Binding("j", "cursor_down", "Down", show=False),
            Binding("k", "cursor_up", "Up", show=False),
        ]

        TITLE = "Brig"
        SUB_TITLE = "Cell Management"

        # Reactive state.
        cells: reactive[list] = reactive(list)
        metrics: reactive[dict] = reactive(dict)
        selected_cell: reactive[Optional[str]] = reactive(None)
        initial_view: str = "dashboard"
        initial_cell: Optional[str] = None

        def __init__(self, initial_view: str = "dashboard", initial_cell: Optional[str] = None):
            super().__init__()
            self.initial_view = initial_view
            self.initial_cell = initial_cell
            self._refresh_timer: Optional[Timer] = None

        def compose(self) -> ComposeResult:
            """Create child widgets."""
            yield Header()
            yield TabbedContent(
                TabPane("Dashboard", Container(
                    Horizontal(
                        CellsTable(),
                        CellDetailPanel(),
                        id="main-container",
                    ),
                ), id="tab-dashboard"),
                TabPane("Logs", LogsPanel(), id="tab-logs"),
                TabPane("Metrics", Static("Select a cell to view metrics", id="metrics-view"), id="tab-metrics"),
                TabPane("Policy", Static("Select a cell to view policy", id="policy-view"), id="tab-policy"),
            )
            yield StatusBar()
            yield Footer()

        def on_mount(self) -> None:
            """Start refresh timer on mount."""
            self._refresh_timer = self.set_interval(REFRESH_INTERVAL, self._refresh_data)
            self._refresh_data()

            # Switch to initial view if specified.
            if self.initial_view != "dashboard":
                view_map = {
                    "logs": "tab-logs",
                    "metrics": "tab-metrics",
                    "policy": "tab-policy",
                }
                if self.initial_view in view_map:
                    tabs = self.query_one(TabbedContent)
                    tabs.active = view_map[self.initial_view]

            # Select initial cell if specified.
            if self.initial_cell:
                self.selected_cell = self.initial_cell

        def _refresh_data(self) -> None:
            """Refresh all data from system."""
            self.cells = get_cells()
            self.metrics = get_metrics()

            # Update table.
            try:
                table = self.query_one(CellsTable)
                table.refresh_cells(self.cells, self.metrics)
            except Exception:
                pass

            # Update status bar.
            try:
                status_bar = self.query_one(StatusBar)
                warden_running = is_warden_running()
                running_count = sum(1 for c in self.cells if c["status"] == "running")
                status_bar.update_status(warden_running, len(self.cells), running_count)
            except Exception:
                pass

            # Update detail panel if cell selected.
            if self.selected_cell:
                self._update_detail_panel()

        def _update_detail_panel(self) -> None:
            """Update the detail panel for selected cell."""
            if not self.selected_cell:
                return

            try:
                detail_panel = self.query_one(CellDetailPanel)
                stats = get_cell_stats(self.selected_cell)
                policy = get_cell_policy(self.selected_cell)
                detail_panel.update_cell(self.selected_cell, stats, self.metrics, policy)

                # Update logs panel.
                logs_panel = self.query_one(LogsPanel)
                logs = get_cell_logs(self.selected_cell)
                logs_panel.update_logs(self.selected_cell, logs)

                # Update metrics view.
                metrics_view = self.query_one("#metrics-view", Static)
                cell_metrics = self.metrics.get("cells", {}).get(self.selected_cell, {})
                if cell_metrics:
                    metrics_text = (
                        f"[bold]{self.selected_cell} Metrics[/]\n\n"
                        f"[bold]Requests[/]\n"
                        f"  Total: {cell_metrics.get('total_requests', 0)}\n"
                        f"  Blocked: {cell_metrics.get('blocked_requests', 0)}\n"
                        f"  Rate limited: {cell_metrics.get('rate_limited_requests', 0)}\n"
                        f"  Errors: {cell_metrics.get('error_requests', 0)}\n\n"
                        f"[bold]Bandwidth[/]\n"
                        f"  Sent: {cell_metrics.get('bytes_sent', 0):,} bytes\n"
                        f"  Received: {cell_metrics.get('bytes_received', 0):,} bytes\n\n"
                        f"[bold]Latency[/]\n"
                        f"  p50: {cell_metrics.get('latency_p50_ms', 0):.2f}ms\n"
                        f"  p95: {cell_metrics.get('latency_p95_ms', 0):.2f}ms\n"
                        f"  p99: {cell_metrics.get('latency_p99_ms', 0):.2f}ms"
                    )
                else:
                    metrics_text = f"[bold]{self.selected_cell}[/]\n\nNo metrics data available"
                metrics_view.update(metrics_text)

                # Update policy view.
                policy_view = self.query_one("#policy-view", Static)
                policy = get_cell_policy(self.selected_cell)
                allow_rules = policy.get("allow", [])
                deny_rules = policy.get("deny", [])
                policy_text = f"[bold]{self.selected_cell} Policy[/]\n\n"
                policy_text += "[bold]Allow Rules[/]\n"
                if allow_rules:
                    for rule in allow_rules[:20]:
                        policy_text += f"  [green]+[/] {rule}\n"
                    if len(allow_rules) > 20:
                        policy_text += f"  ... and {len(allow_rules) - 20} more\n"
                else:
                    policy_text += "  (none)\n"
                policy_text += "\n[bold]Deny Rules[/]\n"
                if deny_rules:
                    for rule in deny_rules[:20]:
                        policy_text += f"  [red]-[/] {rule}\n"
                    if len(deny_rules) > 20:
                        policy_text += f"  ... and {len(deny_rules) - 20} more\n"
                else:
                    policy_text += "  (none)"
                policy_view.update(policy_text)

            except Exception:
                pass

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            """Handle cell selection in table."""
            if event.row_key:
                self.selected_cell = str(event.row_key.value)
                self._update_detail_panel()

        def action_help(self) -> None:
            """Show help screen."""
            self.push_screen(HelpScreen())

        def action_refresh(self) -> None:
            """Manual refresh."""
            self._refresh_data()
            self.notify("Refreshed")

        def action_quit(self) -> None:
            """Quit application."""
            self.exit()

        def action_view_dashboard(self) -> None:
            """Switch to dashboard view."""
            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-dashboard"

        def action_view_logs(self) -> None:
            """Switch to logs view."""
            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-logs"

        def action_view_metrics(self) -> None:
            """Switch to metrics view."""
            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-metrics"

        def action_view_policy(self) -> None:
            """Switch to policy view."""
            tabs = self.query_one(TabbedContent)
            tabs.active = "tab-policy"

        def _get_selected_cell(self) -> str | None:
            """Get currently selected cell name."""
            if self.selected_cell:
                return str(self.selected_cell)
            # Try to get from table selection.
            try:
                table = self.query_one(CellsTable)
                if table.cursor_row is not None and table.row_count > 0:
                    row_key = table.get_row_at(table.cursor_row)
                    if row_key:
                        return str(row_key[0])
            except Exception:
                pass
            return None

        def _run_action(self, action: str) -> None:
            """Run action on selected cell."""
            cell_name = self._get_selected_cell()
            if not cell_name:
                self.notify("No cell selected", severity="warning")
                return

            success, message = run_cell_action(cell_name, action)
            if success:
                self.notify(f"{cell_name}: {message}", severity="information")
                self._refresh_data()
            else:
                self.notify(f"{cell_name}: {message}", severity="error")

        def action_stop_cell(self) -> None:
            """Stop selected cell."""
            self._run_action("stop")

        def action_start_cell(self) -> None:
            """Start selected cell."""
            self._run_action("start")

        def action_kill_cell(self) -> None:
            """Kill selected cell."""
            self._run_action("kill")

        def action_pause_cell(self) -> None:
            """Pause selected cell."""
            self._run_action("pause")

        def action_unpause_cell(self) -> None:
            """Unpause selected cell."""
            self._run_action("unpause")

        def action_shell_cell(self) -> None:
            """Open shell in selected cell."""
            cell_name = self._get_selected_cell()
            if not cell_name:
                self.notify("No cell selected", severity="warning")
                return

            # Suspend TUI and run shell.
            self.exit(result=("shell", cell_name))

        def action_cursor_down(self) -> None:
            """Move cursor down (vim j key)."""
            try:
                table = self.query_one(CellsTable)
                table.action_cursor_down()
            except Exception:
                pass

        def action_cursor_up(self) -> None:
            """Move cursor up (vim k key)."""
            try:
                table = self.query_one(CellsTable)
                table.action_cursor_up()
            except Exception:
                pass


def run_tui(view: str = "dashboard", cell: Optional[str] = None) -> int:
    """Run the TUI application. Returns exit code."""
    if not TEXTUAL_AVAILABLE:
        print("ERROR: textual library not installed.", file=sys.stderr)
        print("Install with: pip install textual", file=sys.stderr)
        return 1

    app = BrigTUI(initial_view=view, initial_cell=cell)
    result = app.run()

    # Handle shell action.
    if isinstance(result, tuple) and result[0] == "shell":
        cell_name = result[1]
        if not _validate_tui_cell_name(cell_name):
            print(f"ERROR: Invalid cell name: {cell_name}", file=sys.stderr)
            return 1
        subprocess.run(
            ["podman", "exec", "-it", f"{CONTAINER_PREFIX}{cell_name}", "/bin/sh"],
        )

    return 0


def main() -> int:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Brig Terminal UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--view",
        choices=["dashboard", "logs", "metrics", "policy"],
        default="dashboard",
        help="Initial view to display",
    )
    parser.add_argument(
        "--cell",
        metavar="NAME",
        help="Focus on specific cell",
    )

    args = parser.parse_args()
    return run_tui(view=args.view, cell=args.cell)


if __name__ == "__main__":
    sys.exit(main())
