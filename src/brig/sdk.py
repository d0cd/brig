"""
Brig Python SDK - Programmatic cell management.

Thin async wrapper over the brig CLI. Uses subprocess to call the brig
binary and parses JSON output. No new daemon or server process needed.

Compatible with Python 3.9+.

Usage:
    from brig.sdk import Brig

    # Async usage
    async def main():
        b = Brig()
        cell = await b.run(
            name="agent-a",
            image="python:3.12",
            command=["python", "agent.py"],
            profile="supervised",
            policy_allow=["api.openai.com"],
            secrets=["openai-key"],
            timeout="2h",
        )
        result = await cell.wait()
        print(f"Exit code: {result.exit_code}")

    # Sync usage
    b = Brig()
    cell = b.run_sync(name="test", image="alpine", command=["echo", "hello"])
    result = cell.wait_sync()
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

# Validation patterns for SDK inputs.
_CELL_NAME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,62}$')
_ENV_KEY_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
_DEFAULT_TIMEOUT = 300  # Default subprocess timeout in seconds.


@dataclass
class CellResult:
    """Result of a cell execution."""
    cell: str
    exit_code: int


@dataclass
class CellInfo:
    """Information about a cell."""
    name: str
    status: str
    image: str


@dataclass
class CellRunResult:
    """Result of running a new cell."""
    cell: str
    cell_id: str
    image: str
    status: str
    network: str
    runtime: str
    timeout_seconds: Optional[int] = None
    labels: dict = field(default_factory=dict)


@dataclass
class CellEvent:
    """A cell lifecycle event."""
    cell: str
    action: str
    time: str
    raw: dict = field(default_factory=dict)


@dataclass
class WardenStatus:
    """Warden proxy status."""
    running: bool


@dataclass
class CellStats:
    """Resource usage stats for a cell."""
    cell: str
    cpu_percent: str
    mem_usage: str
    mem_percent: str
    pids: str


class BrigError(Exception):
    """Error from a brig CLI command."""
    def __init__(self, message: str, returncode: int = 1, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class Cell:
    """Handle to a running or completed cell."""

    def __init__(self, name: str, brig: "Brig", run_result: CellRunResult = None):
        self.name = name
        self._brig = brig
        self.run_result = run_result

    async def wait(self, timeout: str = None) -> CellResult:
        """Block until cell exits, returning its exit code."""
        cmd = [self._brig._bin, "wait", "--output", "json", self.name]
        if timeout:
            cmd.extend(["--timeout", timeout])

        result = await self._brig._run_cmd(cmd, check=False)
        if result.returncode != 0 and not result.stdout.strip():
            raise BrigError(
                f"Failed to wait for cell {self.name}: {result.stderr.strip()}",
                result.returncode, result.stderr
            )

        try:
            data = json.loads(result.stdout)
            return CellResult(cell=data["cell"], exit_code=data["exit_code"])
        except (json.JSONDecodeError, KeyError):
            # If JSON parsing fails, the return code is the cell exit code.
            return CellResult(cell=self.name, exit_code=result.returncode)

    def wait_sync(self, timeout: str = None) -> CellResult:
        """Synchronous version of wait()."""
        return _run_sync(self.wait(timeout))

    async def stop(self) -> None:
        """Gracefully stop the cell."""
        await self._brig._run_cmd([self._brig._bin, "stop", self.name])

    def stop_sync(self) -> None:
        """Synchronous version of stop()."""
        _run_sync(self.stop())

    async def kill(self) -> None:
        """Immediately kill the cell."""
        await self._brig._run_cmd([self._brig._bin, "kill", self.name])

    def kill_sync(self) -> None:
        """Synchronous version of kill()."""
        _run_sync(self.kill())

    async def cp_in(self, local_path: str, cell_path: str) -> None:
        """Copy a file from local filesystem into the cell workspace."""
        await self._brig._run_cmd([
            self._brig._bin, "cp", local_path, f"{self.name}:{cell_path}"
        ])

    def cp_in_sync(self, local_path: str, cell_path: str) -> None:
        """Synchronous version of cp_in()."""
        _run_sync(self.cp_in(local_path, cell_path))

    async def cp_out(self, cell_path: str, local_path: str) -> None:
        """Copy a file from cell workspace to local filesystem."""
        await self._brig._run_cmd([
            self._brig._bin, "cp", f"{self.name}:{cell_path}", local_path
        ])

    def cp_out_sync(self, cell_path: str, local_path: str) -> None:
        """Synchronous version of cp_out()."""
        _run_sync(self.cp_out(cell_path, local_path))

    async def logs(self, follow: bool = False, tail: int = None) -> str:
        """Get cell logs. Returns log text."""
        cmd = [self._brig._bin, "logs"]
        if follow:
            cmd.append("-f")
        if tail:
            cmd.extend(["--tail", str(tail)])
        cmd.append(self.name)
        result = await self._brig._run_cmd(cmd)
        return result.stdout

    def logs_sync(self, follow: bool = False, tail: int = None) -> str:
        """Synchronous version of logs()."""
        return _run_sync(self.logs(follow=follow, tail=tail))

    async def stats(self) -> list[CellStats]:
        """Get resource usage stats for this cell."""
        return await self._brig.stats(self.name)

    def stats_sync(self) -> list[CellStats]:
        """Synchronous version of stats()."""
        return _run_sync(self.stats())

    async def events(self):
        """Async generator yielding lifecycle events for this cell.

        Usage:
            async for event in cell.events():
                print(event.action)
        """
        cmd = [self._brig._bin, "events", "--output", "json", self.name]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async for line in proc.stdout:
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    yield CellEvent(
                        cell=data.get("cell", self.name),
                        action=data.get("Action", data.get("Status", "unknown")),
                        time=str(data.get("time", data.get("Time", ""))),
                        raw=data,
                    )
                except json.JSONDecodeError:
                    continue
        finally:
            proc.kill()
            await proc.wait()

    async def network_logs(self, follow: bool = True, tail: int = None):
        """Async generator yielding network activity logs for this cell.

        Usage:
            async for entry in cell.network_logs():
                print(f"{entry['method']} {entry['host']}")
        """
        cmd = [self._brig._bin, "network"]
        if follow:
            cmd.append("-f")
        if tail:
            cmd.extend(["--tail", str(tail)])
        cmd.extend(["--json", self.name])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async for line in proc.stdout:
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        finally:
            proc.kill()
            await proc.wait()

    async def rm(self, force: bool = False, purge: bool = False) -> None:
        """Remove the cell."""
        cmd = [self._brig._bin, "rm"]
        if force:
            cmd.append("-f")
        if purge:
            cmd.append("--purge")
        cmd.append(self.name)
        await self._brig._run_cmd(cmd)

    def rm_sync(self, force: bool = False, purge: bool = False) -> None:
        """Synchronous version of rm()."""
        _run_sync(self.rm(force=force, purge=purge))

    def __repr__(self) -> str:
        return f"Cell(name={self.name!r})"


class WardenHandle:
    """Handle for Warden proxy operations."""

    def __init__(self, brig: "Brig"):
        self._brig = brig

    async def status(self) -> WardenStatus:
        """Check if Warden proxy is running."""
        result = await self._brig._run_cmd(
            [self._brig._warden_bin, "status"], check=False
        )
        return WardenStatus(running=result.returncode == 0)

    def status_sync(self) -> WardenStatus:
        """Synchronous version of status()."""
        return _run_sync(self.status())

    async def start(self) -> None:
        """Start the Warden proxy."""
        await self._brig._run_cmd([self._brig._warden_bin, "start"])

    def start_sync(self) -> None:
        """Synchronous version of start()."""
        _run_sync(self.start())

    async def stop(self) -> None:
        """Stop the Warden proxy."""
        await self._brig._run_cmd([self._brig._warden_bin, "stop"])

    def stop_sync(self) -> None:
        """Synchronous version of stop()."""
        _run_sync(self.stop())


class Brig:
    """Main entry point for the Brig SDK.

    Args:
        brig_bin: Path to brig binary (default: "brig").
        warden_bin: Path to warden binary (default: "warden").
    """

    def __init__(self, brig_bin: str = "brig", warden_bin: str = "warden"):
        self._bin = brig_bin
        self._warden_bin = warden_bin
        self.warden = WardenHandle(self)

    async def _run_cmd(self, cmd: list[str], check: bool = True,
                       timeout: int = _DEFAULT_TIMEOUT
                       ) -> subprocess.CompletedProcess:
        """Run a brig CLI command asynchronously."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise BrigError(
                f"Command timed out after {timeout}s: {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}",
                -1, "timeout"
            )
        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
        )
        if check and result.returncode != 0:
            # Only include binary + subcommand to avoid leaking secrets.
            cmd_summary = ' '.join(cmd[:2]) if len(cmd) >= 2 else cmd[0]
            raise BrigError(
                f"Command failed: {cmd_summary}\n{result.stderr.strip()}",
                result.returncode, result.stderr
            )
        return result

    @staticmethod
    def _validate_no_flag(value: str, param_name: str) -> None:
        """Validate that a string parameter does not start with '-'."""
        if value and str(value).startswith("-"):
            raise BrigError(f"Invalid {param_name}: must not start with '-'")

    async def run(
        self,
        name: str,
        image: str,
        command: list[str] = None,
        profile: str = None,
        policy_allow: list[str] = None,
        policy_deny: list[str] = None,
        secrets: list[str] = None,
        env: dict[str, str] = None,
        memory: str = None,
        cpus: str = None,
        pids_limit: int = None,
        timeout: str = None,
        network: str = None,
        labels: dict[str, str] = None,
        detach: bool = True,
        rm: bool = False,
    ) -> Cell:
        """Launch a new cell.

        Returns a Cell handle for interacting with the running cell.
        Defaults to detached mode for programmatic use.
        """
        # Validate inputs to prevent CLI flag injection.
        if not name or not _CELL_NAME_RE.match(name):
            raise BrigError(f"Invalid cell name: {name!r}")
        if not image:
            raise BrigError("Image is required")
        self._validate_no_flag(image, "image")
        if profile:
            self._validate_no_flag(profile, "profile")
        if memory:
            self._validate_no_flag(memory, "memory")
        if cpus:
            self._validate_no_flag(cpus, "cpus")
        if timeout:
            self._validate_no_flag(timeout, "timeout")
        if network:
            self._validate_no_flag(network, "network")
        if policy_allow:
            for d in policy_allow:
                self._validate_no_flag(d, "policy_allow domain")
        if policy_deny:
            for d in policy_deny:
                self._validate_no_flag(d, "policy_deny domain")
        if env:
            for k in env:
                if not _ENV_KEY_RE.match(k):
                    raise BrigError(f"Invalid env key: {k!r}")

        cmd = [self._bin, "run", "--output", "json", "--name", name]

        if profile:
            cmd.extend(["--profile", profile])
        if memory:
            cmd.extend(["--memory", memory])
        if cpus:
            cmd.extend(["--cpus", cpus])
        if pids_limit:
            cmd.extend(["--pids-limit", str(pids_limit)])
        if timeout:
            cmd.extend(["--timeout", timeout])
        if network:
            cmd.extend(["--network", network])
        if detach:
            cmd.append("-d")
        if rm:
            cmd.append("--rm")
        if policy_allow:
            for domain in policy_allow:
                cmd.extend(["--policy-allow", domain])
        if policy_deny:
            for domain in policy_deny:
                cmd.extend(["--policy-deny", domain])
        if secrets:
            for secret in secrets:
                cmd.extend(["--secret", secret])
        if env:
            for k, v in env.items():
                cmd.extend(["-e", f"{k}={v}"])
        if labels:
            for k, v in labels.items():
                cmd.extend(["--label", f"{k}={v}"])

        cmd.append("--")  # Prevent image/command flag injection.
        cmd.append(image)
        if command:
            cmd.extend(command)

        result = await self._run_cmd(cmd)

        # Parse structured JSON output.
        run_result = None
        try:
            data = json.loads(result.stdout)
            run_result = CellRunResult(
                cell=data.get("cell", name),
                cell_id=data.get("cell_id", ""),
                image=data.get("image", image),
                status=data.get("status", "running"),
                network=data.get("network", "unknown"),
                runtime=data.get("runtime", "runsc"),
                timeout_seconds=data.get("timeout_seconds"),
                labels=data.get("labels", {}),
            )
        except json.JSONDecodeError:
            pass

        return Cell(name, self, run_result)

    def run_sync(self, **kwargs) -> Cell:
        """Synchronous version of run()."""
        return _run_sync(self.run(**kwargs))

    async def list(self) -> list[CellInfo]:
        """List all cells."""
        cmd = [self._bin, "list", "--format", "json"]
        result = await self._run_cmd(cmd)

        try:
            cells_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        return [
            CellInfo(
                name=c.get("name", ""),
                status=c.get("status", "unknown"),
                image=c.get("image", "unknown"),
            )
            for c in cells_data
        ]

    def list_sync(self) -> list[CellInfo]:
        """Synchronous version of list()."""
        return _run_sync(self.list())

    async def stats(self, name: str = None) -> list[CellStats]:
        """Get resource usage stats for cells."""
        cmd = [self._bin, "stats", "--output", "json"]
        if name:
            cmd.append(name)
        result = await self._run_cmd(cmd, check=False)

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else []
            return [
                CellStats(
                    cell=s.get("cell", s.get("name", s.get("Name", ""))),
                    cpu_percent=s.get("cpu_percent", s.get("CPUPerc", "")),
                    mem_usage=s.get("mem_usage", s.get("MemUsage", "")),
                    mem_percent=s.get("mem_percent", s.get("MemPerc", "")),
                    pids=s.get("pids", s.get("PIDs", "")),
                )
                for s in data
            ]
        except json.JSONDecodeError:
            return []

    def stats_sync(self, name: str = None) -> list[CellStats]:
        """Synchronous version of stats()."""
        return _run_sync(self.stats(name=name))

    async def cell(self, name: str) -> Cell:
        """Get a handle to an existing cell by name."""
        return Cell(name, self)

    async def pipe(
        self, source: Cell, source_path: str,
        dest: Cell, dest_path: str,
        local_tmp: str = "/tmp"
    ) -> None:
        """Transfer data between cells via local filesystem.

        Copies source_path from source cell to local_tmp, then copies
        from local_tmp into dest cell at dest_path. Isolation is preserved
        because data transits through macOS, never cell-to-cell directly.
        """
        import os
        import tempfile
        fd, tmp_file = tempfile.mkstemp(dir=local_tmp, prefix="brig_pipe_")
        os.close(fd)
        try:
            await source.cp_out(source_path, tmp_file)
            await dest.cp_in(tmp_file, dest_path)
        finally:
            try:
                os.unlink(tmp_file)
            except FileNotFoundError:
                pass

    def pipe_sync(self, source: Cell, source_path: str,
                  dest: Cell, dest_path: str) -> None:
        """Synchronous version of pipe()."""
        _run_sync(self.pipe(source, source_path, dest, dest_path))

    def __repr__(self) -> str:
        return f"Brig(bin={self._bin!r})"


def _run_sync(coro):
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in an async context; create a new thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)
