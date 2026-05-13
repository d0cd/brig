"""
Brig SDK — programmatic interface for cell management.

Calls domain modules directly instead of shelling out to the CLI.
Provides both async and sync interfaces.

Usage:
    from brig.sdk import Brig

    b = Brig()
    cell = b.run_sync(name="test", image="alpine", command=["echo", "hi"])
    exit_code = cell.wait_sync()
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from brig.cell.lifecycle import kill_cell, rm_cell, run_cell, stop_cell
from brig.vm.shell import vm_run
from brig.cell.profiles import apply_profile, load_profile
from brig.cell.reconciler import CellState, ReconcileResult, observe
from brig.cell.spec import CellSpec
from brig.config import CELL_NAME_PATTERN, CONTAINER_PREFIX, PROXY_NAME
from brig.errors import BrigError


@dataclass
class CellRunResult:
    """Result of running a cell to completion."""
    name: str
    exit_code: int
    stdout: str
    stderr: str
    success: bool


@dataclass
class CellInfo:
    """Information about a cell."""
    name: str
    status: str
    image: str



@dataclass
class WardenStatus:
    """Warden proxy status."""
    running: bool
    networks: list[str] = field(default_factory=list)


class CellNotFoundError(BrigError):
    """Cell does not exist."""
    pass


class ImageVerificationError(BrigError):
    """Image signature verification failed."""
    pass


class ProfileError(BrigError):
    """Invalid or unknown profile."""
    pass


class SecretNotFoundError(BrigError):
    """Secret file not found."""
    pass


class Cell:
    """Handle to a running or completed cell."""

    def __init__(self, name: str):
        self.name = name
        self._cn = f"{CONTAINER_PREFIX}{name}"

    async def wait(self, timeout: int | None = None) -> int:
        """Wait for cell to exit. Returns exit code."""
        return await asyncio.to_thread(self.wait_sync, timeout)

    def wait_sync(self, timeout: int | None = None) -> int:
        """Synchronous wait for cell to exit."""
        cmd = ["podman", "wait", self._cn]
        try:
            result = vm_run(
                cmd,
                timeout=timeout,
            )
            code = result.stdout.strip()
            return int(code) if code.isdigit() else 1
        except Exception:
            return -1

    async def stop(self) -> None:
        await asyncio.to_thread(stop_cell, self.name)

    def stop_sync(self) -> None:
        stop_cell(self.name)

    async def kill(self) -> None:
        await asyncio.to_thread(kill_cell, self.name)

    def kill_sync(self) -> None:
        kill_cell(self.name)

    async def rm(self, force: bool = False) -> None:
        await asyncio.to_thread(rm_cell, self.name, force)

    def rm_sync(self, force: bool = False) -> None:
        rm_cell(self.name, force)

    async def logs(self, tail: int | None = None) -> str:
        return await asyncio.to_thread(self.logs_sync, tail)

    def logs_sync(self, tail: int | None = None) -> str:
        cmd = ["podman", "logs"]
        if tail:
            cmd.extend(["--tail", str(tail)])
        cmd.append(self._cn)
        result = vm_run(cmd)
        return result.stdout

    def is_alive(self) -> bool:
        """Check if cell is still running."""
        state = observe(self.name)
        return state.running

    def copy_in(self, src: str, dst: str) -> None:
        """Copy a file from host into the cell workspace."""
        from brig.workspace.workspace import copy_in
        copy_in(self.name, src, dst)

    def copy_out(self, src: str, dst: str) -> None:
        """Copy a file from cell workspace to host (with sanitization)."""
        from brig.workspace.workspace import copy_out
        copy_out(self.name, src, dst, sanitize=True)


class WardenHandle:
    """Handle to the Warden proxy."""

    def status(self) -> WardenStatus:
        from warden.proxy import get_status
        s = get_status()
        return WardenStatus(
            running=s.get("running", False),
            networks=s.get("networks", []),
        )

    def start(self) -> bool:
        from warden.proxy import start
        return start()

    def stop(self) -> bool:
        from warden.proxy import stop
        return stop()


class Brig:
    """Main SDK entry point for cell management."""

    def __init__(self) -> None:
        self.warden = WardenHandle()

    async def run(
        self,
        name: str,
        image: str,
        command: list[str] | None = None,
        env: list[str] | None = None,
        secrets: list[str] | None = None,
        memory: str = "2g",
        cpus: str = "2",
        pids_limit: int = 512,
        network: str = "default",
        profile: str | None = None,
        detach: bool = True,
        timeout: str | None = None,
        labels: list[str] | None = None,
    ) -> Cell:
        """Run a new cell. Returns a Cell handle."""
        return await asyncio.to_thread(
            self.run_sync,
            name=name, image=image, command=command, env=env,
            secrets=secrets, memory=memory, cpus=cpus,
            pids_limit=pids_limit, network=network, profile=profile,
            detach=detach, timeout=timeout, labels=labels,
        )

    def run_sync(
        self,
        name: str,
        image: str,
        command: list[str] | None = None,
        env: list[str] | None = None,
        secrets: list[str] | None = None,
        memory: str = "2g",
        cpus: str = "2",
        pids_limit: int = 512,
        network: str = "default",
        profile: str | None = None,
        detach: bool = True,
        timeout: str | None = None,
        labels: list[str] | None = None,
    ) -> Cell:
        """Synchronous version of run()."""
        if not CELL_NAME_PATTERN.match(name):
            raise BrigError(f"Invalid cell name: {name}")

        spec_kwargs: dict[str, Any] = {
            "name": name,
            "image": image,
            "command": command or [],
            "env": env or [],
            "secrets": secrets or [],
            "memory": memory,
            "cpus": cpus,
            "pids_limit": pids_limit,
            "network": network,
            "detach": detach,
            "labels": labels or [],
        }

        if timeout:
            spec_kwargs["timeout"] = timeout

        if profile:
            try:
                prof = load_profile(profile)
                spec_kwargs = apply_profile(spec_kwargs, prof)
            except ValueError as e:
                raise ProfileError(str(e))

        # Filter to only CellSpec fields (profiles may add extra keys like 'runtime').
        import dataclasses
        valid_fields = {f.name for f in dataclasses.fields(CellSpec)}
        spec_kwargs = {k: v for k, v in spec_kwargs.items() if k in valid_fields}

        spec = CellSpec(**spec_kwargs)
        run_cell(spec)
        return Cell(name)

    async def execute(
        self,
        image: str,
        command: list[str],
        name: str | None = None,
        timeout: str = "5m",
        network: str = "default",
        env: list[str] | None = None,
        secrets: list[str] | None = None,
        profile: str | None = None,
    ) -> CellRunResult:
        """Execute code and return the result. Single-call API for agents.

        Runs the command, waits for completion, collects output, cleans up.
        Returns a CellRunResult with exit_code, stdout, stderr.

        Example:
            result = await b.execute("python:3.12", ["python", "-c", "print('hi')"])
            print(result.exit_code, result.stdout)
        """
        return await asyncio.to_thread(
            self.execute_sync,
            image=image, command=command, name=name, timeout=timeout,
            network=network, env=env, secrets=secrets, profile=profile,
        )

    def execute_sync(
        self,
        image: str,
        command: list[str],
        name: str | None = None,
        timeout: str = "5m",
        network: str = "default",
        env: list[str] | None = None,
        secrets: list[str] | None = None,
        profile: str | None = None,
    ) -> CellRunResult:
        """Synchronous execute. Runs code, waits, collects output, cleans up."""
        from brig.cell.names import generate_name

        cell_name = name or generate_name()
        cell = self.run_sync(
            name=cell_name, image=image, command=command,
            env=env, secrets=secrets, network=network,
            profile=profile, detach=True, timeout=timeout,
        )

        try:
            # Wait for completion.
            timeout_seconds = None
            if timeout:
                from brig.cell.spec import parse_duration
                timeout_seconds = parse_duration(timeout)
                if timeout_seconds:
                    timeout_seconds += 10  # Grace period beyond container timeout.

            exit_code = cell.wait_sync(timeout=timeout_seconds)

            # Collect output. Podman logs merges stdout/stderr but we separate
            # by capturing each stream individually.
            stdout_result = vm_run(["podman", "logs", "--follow=false", cell._cn])
            stderr_result = vm_run(["podman", "logs", "--follow=false", cell._cn],
                                   capture=True)

            return CellRunResult(
                name=cell_name,
                exit_code=exit_code,
                stdout=stdout_result.stdout,
                stderr=stderr_result.stderr,
                success=exit_code == 0,
            )
        finally:
            try:
                cell.rm_sync(force=True)
            except Exception:
                pass

    async def list_cells(self) -> list[CellInfo]:
        """List all cells."""
        return await asyncio.to_thread(self.list_sync)

    def list_sync(self) -> list[CellInfo]:
        """Synchronous version of list()."""
        result = vm_run(
            ["podman", "ps", "-a", "--format", "json",
             "--filter", f"name={CONTAINER_PREFIX}"],
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        try:
            containers = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        cells = []
        for c in containers:
            names = c.get("Names", "")
            name = names[0] if isinstance(names, list) else names
            if name == PROXY_NAME:
                continue
            cell_name = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            cells.append(CellInfo(
                name=cell_name,
                status=c.get("State", ""),
                image=c.get("Image", ""),
            ))
        return cells

    def cell(self, name: str) -> Cell:
        """Get a handle to an existing cell."""
        state = observe(name)
        if not state.exists:
            raise CellNotFoundError(f"Cell '{name}' does not exist")
        return Cell(name)
