"""CLI handler for `brig run` and its parse/merge/diagnose helpers."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

from brig.cell.lifecycle import run_cell
from brig.cell.profiles import apply_profile, load_profile
from brig.cell.spec import (
    CellSpec,
    load_cell_definition,
    validate_cell_definition,
    warn_unknown_cell_keys,
)
from brig.config import container_name
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.vm.shell import vm_run

_DIGEST_RE = re.compile(r"@sha(?:256|512):[0-9a-f]{40,}$")


def _warn_unverified_image(image: str) -> None:
    """Stderr-only warning if `image` is from a registry and lacks a
    digest pin. Local builds (localhost/* and dotless single names) and
    digest-pinned refs are silent.

    Brig doesn't refuse — verification is a publishing trust decision
    that varies by user. We just make the absence visible so a careless
    `brig run someorg/their-image:latest` doesn't slip through quietly.
    """
    if not image:
        return
    if image.startswith("localhost/"):
        return
    if _DIGEST_RE.search(image):
        return
    if _suppress_unverified_warn():
        return
    info(
        f"WARN: image {image!r} is unpinned and unverified. "
        f"Pin a digest (image@sha256:...) or verify with: "
        f"brig image verify {image}\n"
        f"  (silence with: brig config set suppress_unverified_image_warn true)"
    )


def _suppress_unverified_warn() -> bool:
    """Read the suppress flag from CONFIG_FILE. Missing/unreadable
    config is treated as 'warn' (the safe default)."""
    import json as _json
    from brig.config import CONFIG_FILE
    try:
        with open(CONFIG_FILE) as f:
            return bool(_json.load(f).get("suppress_unverified_image_warn", False))
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        return False


def cmd_run(args: argparse.Namespace) -> int:
    """Handle `brig run`."""
    # Catch the common foot-gun: `brig run alpine -m 512m sh` puts -m and 512m
    # into the container command instead of being parsed as a brig flag.
    # nargs=REMAINDER swallows everything after the image, so flags must
    # precede the image. If args.image looks like a flag, the user almost
    # certainly meant to put it before the image.
    if args.image and args.image.startswith("-"):
        raise BrigError(
            f"'{args.image}' looks like a flag but appears in image position",
            suggestion="Brig flags must precede the image name. Did you forget '--' "
                       "before the container command? e.g. brig run --memory 512m alpine -- sh",
        )

    # `brig run cells/foo` is a common confusion — that's a build context,
    # not an image ref. Detect host directories and steer the user toward
    # `brig image build` before podman pulls and fails opaquely.
    if args.image and "/" in args.image and not args.image.startswith("localhost/"):
        from pathlib import Path as _P
        if _P(args.image).is_dir():
            raise BrigError(
                f"'{args.image}' is a directory, not an image reference",
                suggestion=(
                    f"Did you mean to build it first?\n"
                    f"  brig image build {args.image}\n"
                    f"  brig run localhost/{_P(args.image).name}:latest ..."
                ),
            )

    # Catch the inverse: flags AFTER a valid image. nargs=REMAINDER swallows
    # everything so `brig run alpine --memory 256m sh` puts the flag tokens
    # into container_cmd and the cell tries to exec `--memory`. Flag it before.
    _BRIG_FLAG_TOKENS = {
        "--memory", "-m", "--cpus", "--name", "-n", "--env", "-e",
        "--secret", "-s", "--profile", "--file", "-f", "--network",
        "--detach", "-d", "--rm", "--timeout", "--workspace-quota",
        "--label", "-l", "--pids-limit", "--image-digest", "--workdir",
        "--policy-allow", "--policy-deny", "-y", "--yes",
    }
    cmd_tail = args.container_cmd or []
    first = cmd_tail[1] if cmd_tail and cmd_tail[0] == "--" else (cmd_tail[0] if cmd_tail else None)
    if first in _BRIG_FLAG_TOKENS:
        raise BrigError(
            f"'{first}' looks like a brig flag but appears after the image",
            suggestion=(
                "Brig flags must precede the image. If you meant to pass it to "
                f"the container, escape it: brig run ... {args.image} -- {first} ..."
            ),
        )

    if args.image:
        _warn_unverified_image(args.image)

    container_cmd = args.container_cmd or []
    if container_cmd and container_cmd[0] == "--":
        container_cmd = container_cmd[1:]

    if not args.image and not args.file:
        raise BrigError("Image is required unless --file is specified")

    # Name resolution: --name flag wins, then the yaml's name: field (if any),
    # then auto-generate. The auto-generate must happen LAST so `--file
    # foo.yaml` with `name: my-cell` keeps `my-cell`.
    spec_kwargs: dict[str, Any] = {
        "name": args.name or "",
        "image": args.image or "",
        "command": container_cmd,
        "env": args.env or [],
        "secrets": args.secret or [],
        "labels": args.label or [],
        "detach": args.detach,
        "rm": args.rm,
        "image_digest": getattr(args, "image_digest", None),
        "workdir": getattr(args, "workdir", None),
    }

    # Precedence: CLI flag > yaml > profile > defaults. Build up from
    # least-specific to most-specific.
    if args.profile:
        profile = load_profile(args.profile)
        merged = apply_profile(spec_kwargs, profile)
        spec_kwargs.update(merged)
        # Record the profile name so the untrusted-profile guards (host_services,
        # tls_passthrough) fire during validation below. Without this,
        # --profile untrusted on the CLI silently voids those guards.
        spec_kwargs["profile"] = args.profile

    cell_def: dict = {}
    if args.file:
        cell_def = load_cell_definition(args.file)
        warn_unknown_cell_keys(cell_def, args.file)
        # The CLI --profile flag is authoritative over the yaml (CLI > yaml),
        # so inject it for validation; otherwise an untrusted-profile run could
        # declare host_services / tls_passthrough in the yaml unchecked.
        if args.profile:
            cell_def["profile"] = args.profile
        errors = validate_cell_definition(cell_def, args.file)
        if errors:
            raise BrigError("Invalid cell definition:\n  - " + "\n  - ".join(errors))
        for key in ("image", "name"):
            if key in cell_def and not getattr(args, key, None):
                spec_kwargs[key] = cell_def[key]
        if "command" in cell_def and not args.container_cmd:
            cmd_val = cell_def["command"]
            spec_kwargs["command"] = cmd_val if isinstance(cmd_val, list) else [cmd_val]
        if "env" in cell_def:
            env_list = cell_def["env"]
            if isinstance(env_list, dict):
                env_list = [f"{k}={v}" for k, v in env_list.items()]
            spec_kwargs["env"] = (args.env or []) + env_list
        if isinstance(cell_def.get("policy"), dict):
            for src_key, dst_key in (("allow", "policy_allow"),
                                      ("deny", "policy_deny"),
                                      ("tls_passthrough", "policy_passthrough_tls")):
                src = cell_def["policy"].get(src_key) or []
                if src:
                    spec_kwargs[dst_key] = list(spec_kwargs.get(dst_key) or []) + list(src)
        # host_services and policy entries from yaml EXTEND the profile
        # baseline. A generic-merge would replace, silently dropping
        # profile-declared services when the yaml has any.
        if isinstance(cell_def.get("host_services"), list):
            spec_kwargs["host_services"] = (
                list(spec_kwargs.get("host_services") or [])
                + list(cell_def["host_services"])
            )
        import dataclasses as _dc
        _spec_field_names = {f.name for f in _dc.fields(CellSpec)}
        _already_handled = {
            "image", "name", "command", "env", "ingress", "policy",
            "host_services",
        }
        for key, val in cell_def.items():
            if key in _spec_field_names and key not in _already_handled:
                spec_kwargs[key] = val

    if args.memory:
        spec_kwargs["memory"] = args.memory
    if args.cpus:
        spec_kwargs["cpus"] = args.cpus
    if args.pids_limit:
        spec_kwargs["pids_limit"] = args.pids_limit
    if args.network:
        spec_kwargs["network"] = args.network
    if args.timeout:
        spec_kwargs["timeout"] = args.timeout
    if args.workspace_quota:
        spec_kwargs["workspace_quota"] = args.workspace_quota
    # --policy-allow / --policy-deny EXTEND profile + yaml entries, consistent
    # with how yaml extends the profile baseline. Single-tenant — no security
    # gain from "CLI clobbers all" because the operator owns every layer.
    if args.policy_allow:
        spec_kwargs["policy_allow"] = (
            list(spec_kwargs.get("policy_allow") or []) + list(args.policy_allow)
        )
    if args.policy_deny:
        spec_kwargs["policy_deny"] = (
            list(spec_kwargs.get("policy_deny") or []) + list(args.policy_deny)
        )

    if args.file and "ingress" in cell_def:
        spec_kwargs["ingress"] = cell_def["ingress"]

    # Yaml is canonical: a `--file <yaml>` invocation must spell its name.
    # CLI shorthand (`brig run alpine echo hi`) still auto-names.
    if not spec_kwargs.get("name"):
        if args.file:
            raise BrigError(
                f"Cell yaml {args.file} is missing required field: name",
                suggestion="Add `name: <cell-name>` to the yaml",
            )
        from brig.cell.names import generate_name
        spec_kwargs["name"] = generate_name()
        info(f"Auto-generated name: {spec_kwargs['name']}")

    # Validate the FULLY-MERGED spec (CLI flags + yaml + profile), mirroring
    # sdk.run_sync. The earlier per-file validation only saw the raw yaml; a
    # flag-only `brig run` (no --file) would otherwise reach CellSpec with only
    # name-validation, silently skipping domain/quota/format checks and the
    # untrusted-profile guards.
    merged_errors = validate_cell_definition(spec_kwargs)
    if merged_errors:
        raise BrigError("Invalid cell definition:\n  - " + "\n  - ".join(merged_errors))

    import dataclasses
    valid_fields = {f.name for f in dataclasses.fields(CellSpec)}
    spec_kwargs = {k: v for k, v in spec_kwargs.items() if k in valid_fields}

    spec = CellSpec(**spec_kwargs)
    # mitmproxy can't hot-add TCP listeners, so a new TCP host_service in a
    # cell yaml requires warden restart. Prompts the operator unless --yes
    # since restart drops every running cell's open egress for ~5s. (The
    # per-cell policy itself is synced inside run_cell, for the SDK too.)
    _maybe_restart_warden_for_tcp(spec, yes=getattr(args, "yes", False))

    from brig.ops.logging import Spinner
    with Spinner(f"Starting cell '{spec.name}'...") as spinner:
        result = run_cell(spec)
        if result.success:
            spinner.success(f"Cell '{spec.name}' started")
        else:
            spinner.fail(f"Cell '{spec.name}' failed")

    if result.container_id:
        output(result.container_id[:12])

    # Detect cells that exit immediately and turn the cryptic outcome into
    # actionable feedback. The most common causes — image's CMD prints help
    # and exits, or the image tried to write somewhere read-only — look like
    # brig brokenness from the user's side.
    if result.success and spec.detach:
        _check_immediate_exit(spec.name)
    return 0


def _maybe_restart_warden_for_tcp(spec: CellSpec, yes: bool = False) -> None:
    """Restart warden if this cell needs a TCP listener that isn't bound.

    mitmproxy can't hot-add `--mode reverse:tcp` listeners, so a new TCP
    host_service in a cell yaml requires warden restart for the listener
    to come up. Restart kills every live cell's open egress for ~5s, so
    we prompt the operator unless `--yes`.
    """
    spec_tcp_ports = sorted({
        e["port"] for e in (spec.host_services or [])
        if isinstance(e, dict) and e.get("protocol") == "tcp"
        and isinstance(e.get("port"), int)
    })
    if not spec_tcp_ports:
        return
    from warden.proxy import get_bound_tcp_ports
    bound = set(get_bound_tcp_ports())
    missing = [p for p in spec_tcp_ports if p not in bound]
    if not missing:
        return
    info(
        f"Cell '{spec.name}' declares TCP host_services on port(s) "
        f"{missing} that warden hasn't bound yet."
    )
    if not yes:
        if not sys.stdin.isatty():
            raise BrigError(
                f"Cell '{spec.name}' needs a warden restart to bind its TCP "
                f"host_service listener(s); declined in non-interactive use",
                suggestion=(
                    "Re-run with --yes to auto-confirm, OR\n"
                    "  brig system down && brig system up  # bind the listener "
                    "manually, then re-run this cell"
                ),
            )
        output(
            "Restarting warden will drop every running cell's open "
            "egress connections for ~5s while the new listener binds."
        )
        try:
            answer = input("Proceed with warden restart? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            raise BrigError(
                "Aborted: warden restart declined",
                suggestion=(
                    "Re-run with --yes to auto-confirm, OR\n"
                    "  brig system down && brig system up  # bind the new listener "
                    "manually, then re-run this cell"
                ),
            )
    from warden.proxy import start as warden_start, stop as warden_stop
    info("Restarting warden to bind new TCP listener(s)...")
    warden_stop()
    if not warden_start():
        raise BrigError(
            "Warden restart failed",
            suggestion="brig system doctor",
        )
    info(f"Warden restarted; TCP listener(s) on {missing} now bound")


def _check_immediate_exit(cell_name: str) -> None:
    """Sleep briefly, then probe whether the cell already exited. If it
    did, scan its stderr/stdout for known error patterns and append a
    suggestion. Best-effort — any failure is swallowed."""
    import time
    time.sleep(1.5)
    try:
        cn = container_name(cell_name)
        status = vm_run(
            ["podman", "inspect", cn, "--format", "{{.State.Status}}"],
            timeout=5,
        )
        if status.returncode != 0:
            return
        if status.stdout.strip() == "running":
            return

        logs = vm_run(["podman", "logs", "--tail", "50", cn], timeout=5)
        log_text = (logs.stdout or "") + (logs.stderr or "")
        hint = _diagnose_exit(log_text)
        info(
            f"NOTE: cell '{cell_name}' exited shortly after start.{hint} "
            f"See: brig cell logs {cell_name}"
        )
    except Exception:  # noqa: BLE001 — pure diagnostic, never fail the run
        pass


def _diagnose_exit(log_text: str) -> str:
    """Heuristic — match common failure patterns and return an actionable
    fragment that fits into the NOTE: line."""
    s = log_text.lower()
    if "read-only file system" in s or "errno 30" in s:
        return (
            " Image tried to write to a read-only path. Writable paths "
            "inside the cell: /work (workspace, persists), /tmp (tmpfs, "
            "64m), /run (tmpfs, 16m). Common fix is to redirect writes "
            "into one of these — e.g. `export HOME=/tmp/home` and stage "
            "credentials there. If the image legitimately needs to write "
            "outside those paths, set writable_rootfs: true in the cell spec."
        )
    if "executable file not found" in s and "bash" in s:
        return " The image likely doesn't ship /bin/bash; try sh."
    return ""


# Backward-compatible re-export; the implementation lives in
# brig.cell.lifecycle and runs inside run_cell for both the CLI and the SDK.
from brig.cell.lifecycle import sync_cell_policy as _sync_cell_policy  # noqa: E402,F401
