"""
CLI handlers for cell lifecycle commands.

Thin wrappers: parse args -> call domain modules -> format output.
All podman commands route through vm_run() to execute inside the Lima VM.
"""

from __future__ import annotations

import json
from typing import Any

from brig.cell.lifecycle import kill_cell, rm_cell, run_cell, stop_cell
from brig.cell.profiles import apply_profile, load_profile
from brig.cell.spec import CellSpec, load_cell_definition, validate_cell_definition
from brig.config import CONTAINER_PREFIX, PROXY_NAME, container_name
from brig.errors import BrigError
from brig.ops.logging import info, output
from brig.vm.shell import vm_run, vm_run_interactive


_DIGEST_RE = __import__("re").compile(r"@sha(?:256|512):[0-9a-f]{40,}$")


def _warn_unverified_image(image: str) -> None:
    """Stderr-only warning if `image` is from a registry and lacks a
    digest pin. Local builds (localhost/* and dotless single names) and
    digest-pinned refs are silent.

    Brig doesn't refuse — verification is a publishing trust decision
    that varies by user. We just make the absence visible so a careless
    `brig run someorg/their-image:latest` doesn't slip through quietly.

    Honors the `suppress_unverified_image_warn` config flag (set via
    `brig config set suppress_unverified_image_warn true`) for users
    who have made an explicit trust decision and want quiet runs.
    """
    if not image:
        return
    if image.startswith("localhost/"):
        return
    if _DIGEST_RE.search(image):
        return
    if _suppress_unverified_warn():
        return
    # No registry component (e.g. "alpine") is an implicit Docker Hub pull,
    # which is the most common trust-by-default footgun. Warn anyway.
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


def cmd_run(args: Any) -> int:
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
    # not an image ref. If the arg looks like a host directory (contains
    # '/' AND exists on disk as a dir), surface the build vs run distinction
    # before podman tries to pull and fails opaquely.
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
    # everything so `brig run alpine --memory 256m sh` puts `--memory 256m sh`
    # into container_cmd. The cell starts and tries to exec `--memory` as the
    # command, fails with "executable not found", and the user can't tell
    # why. Flag a brig-style flag in container_cmd[0] before that happens.
    _BRIG_FLAG_TOKENS = {
        "--memory", "-m", "--cpus", "--name", "-n", "--env", "-e",
        "--secret", "-s", "--profile", "--file", "-f", "--network",
        "--detach", "-d", "--rm", "--timeout", "--workspace-quota",
        "--label", "-l", "--pids-limit", "--image-digest", "--workdir",
        "--policy-allow", "--policy-deny",
    }
    cmd_tail = args.container_cmd or []
    # Strip the optional leading -- separator before checking.
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

    # Strip leading -- from REMAINDER args.
    container_cmd = args.container_cmd or []
    if container_cmd and container_cmd[0] == "--":
        container_cmd = container_cmd[1:]

    if not args.image and not args.file:
        raise BrigError("Image is required unless --file is specified")

    # Name resolution: --name flag wins, then the yaml's name: field (if any),
    # then auto-generate. The previous order auto-generated before loading the
    # file, which made `--file foo.yaml` with `name: my-cell` get an auto-name.
    spec_kwargs: dict[str, Any] = {
        "name": args.name or "",  # may be filled from yaml below
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

    # Precedence (audit L4): CLI flag > yaml > profile > defaults.
    # Build up from least-specific to most-specific: apply profile first,
    # then merge yaml on top, then CLI flag overrides below.

    if args.profile:
        profile = load_profile(args.profile)
        merged = apply_profile(spec_kwargs, profile)
        spec_kwargs.update(merged)

    if args.file:
        cell_def = load_cell_definition(args.file)
        errors = validate_cell_definition(cell_def, args.file)
        if errors:
            raise BrigError("Invalid cell definition:\n  - " + "\n  - ".join(errors))
        # Special-cased fields:
        #   - image / name: --flag wins over yaml (handled by the
        #     `not getattr(args, key, None)` check).
        #   - command: --container_cmd (positional) wins over yaml.
        #   - env: additive — yaml entries appended to --env entries.
        #   - policy: nested {allow, deny} flattens to policy_allow /
        #     policy_deny, extending whatever the profile contributed.
        # All other CellSpec-valid fields fall through to the generic merge.
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
                                      ("deny", "policy_deny")):
                src = cell_def["policy"].get(src_key) or []
                if src:
                    spec_kwargs[dst_key] = list(spec_kwargs.get(dst_key) or []) + list(src)
        # host_services from yaml EXTEND the profile baseline, same as
        # policy.allow/deny. A plain generic-merge would replace, which
        # silently drops profile-declared services when the yaml has any.
        if isinstance(cell_def.get("host_services"), list):
            spec_kwargs["host_services"] = (
                list(spec_kwargs.get("host_services") or [])
                + list(cell_def["host_services"])
            )
        # Generic merge for everything else the validator accepts.
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
    # --policy-allow / --policy-deny EXTEND profile + yaml entries
    # (consistent with how yaml extends the profile baseline). To
    # replace, edit the yaml. Single-tenant: there's no security gain
    # from "CLI clobbers all" because the operator owns every layer.
    if args.policy_allow:
        spec_kwargs["policy_allow"] = (
            list(spec_kwargs.get("policy_allow") or []) + list(args.policy_allow)
        )
    if args.policy_deny:
        spec_kwargs["policy_deny"] = (
            list(spec_kwargs.get("policy_deny") or []) + list(args.policy_deny)
        )

    # Ingress from cell definition file (no CLI flag — file-only).
    if args.file:
        if "ingress" in cell_def:
            spec_kwargs["ingress"] = cell_def["ingress"]

    # Yaml is canonical: a `--file <yaml>` invocation must spell its
    # name. CLI shorthand (`brig run alpine echo hi`) still auto-names.
    if not spec_kwargs.get("name"):
        if args.file:
            raise BrigError(
                f"Cell yaml {args.file} is missing required field: name",
                suggestion="Add `name: <cell-name>` to the yaml",
            )
        from brig.cell.names import generate_name
        spec_kwargs["name"] = generate_name()
        info(f"Auto-generated name: {spec_kwargs['name']}")

    # Filter to CellSpec fields only — profiles may add extra keys like 'runtime'.
    import dataclasses
    valid_fields = {f.name for f in dataclasses.fields(CellSpec)}
    spec_kwargs = {k: v for k, v in spec_kwargs.items() if k in valid_fields}

    spec = CellSpec(**spec_kwargs)
    _sync_cell_policy(spec)

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


def _check_immediate_exit(cell_name: str) -> None:
    """Sleep briefly, then probe whether the cell already exited. If it
    did, scan its stderr/stdout for known error patterns and append a
    suggestion. Otherwise just note that it stopped quickly.

    Called after detached `brig run` so users get a signal when the cell
    they thought started is actually already gone. Best-effort: any
    error here is swallowed (we don't want to fail the run on a
    diagnostic).
    """
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
            return  # All good — cell is still alive.

        # Cell exited quickly. Pull recent logs and look for a known cause.
        logs = vm_run(
            ["podman", "logs", "--tail", "50", cn], timeout=5,
        )
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
    fragment that fits into the NOTE: line. Returns '' if no match."""
    s = log_text.lower()
    if "read-only file system" in s or "errno 30" in s:
        # Lead with the writable paths because relocating writes is the
        # better fix; writable_rootfs:true is the escape hatch.
        return (
            " Image tried to write to a read-only path. Writable paths "
            "inside the cell: /work (workspace, persists), /tmp (tmpfs, "
            "64m), /run (tmpfs, 16m). Common fix is to redirect writes "
            "into one of these — e.g. `export HOME=/tmp/home` and stage "
            "credentials there. If the image legitimately needs to write "
            "outside those paths, set writable_rootfs: true in the cell spec."
        )
    if "executable file not found" in s and "bash" in s:
        return (
            " The image likely doesn't ship /bin/bash; try sh."
        )
    return ""


def _sync_cell_policy(spec: CellSpec) -> None:
    """Write the cell's allow / deny / host_services to its per-cell
    policy file. Replace semantics: the yaml is the source of truth,
    so anything in the file that's no longer in the spec is dropped.

    Skips the write if the on-disk policy already matches the spec —
    idempotent re-runs don't churn mtime or noise the audit log.
    """
    from brig.policy.policy import load_cell_policy, save_cell_policy

    desired = {
        "allow": list(spec.policy_allow or []),
        "deny": list(spec.policy_deny or []),
        "host_services": list(spec.host_services or []),
    }
    existing = load_cell_policy(spec.name) or {}
    current = {
        "allow": existing.get("allow", []),
        "deny": existing.get("deny", []),
        "host_services": existing.get("host_services", []),
    }
    if desired == current:
        return

    # Preserve any other keys the on-disk policy may carry (e.g.
    # rate_limits) so we don't accidentally drop unrelated config.
    merged = dict(existing)
    merged.update(desired)
    save_cell_policy(spec.name, merged)

    # Log host_services diffs (the only field with operator-visible
    # semantics worth flagging — allow/deny changes are too noisy to
    # log line-by-line).
    def _names(items):
        return {e["name"] for e in items if isinstance(e, dict) and "name" in e}
    added = _names(desired["host_services"]) - _names(current["host_services"])
    removed = _names(current["host_services"]) - _names(desired["host_services"])
    for n in sorted(added):
        info(f"host_service granted: {spec.name} → {n} (from cell yaml)")
    for n in sorted(removed):
        info(f"host_service revoked: {spec.name} → {n} (no longer in cell yaml)")


def cmd_preflight(args: Any) -> int:
    """Handle `brig cell preflight <yaml>`.

    Dry-run check: parses the yaml and verifies every host-side
    requirement it implies (declared secrets exist, declared
    host_socket targets exist, declared ingress entries have a
    token secret, image exists or is buildable). Prints a checklist
    with a one-line fix for each gap.

    Replaces the iterative "brig run → error → fix one thing →
    re-run" loop with a single diff. No mutations; safe to run
    anytime.
    """
    from brig.cell.spec import load_cell_definition, validate_cell_definition
    from brig.config import HostPaths

    cell_def = load_cell_definition(args.file)
    errors = validate_cell_definition(cell_def, args.file)
    fail_count = 0

    def _check(label: str, ok: bool, fix: str = "") -> None:
        nonlocal fail_count
        marker = "OK  " if ok else "FAIL"
        output(f"  [{marker}] {label}")
        if not ok:
            fail_count += 1
            if fix:
                output(f"         fix: {fix}")

    cell_name = cell_def.get("name", "<unnamed>")
    output(f"Preflight for cell '{cell_name}' ({args.file})")
    output("=" * 60)

    # 1. Spec validity.
    _check(
        "cell yaml validates",
        not errors,
        fix=("Fix errors:\n         " + "\n         ".join(errors)
             if errors else ""),
    )

    # 2. Secrets exist.
    for secret in cell_def.get("secrets", []):
        if not isinstance(secret, str):
            continue
        p = HostPaths.SECRETS_DIR / secret
        _check(
            f"secret: {secret}", p.exists(),
            fix=f"brig secrets add {secret}",
        )

    # 3. Ingress token (if any ingress entry uses auth: token).
    ingress_entries = cell_def.get("ingress") or []
    needs_token = any(
        isinstance(e, dict) and e.get("auth") == "token" for e in ingress_entries
    )
    if needs_token:
        primary = HostPaths.SECRETS_DIR / f"{cell_name}-ingress-token"
        fallback = HostPaths.SECRETS_DIR / "ingress-token"
        ok = primary.exists() or fallback.exists()
        _check(
            f"ingress token: {primary.name}", ok,
            fix=f"openssl rand -hex 32 | brig secrets add {primary.name} -",
        )

    # 4. host_sockets — targets exist and are sockets on the host.
    import os as _os
    import stat as _stat
    for entry in cell_def.get("host_sockets") or []:
        if not isinstance(entry, dict):
            continue
        host_path = entry.get("host_path", "")
        name = entry.get("name", "?")
        try:
            st = _os.lstat(host_path)
            is_sock = _stat.S_ISSOCK(st.st_mode) and not _stat.S_ISLNK(st.st_mode)
        except (FileNotFoundError, OSError):
            is_sock = False
        _check(
            f"host_socket target: {name} → {host_path}", is_sock,
            fix="Start the service that provides this socket, or "
                "correct host_path.",
        )

    # 5. socat installed if host_sockets are declared.
    if cell_def.get("host_sockets"):
        import shutil as _shutil
        _check(
            "socat installed (host_sockets bridge dependency)",
            bool(_shutil.which("socat")),
            fix="brew install socat",
        )

    output("=" * 60)
    if fail_count:
        output(f"FAILED: {fail_count} check(s) — fix above, then re-run")
        return 1
    output("All preflight checks passed.")
    return 0


def cmd_stop(args: Any) -> int:
    stop_cell(args.name)
    return 0


def cmd_kill(args: Any) -> int:
    kill_cell(args.name)
    return 0


def cmd_rm(args: Any) -> int:
    import sys
    from brig.cell.lifecycle import _workspace_has_content

    keep = getattr(args, "keep_workspace", False)
    # If the cell's workspace has files and the user didn't explicitly
    # opt to keep or force, ask before deleting. Closes the silent-data-loss
    # foot-gun where the user expects docker semantics (rm preserves
    # volumes) and loses unexpected data.
    if not keep and not args.force and _workspace_has_content(args.name):
        if not sys.stdin.isatty():
            raise BrigError(
                f"Cell '{args.name}' has files in its workspace; refusing to "
                f"delete non-interactively.",
                suggestion=(
                    f"brig cell rm {args.name} --keep-workspace   # preserve files\n"
                    f"  OR  brig cell rm -f {args.name}            # force delete"
                ),
            )
        prompt = (
            f"Cell '{args.name}' workspace contains files. "
            f"Delete? [y/N/keep] "
        )
        try:
            answer = input(prompt).strip().lower()
        except EOFError:
            answer = ""
        if answer in ("k", "keep"):
            keep = True
        elif answer not in ("y", "yes"):
            output("Aborted.")
            return 1

    rm_cell(args.name, force=args.force, keep_workspace=keep)
    return 0


def cmd_list(args: Any) -> int:
    result = vm_run(
        ["podman", "ps", "-a", "--format", "json", "--filter", f"name=^{CONTAINER_PREFIX}"],
    )
    if result.returncode != 0:
        return 1

    try:
        containers = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return 1

    fmt = getattr(args, "format", "table")
    if fmt == "json":
        output(json.dumps(containers, indent=2))
        return 0

    cells = []
    for c in containers:
        names = c.get("Names", "")
        # Podman 4.x returns Names as a string; 5.x as a list.
        name = names[0] if isinstance(names, list) else names
        if name == PROXY_NAME:
            continue
        cells.append((name, c))

    if not cells:
        output("No cells found")
        return 0

    if fmt == "wide":
        output(f"{'NAME':<25} {'STATUS':<12} {'CREATED':<22} {'NETWORK':<25} {'IMAGE'}")
        for name, c in cells:
            cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            networks = c.get("Networks") or []
            network = ",".join(networks)[:25] if networks else "-"
            created = c.get("CreatedAt", "")[:22]
            output(f"{cell:<25} {c.get('State', ''):<12} {created:<22} {network:<25} {c.get('Image', '')}")
    else:
        output(f"{'NAME':<25} {'STATUS':<12} {'IMAGE':<30}")
        for name, c in cells:
            cell = name[len(CONTAINER_PREFIX):] if name.startswith(CONTAINER_PREFIX) else name
            output(f"{cell:<25} {c.get('State', ''):<12} {c.get('Image', ''):<30}")
    return 0


def cmd_inspect(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )
    output(result.stdout)
    return 0


def cmd_files(args: Any) -> int:
    """List workspace contents inside a cell."""
    cn = container_name(args.name)
    path = getattr(args, "path", "/work")
    return vm_run_interactive(["podman", "exec", cn, "ls", "-la", path])


def cmd_read(args: Any) -> int:
    """Handle `brig cell read <cell> <relpath>` — stream a workspace file
    to stdout via the race-free safe_open primitive.

    This is the language-agnostic safe-read replacement for the (now
    removed) workspace.host_path field in cell.json. Consumers in any
    language can do:

        brig cell read mycell input.json > /tmp/local-copy

    instead of opening the host path directly. Each path component is
    walked with O_NOFOLLOW so a cell-planted symlink raises
    WorkspaceEscape rather than letting the host follow it.
    """
    import sys
    from brig.workspace.validation import safe_open, WorkspaceEscape

    try:
        with safe_open(args.name, args.path, "rb") as f:
            # Stream in chunks so a large file doesn't blow RAM.
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
        return 0
    except WorkspaceEscape as e:
        raise BrigError(
            f"Refused: {e}",
            suggestion="A path component is a symlink or escapes the workspace root.",
        )
    except FileNotFoundError:
        raise BrigError(f"Not found: {args.path} in cell '{args.name}'")


def cmd_logs(args: Any) -> int:
    cn = container_name(args.name)
    cmd = ["podman", "logs"]
    if getattr(args, "follow", False):
        cmd.append("-f")
    if getattr(args, "tail", None):
        cmd.extend(["--tail", str(args.tail)])
    cmd.append(cn)
    return vm_run_interactive(cmd)


def _parse_cp_target(spec: str) -> tuple[str, str] | None:
    """Parse 'cell:/path' into (cell, path), or return None if not a cell ref.

    Only treats the colon as a cell separator when the prefix matches the
    canonical cell-name pattern. Avoids misreading paths containing colons
    (e.g. './out:put.txt') as cell references.
    """
    from brig.config import CELL_NAME_PATTERN
    if ":" not in spec or spec.startswith("/") or spec.startswith("."):
        return None
    head, tail = spec.split(":", 1)
    if not CELL_NAME_PATTERN.match(head):
        return None
    return head, tail


def cmd_cp(args: Any) -> int:
    """Copy files to/from a cell with safety checks.

    Detects direction from the colon syntax (cell:path). The cell prefix
    must match the canonical cell-name pattern, so a literal path like
    './out:put.txt' is not misread as a cell reference.
    Exports apply quarantine xattr and extension blocking by default.
    """
    src, dst = args.src, args.dst
    src_target = _parse_cp_target(src)
    dst_target = _parse_cp_target(dst)

    if src_target and dst_target:
        raise BrigError(
            "Cannot copy between two cells",
            suggestion="Copy from cell to host first, then from host to cell",
        )
    if src_target:
        from brig.workspace.workspace import copy_out
        copy_out(src_target[0], src, dst, sanitize=True)
    elif dst_target:
        from brig.workspace.workspace import copy_in
        copy_in(dst_target[0], src, dst)
    else:
        raise BrigError(
            "Could not determine copy direction",
            suggestion="Use cell:path syntax, e.g.: brig cp mycell:/work/out.txt ./",
        )
    return 0


def cmd_exec(args: Any) -> int:
    cn = container_name(args.name)
    cmd = ["podman", "exec"]
    if getattr(args, "interactive", False):
        cmd.append("-it")
    cmd.append(cn)
    cmd.extend(args.exec_cmd)
    return vm_run_interactive(cmd)


def cmd_shell(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "exec", "-it", cn, "/bin/sh"])


def cmd_attach(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "attach", cn])


def cmd_start(args: Any) -> int:
    # Invariant 9: proxy must be running before starting cells.
    from brig.network.proxy import proxy_running
    if not proxy_running():
        raise BrigError(
            "Warden proxy is not running",
            suggestion="Start with: brig up",
        )
    # Refresh the cell metadata so /run/brig/cell.json's `started_at`
    # reflects this start, not the original create. workspace_mount is
    # preserved from whatever the cell was created with (bind mounts are
    # fixed at container-create time; we can't change them on start).
    _refresh_metadata_for_start(args.name)
    cn = container_name(args.name)
    result = vm_run(["podman", "start", cn])
    if result.returncode != 0:
        raise BrigError(
            f"Failed to start cell '{args.name}': {result.stderr.strip()}",
            suggestion="Check if cell exists with: brig cell list",
        )
    info(f"Cell '{args.name}' started")
    return 0


def _refresh_metadata_for_start(cell_name: str) -> None:
    """Rewrite /run/brig/cell.json on restart with a fresh `started_at`.

    Preserves the original workspace_mount (the bind mount is fixed at
    container-create time and re-setting it on `podman start` doesn't
    take effect). If the existing metadata is missing or unreadable
    (e.g. the cell was created before cell.json existed), write a
    default-mount metadata file as a best-effort fallback.
    """
    import json as _json
    from brig.cell.metadata import (
        _host_metadata_path,
        write_metadata,
    )
    existing = _host_metadata_path(cell_name)
    workspace_mount = "/work"
    try:
        prior = _json.loads(existing.read_text())
        workspace_mount = prior.get("workspace", {}).get("mount_point", "/work")
    except (FileNotFoundError, _json.JSONDecodeError, OSError):
        pass
    write_metadata(cell_name, workspace_mount)


def cmd_restart(args: Any) -> int:
    """Handle `brig cell restart <name>` — stop (if running) then start.

    Composite of stop_cell + cmd_start. Refreshes the cell metadata's
    started_at via cmd_start's existing path.
    """
    from brig.cell.lifecycle import observe, stop_cell
    actual = observe(args.name)
    if not actual.exists:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="brig cell list  # see what's there",
        )
    if actual.running:
        stop_cell(args.name)
    return cmd_start(args)


def cmd_wait(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "wait", cn], timeout=None)
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )
    exit_code = result.stdout.strip()
    output(exit_code)
    return int(exit_code) if exit_code.isdigit() else 1


def cmd_pause(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "pause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to pause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' paused")
    return 0


def cmd_unpause(args: Any) -> int:
    cn = container_name(args.name)
    result = vm_run(["podman", "unpause", cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to unpause cell '{args.name}': {result.stderr.strip()}")
    info(f"Cell '{args.name}' unpaused")
    return 0


def cmd_rename(args: Any) -> int:
    from brig.config import CELL_NAME_PATTERN
    if not CELL_NAME_PATTERN.match(args.new_name):
        raise BrigError(
            f"Invalid cell name '{args.new_name}': must match {CELL_NAME_PATTERN.pattern}",
            suggestion="Cell names: lowercase alphanumeric, hyphens, dots, max 63 chars",
        )
    old_cn = container_name(args.old_name)
    new_cn = container_name(args.new_name)
    result = vm_run(["podman", "rename", old_cn, new_cn])
    if result.returncode != 0:
        raise BrigError(f"Failed to rename: {result.stderr.strip()}")
    info(f"Renamed '{args.old_name}' to '{args.new_name}'")
    return 0


def cmd_top(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "top", cn])


def cmd_diff(args: Any) -> int:
    cn = container_name(args.name)
    return vm_run_interactive(["podman", "diff", cn])


def cmd_stats(args: Any) -> int:
    cmd = ["podman", "stats", "--no-stream"]
    if hasattr(args, "name") and args.name:
        cmd.append(container_name(args.name))
    else:
        cmd.extend(["--filter", f"name=^{CONTAINER_PREFIX}"])
    return vm_run_interactive(cmd)


def cmd_export(args: Any) -> int:
    """Export a running cell's config as a reusable YAML cell definition."""
    cn = container_name(args.name)
    result = vm_run(["podman", "inspect", cn, "--format", "json"])
    if result.returncode != 0:
        raise BrigError(
            f"Cell '{args.name}' does not exist",
            suggestion="Use 'brig list' to see available cells",
        )

    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            data = data[0]
    except json.JSONDecodeError:
        raise BrigError("Could not parse container info")

    # Extract cell definition from container inspect.
    host_config = data.get("HostConfig", {})
    config = data.get("Config", {})

    cell_def = {"name": args.name}

    image = config.get("Image", "")
    if image:
        cell_def["image"] = image

    cmd = config.get("Cmd")
    if cmd:
        cell_def["command"] = cmd

    # Extract non-proxy env vars.
    proxy_prefixes = ("http_proxy=", "https_proxy=", "HTTP_PROXY=", "HTTPS_PROXY=", "no_proxy=")
    env_vars = [
        e for e in (config.get("Env") or [])
        if not any(e.startswith(p) for p in proxy_prefixes)
        and not e.endswith("_FILE=/run/secrets/" + e.split("=")[0].replace("_FILE", "").lower())
    ]
    if env_vars:
        cell_def["env"] = env_vars

    memory = host_config.get("Memory", 0)
    if memory:
        if memory >= 1024**3:
            cell_def["memory"] = f"{memory // 1024**3}g"
        elif memory >= 1024**2:
            cell_def["memory"] = f"{memory // 1024**2}m"

    cpus = host_config.get("NanoCpus", 0)
    if cpus:
        cell_def["cpus"] = str(cpus / 1e9)

    pids = host_config.get("PidsLimit", 0)
    if pids and pids > 0:
        cell_def["pids_limit"] = pids

    # Per-cell policy (allow / deny / host_services). The yaml is
    # canonical, the per-cell policy file mirrors it, and warden
    # reads that file — so it's the authoritative running state.
    from brig.policy.policy import load_cell_policy
    cell_policy = load_cell_policy(args.name) or {}
    allow = cell_policy.get("allow") or []
    deny = cell_policy.get("deny") or []
    if allow or deny:
        policy_block: dict = {}
        if allow:
            policy_block["allow"] = list(allow)
        if deny:
            policy_block["deny"] = list(deny)
        cell_def["policy"] = policy_block
    host_services = cell_policy.get("host_services") or []
    if host_services:
        cell_def["host_services"] = list(host_services)

    # Ingress routes (from the host-side ingress-routes.json, written
    # at cell start by lifecycle._register_cell_ingress).
    from brig.config import HostPaths
    ingress = _ingress_for_cell(args.name, HostPaths.INGRESS_ROUTES_FILE)
    if ingress:
        cell_def["ingress"] = ingress

    # host_sockets — projected to {name, mount_point, mode} (host_path
    # stays off the wire for the same reason it's omitted from the
    # downward-API metadata).
    sockets = _host_sockets_from_metadata(args.name)
    if sockets:
        cell_def["host_sockets"] = sockets

    output(f"# Cell definition exported from '{args.name}'")
    output("# Self-contained: brig run --file <this-file> will reproduce the cell.")
    output("")
    _emit_yaml(cell_def)
    return 0


def _ingress_for_cell(cell_name: str, routes_file) -> list:
    try:
        data = json.loads(routes_file.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    routes = data.get("routes") or []
    return [
        {"name": r.get("name"),
         "port": r.get("port"),
         "path_prefix": r.get("path_prefix"),
         "auth": "token"}
        for r in routes
        if isinstance(r, dict) and r.get("cell") == cell_name
    ]


def _host_sockets_from_metadata(cell_name: str) -> list:
    from brig.cell.metadata import _host_metadata_path
    try:
        meta = json.loads(_host_metadata_path(cell_name).read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    entries = meta.get("host_sockets") or []
    return [
        {"name": e["name"], "mount_point": e["mount_point"]}
        for e in entries
        if isinstance(e, dict) and "name" in e and "mount_point" in e
    ]


def _emit_yaml(d: dict) -> None:
    """Minimal yaml emitter that handles the shapes cell_def uses
    (scalars, list of scalars, list of dicts, nested dicts). Avoids
    pulling in pyyaml just for output.

    Strings are always JSON-quoted to dodge yaml metachars: bare
    `*.example.com` parses as a yaml alias reference, bare `1.0` as
    a float, leading-`!`/`&`/`>`/`|`/`#` as tag/anchor/block-scalar
    markers. JSON quoting is yaml-valid for any string and keeps the
    round-trip through load_cell_definition correct.
    """
    def _scalar(v):
        return json.dumps(v)

    for key, val in d.items():
        if isinstance(val, dict):
            output(f"{key}:")
            for k, v in val.items():
                if isinstance(v, list):
                    output(f"  {k}:")
                    for item in v:
                        output(f"    - {_scalar(item)}")
                else:
                    output(f"  {k}: {_scalar(v)}")
        elif isinstance(val, list):
            if val and all(isinstance(x, dict) for x in val):
                output(f"{key}:")
                for item in val:
                    first = True
                    for k, v in item.items():
                        prefix = "  - " if first else "    "
                        output(f"{prefix}{k}: {_scalar(v)}")
                        first = False
            else:
                output(f"{key}:")
                for item in val:
                    output(f"  - {_scalar(item)}")
        else:
            output(f"{key}: {_scalar(val)}")
