"""Render the operator-declared `mount_roots` into the Lima VM config.

`mount_roots` (config.json) lists host trees that may be exposed to cells via
the per-cell `mounts:` block. Lima mounts are static + VM-wide, so each root is
mounted into the VM at /mnt/host/<slug> and the reconciler binds sub-paths from
there into cells. See docs/design/host-mounts.md.

The mounts live between managed markers in lima.yaml so we can rewrite just that
block (idempotent) without disturbing the rest of the operator's config.
"""

from __future__ import annotations

import json
from pathlib import Path

from brig.config import (
    VM_NAME,
    HostPaths,
    mount_root_slug,
    mount_roots,
    validate_mount_roots,
)
from brig.errors import BrigError
from brig.ops.atomic import atomic_write_text

_BEGIN = "# brig:mount_roots:begin"
_END = "# brig:mount_roots:end"


def render_mount_roots_block(roots: list[str]) -> str:
    """The lima.yaml lines (between the markers) for the given roots.

    Raises BrigError if the roots don't validate (catastrophe/sensitive root,
    non-dir, slug collision, illegal chars). `location` is JSON-quoted so a path
    with YAML-hostile characters can't break out of the string.
    """
    errs = validate_mount_roots(roots)
    if errs:
        raise BrigError("Invalid mount_roots: " + "; ".join(errs))
    lines: list[str] = []
    for root in roots:
        slug = mount_root_slug(root)
        # json.dumps gives a safely-quoted YAML scalar (YAML is a JSON superset).
        # Writable at the VM layer; per-cell ro/rw is enforced by podman's
        # `-v ...:<mode>` (the reconciler), not here.
        lines.append(f'  - location: {json.dumps(root)}')
        lines.append(f'    mountPoint: "/mnt/host/{slug}"')
        lines.append('    writable: true')
    return "\n".join(lines)


def sync_lima_mount_roots(lima_yaml: Path = HostPaths.LIMA_YAML) -> bool:
    """Rewrite the managed mount_roots block in lima.yaml from config.

    Returns True if the file content changed (caller may then advise a VM
    restart). No-op (returns False) if lima.yaml is missing or predates the
    markers — we never inject mounts into an unmarked file (would risk
    corrupting hand-edited YAML). Raises BrigError on malformed markers or
    invalid mount_roots rather than producing broken YAML.
    """
    if not lima_yaml.exists():
        return False
    text = lima_yaml.read_text()
    if _BEGIN not in text or _END not in text:
        return False
    # Exactly one well-ordered marker pair, else refuse (don't corrupt the file).
    if text.count(_BEGIN) != 1 or text.count(_END) != 1 or text.index(_BEGIN) > text.index(_END):
        raise BrigError(
            f"Malformed brig:mount_roots markers in {lima_yaml} — expected one "
            f"begin before one end. Fix or regenerate with: brig system init"
        )

    pre, rest = text.split(_BEGIN, 1)
    mid_and_end, post = rest.split(_END, 1)

    block = render_mount_roots_block(mount_roots())
    middle = f"\n{block}\n" if block else "\n"
    # Preserve the begin marker's trailing descriptor (up to the newline) and
    # the END marker's leading indentation so the managed block stays tidy.
    begin_line_tail = mid_and_end[: mid_and_end.index("\n")] if "\n" in mid_and_end else ""
    last_nl = mid_and_end.rfind("\n")
    end_indent = mid_and_end[last_nl + 1:] if last_nl != -1 else ""  # ws before _END

    new_text = f"{pre}{_BEGIN}{begin_line_tail}{middle}{end_indent}{_END}{post}"
    if new_text != text:
        atomic_write_text(lima_yaml, new_text)
        return True
    return False


def lima_instance_config() -> Path:
    """The live Lima instance config Lima reads on `limactl start`. Distinct
    from HostPaths.LIMA_YAML (brig's template, used only on VM create)."""
    return Path.home() / ".lima" / VM_NAME / "lima.yaml"


def sync_all_lima_mount_roots() -> bool:
    """Sync the managed mount block into BOTH the template (used on VM create)
    and the live instance config (read on `limactl start`).

    Returns True if the INSTANCE config changed — i.e. the running VM needs a
    `brig system down --vm && brig system up` (a lossless stop/start; vz applies
    the new virtiofs mounts on restart and the container/image store survives —
    only `limactl delete` would wipe it).

    The two files are synced independently so a fault in one (e.g. operator-
    corrupted markers in `~/.lima`) doesn't strand the other; any errors are
    aggregated into one BrigError that names the offending file(s).
    """
    instance = lima_instance_config()
    errors: list[str] = []
    instance_changed = False
    for target in (HostPaths.LIMA_YAML, instance):
        if not target.exists():
            continue
        try:
            changed = sync_lima_mount_roots(target)
        except BrigError as e:
            errors.append(str(e))
            continue
        if target == instance:
            instance_changed = changed
    if errors:
        raise BrigError("; ".join(dict.fromkeys(errors)))
    return instance_changed
