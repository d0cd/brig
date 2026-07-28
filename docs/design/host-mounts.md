# Design: Scoped Host-Directory Mounts (`mounts:`)

**Status:** Implemented (ro + rw). The original premise — that rw was unsafe
until in-VM `nosymfollow` hardening — was **disproved empirically** (see
[Symlink reality](#symlink-reality-empirically-verified)): container
mount-namespace isolation already prevents a cell from following a symlink out
of the mounted subtree to a VM path, under both `runsc` and `crun`. The real
residual symlink risk is **host-side** and is the consumer's responsibility,
backed by a brig host-side scanner. See `docs/design/mount-symlink-hardening.md`.

## Motivation

Today the only host↔cell filesystem bridge is the managed `/work` workspace
(`~/.brig/state/<cell>/workspace`). Editing a host directory that lives elsewhere
means cloning it into `/work` and syncing changes back — a clone/sync dance.

Concrete driver: a hermes agent keeps a directory of working files and delegates
work on those files to aitelier, which runs the work inside a brig cell. The cell
needs **read-write** access to that shared folder so changes land in place.

`mounts:` lets a non-`untrusted` cell bind-mount a single operator-chosen host
directory (ro by default, rw opt-in), keeping the existing isolation guarantee for
everything outside the mounted subtree.

## Threat-model framing (read this first)

This feature changes brig's job, for the affected cell, from *"isolate untrusted
code"* to *"let a semi-trusted agent edit a shared folder in place."* That is why
it is a `supervised`/`dev` capability and the `untrusted` profile rejects it — the
same rule already applied to `host_services` and TLS passthrough.

Two distinct risks, with different owners:

1. **brig's boundary** (brig's job): a cell must not reach *outside* the mounted
   subtree. Two sub-cases, both handled: (a) **widening the VM's host view** is
   bounded by the `mount_roots` allowlist; (b) **symlink-escape from inside the
   cell** is blocked by container mount-namespace isolation — a symlink in the
   mount that targets an unmounted VM path simply dangles (verified under runsc
   *and* crun; see [Symlink reality](#symlink-reality-empirically-verified)).
2. **Confused deputy** (the operator's job — brig *cannot* solve this): the cell is
   an untrusted *writer*; whatever trusted host process consumes the files it wrote
   is a *reader* outside the sandbox. **brig sandboxes the cell's execution, not the
   fate of files it is permitted to write.** If the consumer executes / sources /
   builds-from those files without its own review or sandbox, the sandbox is
   bypassed by the data flow, not by a breakout. This risk is identical for a rw
   mount, an overlay export, or a git push-back — it is inherent to "untrusted-cell
   output feeds a trusted consumer," not to the mount mechanism.

The cell-to-cell story is unchanged: cells still cannot read each other (invariant
1 is network isolation; separate workspaces/sandboxes). A shared mount is a
**deliberate filesystem channel between exactly the cells granted it** — two cells
pointed at the same rw host dir can pass data through it by design. Only grant a
shared mount to cells that are allowed to see each other's data.

## Design

### Cell yaml — `mounts:` (per-cell)

Shape — `{name, host_path, mount_point, mode?}`, with `mode` ∈ {`ro`, `rw`}:

```yaml
# user: "0" — a rw mount the cell must own needs a root cell (gVisor presents
# virtiofs mounts as 0:0; see "Ownership & writability" below). ro needs nothing.
user: "0"
mounts:
  - { name: hermes-files, host_path: /Users/d0c/work/hermes/files, mount_point: /workspace, mode: rw }
  - { name: refdata,      host_path: /Users/d0c/work/corpus,        mount_point: /data,      mode: ro }
```

- `name` — audit label; unique within the cell.
- `host_path` — absolute, normalized; its **realpath must resolve under one of the
  declared `mount_roots`** and be an existing directory.
- `mount_point` — where it appears in the cell.
- `mode` — `ro` (default) | `rw`. Per-entry; this is the rw opt-in.

### `mount_roots` — VM-level allowlist (list)

```
brig config set mount_roots /Users/d0c/work,/Users/d0c/code   # one-time; VM restart to apply
```

`mount_roots` is the set of host trees the VM is *ever* willing to expose to cells.
It is **VM-level, not per-cell** — for two reasons:

1. **Lima mounts are static and VM-wide.** A cell runs *inside* the VM, so a host
   file is only visible to a cell if it is mounted into the VM, and Lima mounts are
   fixed at VM start and shared by every cell. "Which host trees may enter the VM"
   is therefore unavoidably a VM fact, not a per-cell one.
2. **It is the security bound.** An operator-declared allowlist, set once and
   auditable, prevents a less-careful (or agent-authored) cell yaml from exposing an
   arbitrary host tree (`/`, `~/.ssh`, …) to the VM. Without it the cell yaml would
   be the sole gate, leaving only a leaky denylist. This is consistent with
   invariant 4 (the macOS state dir / specs are untrusted).

The per-cell thing — *what this cell mounts* — stays in the cell yaml (`mounts:`).
The VM-level thing — *which roots may ever be mounted* — stays in config.

### Lima mount mechanics

Each declared root `R` is statically Lima-mounted at `/mnt/host/<slug(R)>` (slug =
sanitized basename; validation rejects two roots with colliding slugs). Adding or
changing `mount_roots` rewrites both the template and the live instance `lima.yaml`
and is applied by a **lossless** VM restart (`brig system down --vm && brig system
up`): vz re-applies the virtiofs mounts on start and the podman image/container
store survives — only `limactl delete` would wipe it. No per-cell VM reconfiguration.

`HostPaths.MOUNT_ROOTS` (list) and `VMPaths.MOUNTS_DIR` (`/mnt/host`) are added to
`config.py`. If `mount_roots` is empty, any cell declaring `mounts:` is rejected at
validation. Default: empty (opt-in).

### Ownership & writability of rw mounts (gVisor reality)

gVisor's gofer presents virtiofs-backed files (host `mounts:` **and** the managed
`/work` workspace) as owned by **`0:0` inside the cell**, and that ownership can't
be changed from the guest — `chown`, podman `:U`, and `:idmap` are all no-ops or
unsupported on virtiofs under runsc (empirically verified). Consequences:

- A virtiofs rw mount is fully owned/writable only by a cell running as **root
  (uid 0)** — it's the owner of the `0:0`-squashed tree. A non-root cell is
  permanently "other": it may write only what the dir mode grants and can't
  rewrite files or chmod. This is why a non-root image (e.g. one whose `USER` is
  not 0) hits `EACCES` writing a dir it conceptually owns.
- Regardless of the cell's uid, files it writes land **owned by the operator on
  macOS** (virtiofs maps guest writes back to the VM/host user), so host-side
  readback is never the problem.

So to host-mount a directory the cell must *own* (HERMES_HOME, app state, a build
output dir), run that cell as root with the cell-yaml `user: "0"`. Running as root
*inside* the gVisor+VM sandbox is not a host-privilege change — the VM is the only
hard boundary and the cell is untrusted regardless of its internal uid. `ro`
reference mounts need none of this.

### Validation — `_v_mounts` / `_v_mount_entry` (`validators.py`)

Per-entry checks:

- `name`: required, `MOUNT_NAME_PATTERN`, unique per cell.
- `host_path`: required, absolute, normalized, no `..`. `realpath(host_path)` must
  (a) exist, (b) be a directory, (c) live under `realpath(R)` for some `R` in
  `mount_roots` (`startswith(R + "/")`). Rejected if `mount_roots` is empty.
- `mount_point`: required, absolute, normalized — validated by
  `_v_cell_mount_point` (mirrors, kept separate from, `_v_workspace_mount`):
  forbidden prefixes (`/proc`, `/sys`, `/dev`, `/etc`, `/run/secrets`,
  `/run/host`, `/run/brig`, not `/`); no `:` (the podman `-v` separator); must
  not equal *or* be an ancestor/descendant of the cell's `workspace_mount`
  (default `/work`); deduped.
- `mode`: `ro` | `rw` (`MOUNT_MODES`).
- Cross-field: **rejected on the `untrusted` profile** via `_profile_is_untrusted()`.
- `MAX_MOUNTS_PER_CELL` cap (`config.py`).
- Register `"mounts": _v_mounts`; add the `if "mounts" in cell_def` dispatch in
  `validate_cell_definition`.

### Reconciler — `_attach_mounts(spec, cmd)` (`reconciler.py`)

Per entry, in `build_run_command`:

1. Re-resolve `realpath(host_path)`, re-confirm it is under one of the `mount_roots`
   (runtime check is the real boundary; unavoidable TOCTOU between check and bind).
2. Translate to the VM path: `/mnt/host/<slug(R)>/<relpath(realpath, R)>`.
3. Emit `-v {vm_path}:{mount_point}:{mode}`.
4. `log_lifecycle("mount_attach", spec.name, {name, mount_point, mode})` and a loud
   `info()` banner with a "Warden does not see this" disclaimer: *"cell '<name>'
   has a <mode> host mount at <mount_point> → <host_path>; the cell reads/writes
   these host files directly."*

### Profile gating

`untrusted` rejects `mounts:` at parse time (identical to `host_services` /
passthrough). `supervised` / `dev` allow it. Per-entry `mode` is
the rw opt-in; no separate global kill-switch.

## Symlink reality (empirically verified)

The original design gated rw on in-VM `nosymfollow` hardening, on the theory
that a runtime symlink in the mount could escape the subtree. **On-VM testing
disproved that for brig's stack** (see `docs/design/mount-symlink-hardening.md`
for the full results):

- A cell creating `ln -s <vm-only-path> /workspace/x` and reading `x` got
  **"No such file or directory"** — under **both `runsc` and `crun`**. Container
  **mount-namespace isolation** means the only host-backed path the cell sees is
  the mounted subtree; a symlink to any other VM path simply dangles. This is
  *runtime-independent* — it does not rely on gVisor.

So no in-VM symlink hardening is needed for brig's boundary. The reconciler binds
the **realpath** of `host_path` (collapsing symlink components in the declared
path; runtime containment re-checked at attach), and that is sufficient
in-cell.

**The real residual symlink risk is host-side.** The cell has rw, so it can write
`folder/evil → /Users/you/.ssh/id_rsa` (a symlink's target is just a stored
string — it need not exist in the cell's namespace). That symlink lands in the
shared folder on macOS, where the path *is* resolvable. If a trusted host
consumer (hermes, your editor) follows it, it escapes the folder. No in-VM
mechanism touches this — it is part of the confused-deputy boundary and is the
**consumer's** responsibility. brig ships a host-side mitigation: `brig cell
mount-scan <cell>` walks the declared mount dirs and reports/quarantines symlinks
whose realpath escapes the dir (reusing the copy-out sanitizer's logic).

## Isolation summary

| Axis | Guarantee |
|---|---|
| Network (cell↔cell) | Unchanged — invariant 1, no east-west. |
| Filesystem (cell↔cell) | Separate `/work` + rootfs; no sharing **unless** the operator mounts the same host dir into both cells (then they share *that dir only*). |
| Cell↔host (outside mount) | Cell confined to its rootfs + `/work` + declared mounts; nothing else on the host is reachable. |
| Cell↔host (inside mount) | Cell reads/writes the mounted subtree directly; Warden does not mediate these bytes. |
| VM host exposure | Bounded to the declared `mount_roots`; nothing else enters the VM. |

## INVARIANTS ledger row (added to docs/INVARIANTS.md on enablement)

The invariant text + surface table now live in `docs/INVARIANTS.md` (invariant
13). Summary: opt-in per cell yaml; `untrusted` profile rejects; `host_path`
realpath must resolve under a declared `mount_roots` entry; `mount_point` can't
shadow system paths or `/work`; cell-side escape is blocked by mount-namespace
isolation; the host-side symlink risk is mitigated by `brig cell mount-scan` and
is otherwise the consumer's responsibility; every attach is audited + bannered;
Warden does not mediate the bytes.

## Implementation plan (TDD; each step ships green)

1. **Config + Lima:** `MOUNT_ROOTS` (list) in `config.py`, `brig config set
   mount_roots`, lima.yaml mount generation, `VMPaths.MOUNTS_DIR`. Tests: config
   parse, slug uniqueness, lima rendering.
2. **Spec + validation:** `CellSpec.mounts`, `_v_mounts`/`_v_mount_entry`, dispatch.
   Tests: `tests/test_mounts_spec.py` (paths, modes, root-containment, untrusted
   reject, shadow/`/work`, cap, `mount_roots`-empty reject).
3. **Reconciler (ro first):** `_attach_mounts` realpath→VM translation, `-v ...:ro`,
   audit + banner. Tests: `tests/test_reconciler_mounts.py` (argv shape, translation).
4. **Enable rw:** mounts (ro+rw) are unconditionally enabled; `_attach_mounts`
   emits the binds for both modes; on-VM verification confirmed no in-VM symlink
   hardening is required.
5. **Host-side scanner:** `brig cell mount-scan <cell>` — reports/quarantines
   symlinks whose realpath escapes a mounted dir (the host-side residual-risk
   mitigation). SDK `run_sync(mounts=...)` param. INVARIANTS row.
6. **Docs:** `cell-definition.md` `mounts:` reference; `brig-cli.md` `config set
   mount_roots` + `cell mount-scan`; export/inspect round-trip.

## Open assumptions

- Directories only (no single-file mounts) in v1.
- `mount_roots` is a list of absolute, existing dirs; obvious-catastrophe roots
  (`/`, `$HOME` itself, `~/.brig`, `~/.ssh`) are rejected even though operator-set.
  The floor (`validate_mount_roots`) compares by real path and on-disk identity,
  so a symlink, a realpath alias (`/etc` → `/private/etc`), or a case variant on a
  case-insensitive filesystem (`~/.SSH` == `~/.ssh`) can't dodge it.
- Changing `mount_roots` requires a lossless VM restart (`brig system down --vm &&
  brig system up`); the image store is preserved (only `limactl delete` wipes it).
