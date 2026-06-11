# Mount Symlink Behavior — Findings & Decision

**Status:** Resolved by on-VM testing. Supersedes the earlier "rw is gated on
in-VM `nosymfollow`" premise, which was **wrong** for brig's stack. See
[host-mounts.md](host-mounts.md).

## The question

`mounts:` gives a cell rw access to a host directory. Can a symlink created
inside the mounted subtree be used to read/write **outside** it?

## What we tested (live brig VM, kernel 6.8, podman 4.9.3)

A VM-only secret was placed *outside* the subtree; a cell created a symlink to
it inside its mount and tried to read through it:

| Scenario | Result |
|---|---|
| `runsc` (gVisor): `ln -s <vm-only> /workspace/x; cat x` (abs + rel climb) | **"No such file or directory"** — no leak |
| `crun` (gVisor OFF): same | **"No such file or directory"** — no leak |
| Kernel `nosymfollow` bind remount: `cat` a symlink on it | `ELOOP` — primitive works, available if ever needed |

## Conclusion

**Container mount-namespace isolation already blocks the cell→VM symlink
escape, and it is runtime-independent** (runsc *and* crun). The only host-backed
path a cell sees is the mounted subtree; a symlink targeting any other VM path
isn't present in the cell's namespace, so it dangles. **No in-VM `nosymfollow`
hardening is required** for brig's boundary.

- `nosymfollow` on the VM-side mount would only be defense-in-depth against a
  hypothetical *runtime/gofer bug* that followed symlinks host-side. The kernel
  primitive works (verified) if we ever want that belt-and-suspenders, but it is
  **not** a precondition for shipping `mounts:`. We do not add it now (keep the
  bind simple; the boundary holds without it).
- The reconciler still binds the **realpath** of `host_path` (collapses symlink
  components in the *declared* path) and re-checks containment at attach.

## Where the real residual symlink risk is: host-side

The cell has rw, so it can write a symlink whose target string is an absolute
**macOS** path — `folder/evil → /Users/you/.ssh/id_rsa` — or a relative climb.
A symlink's target is just stored text; the cell doesn't need the path to exist
in its namespace to create it. That symlink lands in the shared folder on macOS
via virtiofs, where the path **is** resolvable. If a trusted host consumer
(hermes, an editor, a build) reads the folder and **follows** the symlink, it
escapes the folder — into the SSH key, etc.

No in-VM mechanism touches this; it's the macOS side. It is the same
confused-deputy boundary already documented: the consumer must treat the folder
— **symlinks included** — as untrusted.

## Mitigation (shipped)

1. **`brig cell mount-scan <cell>`** — walks each declared mount's host dir and
   reports symlinks whose realpath escapes the dir; `--quarantine` removes them.
   Reuses the copy-out sanitizer's escaping-symlink logic
   (`workspace._sanitize_tree`). The operator/hermes runs it before consuming
   cell output.
2. **Guidance for consumers:** read cell-written files with `O_NOFOLLOW` / reject
   symlinks resolving outside the folder. brig sandboxes the cell's *execution*,
   not the *fate of files it may write* — running the consume step in its own
   cell is the strongest option.

## Residual / out of scope

- A gVisor escape inside the VM is in-model (defense-in-depth, not a boundary) —
  unchanged by this feature.
- Host-side TOCTOU (consumer races the scanner) — `mount-scan` is a
  point-in-time check; for adversarial timing, the consumer's own `O_NOFOLLOW`
  discipline is the real control.
