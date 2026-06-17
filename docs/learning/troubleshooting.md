# Troubleshooting

Quick answers to the failures most users hit first.

## "Warden proxy is not running"

```
ERROR: Warden proxy is not running
  Suggestion: Start with: brig system up
```

`brig run` fails closed when warden isn't reachable (invariant 9). Run
`brig system up` to start the VM (if needed) and warden. If `brig system up` itself
fails, see "Warden won't start" below.

## "limactl not found on PATH"

You need [Lima](https://lima-vm.io/):

```bash
brew install lima
```

Then `make setup` (or just `brig system up` if you've already run setup once).

## "Brig VM is not running"

Lima is installed but the VM isn't up. Either:

```bash
limactl start brig          # If the VM exists.
make setup                  # If you've never created it (idempotent).
```

`brig system doctor` reports both states with concrete fix suggestions.

## Warden won't start

Common causes, in order of likelihood:

1. **Addons missing.** If `~/.brig/cells/addons/enforce.py` doesn't exist:
   ```bash
   brig system up   # syncs addons from the installed package and (re)starts warden
   ```
   (`make _copy-addons` does the same one-shot staging if you only want to copy.)

2. **Policy file is malformed.** `warden start` refuses to boot on an
   unparseable `network-policy.json` — check the JSON syntax of
   `~/.brig/cells/network-policy.json`.

3. **State drift.** The subnet allocator state and podman's actual networks
   disagree (e.g. you `podman rm`'d a network outside brig):
   ```bash
   limactl shell brig -- warden preflight
   ```

4. **Image not pulled yet.** First `brig system up` pulls the mitmproxy image and
   can take a minute. Re-run after the pull completes.

`brig system doctor` covers all of the above in one pass.

## "Why was my request blocked?"

```bash
brig cell network <cell> --blocked
```

Shows the most recent blocked requests with the block reason inline.
Common reasons:

- `not in allowlist` — domain isn't in the cell's per-cell `allow` list (or the
  cell has no policy at all, which is default-deny). Edit with `brig policy set
  <cell> --allow <domain>`.
- `denied by rule: <pattern>` — explicit deny rule matched.
- `host header mismatch` — the cell tried to set a Host header that
  disagrees with the URL it's connecting to (smuggling defense).
- `internal IP range blocked` — the cell tried to reach an RFC1918 / link-local IP directly.
- `host service '<name>': cell '<cell>' has no host_services configured` —
  the cell tried `<name>.host.brig` but its per-cell policy doesn't grant
  access. Add the service name to the cell's `host_services` list (see
  `brig policy set <cell> --help`).

To test a domain without sending real traffic:

```bash
brig policy test <cell> <domain> --path /api
```

## Disk space

`~/.brig/state/system/<cell>/workspace/` accumulates per-cell. The Lima VM
has its own disk allocation (default 100 GiB) for the container layer. If
you're running out:

```bash
brig cell list                     # Find candidate cells.
brig cell rm -f <cell>             # Free workspace + container layer.
limactl shell brig -- podman system prune -f   # Reclaim image layers.
```

Or in one shot — `brig system prune` cleans up stopped cells, old rotated logs
(default >7 days), and orphan subnet allocations (cells whose podman
network was removed outside brig):

```bash
brig system prune --dry-run          # see what would be removed
brig system prune                    # do it (all three categories)
brig system prune --logs --log-days 1  # just trim recent logs
```

## "podman: command not found" inside the VM

`make setup` runs `scripts/provision-vm.sh` to install gVisor (`runsc`)
inside the VM. If you skipped setup or the script failed mid-way:

```bash
./scripts/provision-vm.sh
```

The script is idempotent — safe to re-run.

## Uninstall

To wipe everything (VM, addons, secrets, state):

```bash
make reset
```

This is destructive. To wipe just `~/.brig` while keeping the VM:

```bash
limactl stop brig
rm -rf ~/.brig
```

## Cell can't write to `/workspace/...` ("Read-only file system")

Brig mounts your cell's workspace at the path declared by
`workspace_mount` in the cell yaml (default: `/work`). Writes anywhere
ELSE on the rootfs hit the cell's `--read-only` mount and fail.

If your in-cell app expects to write to `/workspace/...`, either:

1. **Change the cell yaml** to align with the app's expectation:
   ```yaml
   workspace_mount: /workspace        # default is /work
   workspace_quota: "20g"             # bound the writable area
   ```
   Then `brig cell rm <name> -f && brig run --file <yaml>`. Bind
   mounts are fixed at container-create time; restart alone won't
   change the mount point.

2. **Change the app** to write under the declared `workspace_mount`.

3. **Set `writable_rootfs: true`** in cell yaml — last resort. Removes
   `--read-only` on the entire rootfs, which lets a hostile cell DoS
   the shared VM disk and hide state across stop/start. Use only for
   images whose entrypoint genuinely needs to write outside the
   workspace (legacy daemons writing to `/var/log`, etc.).

## Cell logs are empty

`brig cell logs <cell>` shows the container's stdout/stderr (it's a
thin wrapper over `podman logs`). If your app writes to a file inside
the cell rather than stdout, the output never reaches `podman logs`.
Inspect the file directly:

```bash
brig cell exec <cell> -- cat /var/log/myapp.log
```

(`brig cell read` only reaches files under the cell's workspace mount, not
arbitrary container paths like `/var/log` — use `exec ... cat` for those.)

For long-running interactive cells, write app logs to stdout (most
runtimes have a flag for this) so `brig cell logs -f <cell>` works.

## Cell flips to "stopped" immediately on `brig run`

The cell's PID 1 exited. Common causes:

- **Default command prints help and exits.** Many CLI tools do this
  when invoked with no arguments. Override in cell yaml:
  ```yaml
  command: ["sleep", "infinity"]      # keepalive — drive via `brig cell exec`
  ```
  Or use the app's daemon/gateway mode.

- **Image's entrypoint writes outside the workspace** and hits
  `--read-only`. See "Cell can't write to /workspace/..." above.

- **Required env var or secret missing.** `brig cell preflight <yaml>`
  validates secrets + host_services + ingress before starting.

## Warden blocks well-known telemetry endpoints (non-fatal)

Several agents include telemetry that warden's default-deny allowlist
correctly refuses. Common ones, with the agent's behavior:

| Domain | Source | Agent behavior |
|---|---|---|
| `http-intake.logs.us5.datadoghq.com` | Codex CLI Datadog shipping | Continues; logs locally |
| `mcp-proxy.anthropic.com` | Anthropic hosted MCP proxy | Falls back to direct API |
| `platform.claude.com` | Anthropic platform endpoint | Non-essential |

If you want these reachable, add them to the cell's `policy.allow`
list. If you want them silenced, set the agent's relevant
telemetry-off flag (e.g. Codex's `--no-telemetry`).

## Where logs live

| What | Path | Notes |
|---|---|---|
| Warden network logs | `/var/log/brig/network/<cell>.jsonl` (inside VM) | Per-cell JSONL. View via `brig cell network <cell>`. |
| Warden container logs | `podman logs warden` (inside VM) | mitmproxy stdout. View via `limactl shell brig -- warden logs`. |
| Cell stdout/stderr | `podman logs brig-<cell>` (inside VM) | View via `brig cell logs <cell>`. |
| Brig CLI history | `~/.brig/state/system/operations.jsonl` | View via `brig system history`. |
| Lifecycle events | `~/.brig/state/system/lifecycle.jsonl` | View via `brig cell events`. |

## Still stuck

Run `brig system doctor` first — it covers most environment issues with concrete
fix commands. If that comes up clean and the problem persists, `brig cell diagnose
<cell>` shows per-cell state (status, runtime, networks).

For deeper inspection: `brig cell inspect <cell>` dumps the full podman inspect
JSON.
