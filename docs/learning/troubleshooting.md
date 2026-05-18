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
   make _copy-addons
   ```

2. **Policy file is malformed.** Validate it:
   ```bash
   limactl shell brig -- warden policy validate
   ```

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

- `not in allowlist` — domain isn't in `network-policy.json`'s `allow` list.
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
brig policy test <domain> --path /api
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
