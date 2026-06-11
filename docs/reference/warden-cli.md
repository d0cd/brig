# Warden CLI Reference

`warden` is the proxy lifecycle CLI. It runs inside the Lima VM. From the
host, the standard pattern is to use `brig system up` / `brig system down` (which call
into warden) — but for diagnostics or policy authoring you can call warden
directly via `limactl shell brig -- warden <subcommand>`.

## Lifecycle

| Command | What it does |
|---|---|
| `warden start` | Pulls the mitmproxy image (if needed), creates the proxy-external network, mounts addons + policy, and starts the container with strict hardening (`--cap-drop ALL`, `--read-only`, gVisor not required since this is the proxy itself). After start, reconnects to any existing cell networks. |
| `warden stop` | Sends SIGTERM (10s grace), then removes the container. Idempotent. |
| `warden restart` | `stop` then `start`. |
| `warden status` | Prints `running` / `not running` and the list of cell networks the proxy is attached to. |
| `warden reload` | Sends SIGHUP to mitmproxy. `enforce` hot-reloads `network-policy.json`, the per-cell policy directory, and `subnet-map.json`; `logger` reloads its log filter (from `network-policy.json`) and `subnet-map.json`. Quicker than a restart. |
| `warden preflight` | Reconciles the subnet allocator state file with podman's actual networks. Reports missing networks, orphaned subnets, and inconsistencies — without making any changes. Run this when warden won't start. |

## Health & logs

| Command | What it does |
|---|---|
| `warden health` | Runs the addons' health checks (policy parses, log dir writable, addons loaded). `--json` for machine output. |
| `warden logs` | Tails the warden container logs via `podman logs -f warden`. |
| `warden logs prune --days N --size MB` | Compresses or removes per-cell network log files older than N days, or until the total size drops below MB. |

## Policy

Network policy is enforced **per cell** — there is no global allow/deny list.
Author and inspect a cell's policy from the host with `brig policy …` (see
[`brig-cli.md`](brig-cli.md)); the warden CLI does not have policy subcommands.

## Common workflows

**"Why was this request blocked?"**

```bash
# Easiest: brig-side filter shows the block reason inline.
brig cell network <cell> --blocked

# Or test a domain against a cell's policy without actually fetching it.
brig policy test mycell example.com --path /api
```

**"My policy edit doesn't seem to be applied."**

```bash
# Hot-reload (no restart needed for policy changes).
limactl shell brig -- warden reload

# If reload doesn't help, restart.
limactl shell brig -- warden restart
```

**"Warden won't start."**

```bash
# Preflight reports state inconsistencies without changing anything.
limactl shell brig -- warden preflight

# Last resort: tail container logs while attempting to start.
limactl shell brig -- warden logs &
limactl shell brig -- warden start
```
