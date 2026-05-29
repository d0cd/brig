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
| `warden reload` | Sends SIGHUP to mitmproxy. The `enforce` and `logger` addons hot-reload `network-policy.json`, `subnet-map.json`, and the per-cell policy directory on receipt. Quicker than a restart. |
| `warden preflight` | Reconciles the subnet allocator state file with podman's actual networks. Reports missing networks, orphaned subnets, and inconsistencies — without making any changes. Run this when warden won't start. |

## Health & logs

| Command | What it does |
|---|---|
| `warden health` | Runs the addons' health checks (policy parses, log dir writable, addons loaded). `--json` for machine output. |
| `warden logs` | Tails the warden container logs via `podman logs -f warden`. |
| `warden logs prune --days N --size MB` | Compresses or removes per-cell network log files older than N days, or until the total size drops below MB. |

## Policy

| Command | What it does |
|---|---|
| `warden policy validate [path]` | Loads a policy JSON/YAML file and reports parse errors and rule problems (invalid domains, suspicious patterns). Useful for linting per-cell policies before they're written. |
| `warden policy test <path> <domain> [--path /...] [--method GET]` | Runs the proxy's allow/deny matcher against the policy at `<path>`. From the host the equivalent for a deployed cell is `brig policy test <cell> <domain>`. |

For the host-side `brig` command, see [`brig-cli.md`](brig-cli.md).

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

# Check the policy file parses.
limactl shell brig -- warden policy validate

# Last resort: tail container logs while attempting to start.
limactl shell brig -- warden logs &
limactl shell brig -- warden start
```
