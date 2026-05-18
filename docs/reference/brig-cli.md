# Brig CLI Reference

A working reference for the `brig` command. Companion to
[`warden-cli.md`](warden-cli.md) for the proxy lifecycle commands. For
the SDK that wraps these, see [`sdk-spec.md`](../sdk-spec.md).

`brig --version` prints the installed version. `brig --help` lists every
subcommand. `--debug` adds verbose logs; `--quiet` suppresses info-level
output; `--no-color` disables ANSI colors.

## Cells

| Command | What it does |
|---|---|
| `brig run <image> [cmd...]` | Create + start a new cell. `--name`, `--profile`, `--memory`, `--cpus`, `--secret`, `--env`, `--file <yaml>`, `--detach`, `--rm`. Flags must precede the image — `brig run` rejects flag-after-image with an explanatory error. |
| `brig cell list [--format=table\|wide\|json]` | List cells. `wide` adds CREATED, NETWORK columns. |
| `brig cell inspect <cell>` | Raw podman inspect JSON. |
| `brig cell diagnose <cell>` | Per-cell state summary (status, runtime, networks). |
| `brig cell stop <cell>` | SIGTERM with 10s grace. |
| `brig cell kill <cell>` | SIGKILL. |
| `brig cell start <cell>` | Start a previously stopped cell. |
| `brig cell pause <cell>` / `brig cell unpause <cell>` | Freeze / thaw processes. |
| `brig cell rm <cell> [-f]` | Remove cell + network + subnet allocation. `-f` required if running. |
| `brig cell rename <old> <new>` | Rename a cell. |
| `brig cell wait <cell>` | Block until exit; prints exit code. |
| `brig cell attach <cell>` | Attach stdio to a running cell. |
| `brig cell shell <cell>` | Open `/bin/sh` inside the cell. |
| `brig cell exec <cell> [-i] -- cmd...` | Run a one-off command inside the cell. |
| `brig cell export <cell>` | Print the cell's YAML definition (round-trips via `brig run --file -`). |

## Workspace

| Command | What it does |
|---|---|
| `brig cell cp <src> <dst>` | Copy files. `cell:/path → host` exports (with sanitize + quarantine xattr); `host → cell:/path` imports. The cell-side path must match `^[a-z0-9]...:/path`; `./out:put.txt` is treated as a local path, not a cell reference. |
| `brig cell files <cell> [path]` | `ls -la` inside the cell (default `/work`). |
| `brig cell logs <cell> [-f] [--tail N]` | Tail the cell's stdout/stderr. |
| `brig cell top <cell>` | `podman top` inside the cell. |
| `brig cell diff <cell>` | Filesystem changes since image base. |
| `brig cell stats [cell]` | One-shot resource usage. |

## Network policy + observability

| Command | What it does |
|---|---|
| `brig cell network <cell> [--tail N] [--blocked]` | Warden's per-cell request log. `--blocked` filters to only the requests warden denied, with the block reason on the same line. |
| `brig cell events [cell] [--tail N] [-f]` | Lifecycle events stream. `-f` follows; default is one-shot. |
| `brig system history [--tail N] [--cell <name>]` | Operations history (every `brig` invocation with exit code + duration). |
| `brig policy show [name] [--effective]` | Print policy. `global` or omitted: global; `<cell>`: per-cell override; `--effective <cell>`: merged view. |
| `brig policy set <name> --allow DOMAIN [...] --deny DOMAIN [...]` | Add/remove `allow`/`deny` rules. Use `--remove-allow` / `--remove-deny` to drop. |
| `brig policy set global --host-service name:port` | Declare a host service (warden forwards `<name>.host.brig` → host:port). |
| `brig policy set <cell> --host-service <name>` | Grant a cell access to a globally-declared host service. Per-cell ACL — cells without this entry cannot reach the service. |
| `brig policy test <domain> [--path /...] [--method GET]` | Dry-run the global policy against a domain. Same logic warden uses. |
| `brig policy rm <cell>` | Drop a cell's per-cell policy override. The cell falls back to the global policy on the next request. Refuses to delete the global policy. |

## Secrets

| Command | What it does |
|---|---|
| `brig secrets list` | List secrets + their mount paths and env var names. |
| `brig secrets add <name> [--value V \| --from-file F]` | Add a secret. Falls back to interactive `getpass` prompt if stdin is a TTY, else pipes from stdin. |
| `brig secrets rm <name> [-y\|--yes]` | Delete a secret. **Requires `--yes` for non-interactive use** (refuses to delete in scripts/CI without explicit confirmation); interactive shells get a `[y/N]` prompt. |

## Images

| Command | What it does |
|---|---|
| `brig image pull <image>` | Pull + cache an image. |
| `brig image warmup [--profile NAME]` | Pre-pull images for a profile. |
| `brig image verify <image> [--key KEY \| --keyless]` | Verify a cosign signature. Cosign is a hard requirement (no `podman trust` fallback). |

## System / lifecycle

| Command | What it does |
|---|---|
| `brig system up` | Initialize `~/.brig` if needed, create Lima VM if missing, start it if stopped, start warden. The "make it work" command. |
| `brig system down [--vm]` | Stop all cells + warden. `--vm` also stops the Lima VM. |
| `brig system init` | Bootstrap `~/.brig`, set 0700 perms on `secrets`/`addons`/`state/system`, write default policy. Idempotent. |
| `brig system profiles` | List trust profiles (`untrusted`, `supervised`, `dev`, `airgapped`, `honeypot`). |
| `brig system doctor --quick [--format=table\|json]` | Lightweight health check: proxy running + VM reachable. |
| `brig system doctor` | Deep environment check: tooling on PATH, Lima VM state, addon presence, directory permissions, network policy parses, warden running. Prints a checklist with fix suggestions on each failure. Use this before filing a bug. |
| `brig system verify` | Run security invariant checks (`verify_all` in `brig.security.verify`). |
| `brig system preflight` | Reconcile subnet state with podman networks; report drift. |
| `brig system metrics` | Output Prometheus-format counters. |
| `brig system prune [--cells\|--logs\|--subnets] [--log-days N] [--dry-run]` | Clean up. **No scope flag → all categories.** `--cells` removes stopped/exited cells + their networks. `--logs` deletes rotated operation logs older than N days (default 7) + invokes `warden logs prune`. `--subnets` frees allocator entries whose podman network is gone. `--dry-run` shows what would be removed. |
| `brig system watchdog [--interval N] [--max-restarts N]` | Monitor warden, restart it on failure. Foreground long-running command. |

## Config

| Command | What it does |
|---|---|
| `brig config show [key]` | Print config. Dot paths supported (`brig config show operation_logging.level`). |
| `brig config set <key> <value>` | Set a config value. Dot paths create intermediate dicts. Values are parsed as JSON if possible, else stored as a string. |
| `brig config reset` | Restore defaults. |

## Common workflows

**First-run setup:**
```bash
make setup            # one-time: install deps, create VM, run brig system init, start warden
brig run alpine echo hello
```

**Debugging blocked requests:**
```bash
brig cell network <cell> --blocked
brig policy test <domain>           # try a domain without sending real traffic
```

**Recovering from a confused state:**
```bash
brig system doctor                         # full env check, lists fixes
brig system preflight                      # reconcile subnet state without changing anything
brig system prune --dry-run                # see what's safe to clean up
brig system prune                          # do it
```

**Migrating a cell definition:**
```bash
brig cell export mycell > mycell.yaml
brig cell rm -f mycell
brig run --file mycell.yaml
```
