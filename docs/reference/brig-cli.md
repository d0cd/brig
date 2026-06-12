# Brig CLI Reference

A working reference for the `brig` command. Companion to
[`warden-cli.md`](warden-cli.md) for the proxy lifecycle commands. For
the SDK that wraps these, see [`sdk.md`](sdk.md).

`brig --version` prints the installed version. `brig --help` lists every
subcommand. `--debug` adds verbose logs; `--quiet` suppresses info-level
output; `--no-color` disables ANSI colors.

## Cells

| Command | What it does |
|---|---|
| `brig run <image> [cmd...]` | Create + start a new cell. See [brig run flags](#brig-run-flags) for the full flag list. Flags must precede the image — `brig run` rejects flag-after-image with an explanatory error. |
| `brig cell list [--format=table\|wide\|json]` | List cells. `wide` adds CREATED, NETWORK columns. Aliases: `brig cell ls`, top-level `brig ps`. |
| `brig cell inspect <cell>` | Raw podman inspect JSON. Alias: `brig cell status <cell>`. |
| `brig cell diagnose <cell>` | Per-cell state summary (status, runtime, networks). |
| `brig cell stop <cell>` | SIGTERM with 10s grace. |
| `brig cell kill <cell>` | SIGKILL. |
| `brig cell start <cell>` | Start a previously stopped cell. |
| `brig cell restart <cell>` | Stop (if running) then start. Applies cell-yaml changes. |
| `brig cell pause <cell>` / `brig cell unpause <cell>` | Freeze / thaw processes. |
| `brig cell rm <cell> [-f] [--keep-workspace]` | Remove cell + network + subnet allocation. `-f` required if running. By default the cell's `~/.brig/state/<cell>/` workspace is deleted; pass `--keep-workspace` to retain it. |
| `brig cell rename <old> <new>` | Rename a cell. |
| `brig cell preflight <path>` | Dry-run validation of a cell yaml/json without starting anything (host-side requirements only). |
| `brig cell wait <cell>` | Block until exit; prints exit code. |
| `brig cell attach <cell>` | Attach stdio to a running cell. |
| `brig cell shell <cell>` | Open `/bin/sh` inside the cell. |
| `brig cell exec <cell> [-i] -- cmd...` | Run a one-off command inside the cell. |
| `brig cell read <cell> <path>` | Stream a workspace file to stdout. Race-free; refuses symlinks. Safer than `brig cell cp` for plain reads. |
| `brig cell export <cell>` | Print the cell's YAML definition. Round-trip with `brig cell export <cell> > cell.yaml && brig run --file cell.yaml` (no stdin: `--file` takes a path). |
| `brig cell mount-scan <cell> [--quarantine]` | Scan a cell's host `mounts:` for symlinks whose realpath escapes the mounted dir (a cell can plant one pointing out of a shared rw mount). Reports them (exit 1 if any); `--quarantine` removes them. Run before a host process consumes cell-written files. |

### brig run flags

| Flag | Purpose |
|---|---|
| `--name`, `-n <name>` | Cell name. Auto-generated if omitted. |
| `--profile <name>` | Trust profile (`untrusted`, `supervised`, `dev`, `airgapped`, `honeypot`, or a user-defined one). |
| `--memory`, `-m <size>` | Memory limit (e.g. `512m`, `2g`). |
| `--cpus <n>` | CPU limit (accepts fractional). |
| `--pids-limit <N>` | Maximum number of PIDs in the cell. |
| `--network default\|none` | `default` = per-cell isolated network; `none` = airgapped. |
| `--secret`, `-s <name>` | Mount a secret (repeatable). |
| `--env`, `-e KEY=VALUE` | Environment variable (repeatable). |
| `--policy-allow <domain>` | Add to the cell's allowlist (repeatable). |
| `--policy-deny <domain>` | Add to the cell's denylist (repeatable). |
| `--label`, `-l KEY=VALUE` | Label on the cell (repeatable). |
| `--timeout <duration>` | Container timeout, e.g. `30s`, `5m`, `2h`. |
| `--workspace-quota <size>` | Cap on the cell's workspace size (e.g. `500m`). |
| `--image-digest sha256:...` | Pin the expected image digest. Reconciler refuses to start the cell on mismatch. |
| `--workdir <path>` | Working directory inside the cell. |
| `--file`, `-f <yaml>` | Cell definition file (YAML / JSON). Mutually compatible with flags; flags override fields from the file. |
| `--detach`, `-d` | Run in background. |
| `--rm` | Remove cell on exit. |
| `--yes`, `-y` | Auto-confirm prompts (e.g. the warden restart required when adding a new TCP `host_service` that needs a listener bound). |

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
| `brig cell network <cell> [--tail N] [--blocked] [--otel]` | Warden's per-cell request log. `--blocked` filters to only the requests warden denied, with the block reason on the same line. `--otel` reads from the OTel collector's flow store instead of the per-cell JSONL file (needed when the collector has retention older than the JSONL rotation). |
| `brig cell events [cell] [--tail N] [-f]` | Lifecycle events stream. `-f` follows; default is one-shot. |
| `brig cell ingress <cell>` | Show the reachable ingress URL(s) for a cell, the token-secret name to use in the `Authorization: Bearer` header, and whether the cell currently has a registered route. |
| `brig system history [--tail N] [--cell <name>]` | Operations history (every `brig` invocation with exit code + duration). |
| `brig policy show <cell>` | Print the cell's policy. Cells with no policy file show the empty default (cell blocks all egress). |
| `brig policy set <cell> --allow DOMAIN [...] --deny DOMAIN [...]` | Extend a cell's allow/deny lists. Use `--remove-allow` / `--remove-deny` to drop. To declare host_services, edit the cell yaml. |
| `brig policy test <cell> <domain> [--path /...] [--method GET]` | Dry-run the cell's policy against a request. Same matcher warden uses. |
| `brig policy rm <cell>` | Delete the cell's per-cell policy. The cell will block all egress until reconfigured. |

## Secrets

| Command | What it does |
|---|---|
| `brig secrets list` | List secrets + their mount paths and env var names. |
| `brig secrets add <name> [--value V \| --from-file F] [--force]` | Add a secret. Falls back to interactive `getpass` prompt if stdin is a TTY, else pipes from stdin. `--force` overwrites an existing secret (otherwise adding a name that exists is refused). |
| `brig secrets rm <name> [-y\|--yes]` | Delete a secret. **Requires `--yes` for non-interactive use** (refuses to delete in scripts/CI without explicit confirmation); interactive shells get a `[y/N]` prompt. |

## Images

| Command | What it does |
|---|---|
| `brig image build <dir> [--tag TAG] [--file PATH] [--build-arg K=V] [--use-warden]` | Build a container image from a directory inside the VM. Auto-derives tag from the dir basename if `--tag` omitted; auto-detects `Containerfile`/`Dockerfile` if `--file` omitted. `--use-warden` routes the build's HTTP(S) traffic through warden — injects `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` build args and mounts the warden CA at `/etc/ssl/certs/warden-ca.crt`. Same policy applies as runtime. |
| `brig image pull <image>` | Pull + cache an image. |
| `brig image warmup` | Pre-pull the pinned warden/mitmproxy base image into the VM cache. |
| `brig image verify <image> [--key KEY \| --keyless]` | Verify a cosign signature. Cosign is a hard requirement (no `podman trust` fallback). Advisory only — `--keyless` without an identity/issuer constraint confirms the image is signed, not who signed it; run-time integrity comes from digest pinning. |

## System / lifecycle

| Command | What it does |
|---|---|
| `brig system up` | Initialize `~/.brig` if needed, create Lima VM if missing, start it if stopped, start warden, then re-launch any gone `restart: always` cells. The "make it work" command. |
| `brig system down [--vm]` | Stop all cells + warden. `--vm` also stops the Lima VM. |
| `brig system init` | Bootstrap `~/.brig`, set 0700 perms on `secrets`/`addons`/`state/system`, write default policy. Idempotent. |
| `brig system profiles` | List trust profiles (`untrusted`, `supervised`, `dev`, `airgapped`, `honeypot`). |
| `brig system doctor --quick` | Lightweight health check: proxy running + VM reachable. |
| `brig system doctor` | Deep environment check: tooling on PATH, Lima VM state, addon presence, directory permissions, network policy parses, warden running. Prints a checklist with fix suggestions on each failure. Use this before filing a bug. |
| `brig system verify` | Run security invariant checks (`verify_all` in `brig.security.verify`). |
| `brig system preflight` | Reconcile subnet state with podman networks; report drift. |
| `brig system metrics` | Output Prometheus-format counters. |
| `brig system stats` | Per-cell summary (requests / bytes / blocks) scraped from the OTel collector. Requires the collector to be running. |
| `brig system prune [--cells\|--logs\|--subnets] [--log-days N] [--dry-run]` | Clean up. **No scope flag → all categories.** `--cells` removes stopped/exited cells + their networks. `--logs` deletes rotated operation logs older than N days (default 7) + invokes `warden logs prune`. `--subnets` frees allocator entries whose podman network is gone. `--dry-run` shows what would be removed. |
| `brig system watchdog [--interval N] [--max-restarts N]` | Monitor warden, restart it on failure. Foreground long-running command. |

## Config

| Command | What it does |
|---|---|
| `brig config show [key]` | Print config. Dot paths supported (`brig config show operation_logging.level`). |
| `brig config set <key> <value>` | Set a config value. Dot paths create intermediate dicts. Values are parsed as JSON if possible, else stored as a string. |
| `brig config set mount_roots <dir[,dir...]>` | Declare the host trees that cells may bind-mount via `mounts:` (VM-level allowlist). Rejects `/`, `$HOME`, secret dirs, `~/.brig`, `/etc`, non-dirs, and slug collisions — comparing by real path + on-disk identity, so symlinks, realpath aliases (`/etc` → `/private/etc`), and case variants (`~/.SSH`) can't slip past. Accepts a JSON list or a comma-separated string. A lossless VM restart applies it (`brig system down --vm && brig system up`; images preserved). See `docs/design/host-mounts.md`. |
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
brig policy test <cell> <domain>    # try a domain without sending real traffic
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
