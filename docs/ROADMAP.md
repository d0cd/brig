# Brig Roadmap

Evaluated features, prioritized by value and effort. Items marked "deferred"
have a clear trigger condition — build them when you hit the friction, not before.

## Near-term

### Snapshot / restore
**Status:** Deferred — check if runtime installs are common.

`brig snapshot my-cell` captures the full container filesystem diff + workspace
+ policy as a tarball. `brig restore` recreates the cell exactly. Currently
`ops.sh migrate` only captures `/work/.my-cell/` (agent state), not runtime
package installs.

**Trigger:** You find yourself re-installing packages after `brig cell rm` + `brig run`.

**Effort:** Low. `podman commit` + `podman save` + tarball glue.

## Medium-term

### Brig on Linux (no Lima)
**Status:** Deferred — build when dispatcher needs to run Brig on cloud VMs.

Remove the Lima VM dependency. On Linux, run Podman directly. The security
model changes (host IS the boundary), but cell isolation (Podman + gVisor +
Warden) still works. Would make `brig run` work identically on laptop and
cloud.

**Trigger:** Dispatcher is ready and needs a native Linux Brig backend.

**Effort:** High. Abstract `vm_run()` to support direct execution. Handle
path mapping differences. Test on multiple distros.

### Dispatcher integration
**Status:** Deferred — dispatcher's job, not Brig's.

`brig push my-cell --target cloud` sends cell definition + state to
dispatcher for automated cloud deployment. The cell definition
(`my-cell.yaml`) is already the portable spec that dispatcher would consume.

**Trigger:** Dispatcher exists and has an API to receive cell specs.

**Effort:** Low on Brig side (thin `brig push` command). Real work is in
dispatcher.

### Warden metrics endpoint
**Status:** Deferred — build for production monitoring.

Prometheus-format metrics on Warden's health endpoint: requests/sec,
blocked/allowed ratio, per-cell bandwidth, host service usage, ingress
auth failures. Data already tracked in addons.

**Trigger:** Running agents in production and want Grafana dashboards.

**Effort:** Low. Format existing counters as Prometheus text exposition.

### Budget / cost tracking
**Status:** Deferred — irrelevant with subscription pricing.

Track per-cell LLM costs via Warden logs. Parse usage from API responses.
Enforce daily/monthly budgets per cell.

**Trigger:** Switching from subscription pricing to per-token pricing and
getting surprise bills.

**Effort:** Medium. Response body parsing in Warden + budget enforcement addon.

### Anonymous egress (Tor)
**Status:** Deferred — earlier scaffolding (`warden/tor.py`, `--tor` flag,
`warden tor` subcommands) was deleted because the start path was a stub
and nothing connected it. Re-design fresh.

Cells route their warden-approved egress through Tor instead of (or
alongside) the public internet, for cells that need anonymity from the
upstream services they call.

Two architectural options to evaluate when this is built:

1. **Global toggle.** A separate `proxy-tor` external network with a Tor +
   Privoxy stack. `brig system up --tor` brings the stack up; all cells route
   through it. Simple but coarse.
2. **Per-cell toggle.** Cell spec field `egress: tor` selects a different
   upstream from warden. Requires warden to chain to per-cell upstreams,
   which mitmproxy supports via per-flow `set_upstream_proxy_*`.

Either path needs: cosign-verified pinned Tor + Privoxy images, a
`brig system doctor` check that Tor exit-IP egress actually works, and
documentation that this only hides the cell from upstream — not the cell
from the host (Lima VM still sees the cell, warden still policies it).

**Trigger:** A real cell needs to call a service without revealing the
operator's IP, AND warden's allowlist isn't sufficient.

**Effort:** Medium-high. Mostly correctness work — getting upstream
chaining right, container hardening for the Tor stack, and verifying the
exit IP actually differs from the host's.

### Audit-log signing
**Status:** Deferred — earlier `signer.py` scaffolding was deleted because
it had no mitmproxy hooks and no consumer.

Per-warden-session signed log batches with Ed25519. Either a new mitmproxy
addon that wraps `logger.py` writes (so every batch flushed gets signed)
or a host-side `brig audit verify` tool that signs/verifies after the
fact from the JSONL files.

**Trigger:** A compliance or incident-response requirement to prove logs
weren't tampered with after capture.

**Effort:** Medium. Key management (per-session keypair, public key
distribution), batch boundary semantics, and a verification CLI.

### Canary tokens
**Status:** Deferred — earlier `canary.py` addon was deleted because no
CLI surface registered tokens; the only path was hand-editing per-cell
policy JSON.

Plant decoy values inside a cell that should never leave it; on egress
match, block the request and kill the cell. The detection logic in the
deleted addon was sound — the missing pieces were:

- `brig canary add <cell> <label>` (and `rm`, `list`) to register tokens
  with `getpass`-style value entry, persisted via the existing atomic-write
  helpers to per-cell policy.
- A `warden reload` after registration so the new tokens are picked up
  without a restart.
- A `brig canary status <cell>` showing recent canary trips from the
  per-cell network log.

**Trigger:** You're shipping cells to environments where you suspect the
workload itself might be malicious, not just the network.

**Effort:** Low for the CLI; the addon side has prior art that can be
rewritten in ~200 lines.

## Nice-to-have

### `brig watch` — live TUI dashboard
**Status:** Deferred — polish, not capability. Earlier `src/tui.py` and
`src/dashboard.py` scaffolding was deleted because it was unwired and
untested. The same Textual library is fine when this comes back; design
fresh from `brig cell stats`, `brig cell network`, and `brig cell list` as data sources.

**Trigger:** Running multiple agents daily and switching between commands is
annoying.

### AI log compaction
**Status:** Deferred — earlier `summarizer.py` addon was deleted because
nothing loaded it and it lived in the wrong place architecturally.

If revived, build it as a host-side `brig cell logs compact` tool that reads
the JSONL files outside the warden container. That keeps warden small,
keeps the LLM API egress on the host (where it can be policied or routed
through an existing gateway), and avoids putting an LLM dependency on the
proxy's critical path.

**Trigger:** Per-cell logs are big enough that grep is slow and you want
preserved-but-summarized rolling history.

**Effort:** Medium. The summarization prompt, partition logic, and
cost-budget code from the old addon can be ported almost verbatim — only
the I/O layer needs to be reworked for host-side execution.

### Cell groups / compose
**Status:** Deferred — host services avoid the need.

Define multiple related cells in one file with shared policy. Like
docker-compose but with Brig's security model.

**Trigger:** You have a multi-cell workload that can't be solved with host
services (e.g., MCP server as a separate cell that the cell talks to directly).

**Effort:** High. New spec format, dependency ordering, shared lifecycle.

## Out of scope

### Multi-tenant Warden
Multiple users sharing one Brig instance with isolated namespaces. Wrong
scope — Brig is a personal workstation tool. Give each user their own instance.
