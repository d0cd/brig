# Brig Roadmap

Evaluated features, prioritized by value and effort. Items marked "deferred"
have a clear trigger condition — build them when you hit the friction, not before.

## Near-term

### Per-cell host services
**Status:** Deferred — build when running multiple cells with different trust levels.

Currently all declared host services are available to all cells. Per-cell
host services would restrict which cells can reach which host:port pairs.

**Trigger:** You run a second cell that shouldn't access aitelier or LiteLLM.

**Effort:** Low. Add `host_services` to per-cell policy. Check cell name in
`_handle_host_service()`.

### Snapshot / restore
**Status:** Deferred — check if runtime installs are common.

`brig snapshot hermes` captures the full container filesystem diff + workspace
+ policy as a tarball. `brig restore` recreates the cell exactly. Currently
`ops.sh migrate` only captures `/work/.hermes/` (agent state), not runtime
package installs.

**Trigger:** You find yourself re-installing packages after `brig rm` + `brig run`.

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

`brig push hermes --target cloud` sends cell definition + state to
dispatcher for automated cloud deployment. The cell definition
(`hermes.yaml`) is already the portable spec that dispatcher would consume.

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

**Trigger:** Switching from subscription pricing (aitelier runAgent) to
per-token pricing and getting surprise bills.

**Effort:** Medium. Response body parsing in Warden + budget enforcement addon.

## Nice-to-have

### `brig watch` — live TUI dashboard
**Status:** Deferred — polish, not capability.

Unified real-time view: cell states, resource usage, network activity.
Data sources exist (`brig stats`, `brig network`, `brig list`). `src/tui.py`
has 853 lines of TUI infrastructure.

**Trigger:** Running multiple agents daily and switching between commands is
annoying.

### Cell groups / compose
**Status:** Deferred — host services avoid the need.

Define multiple related cells in one file with shared policy. Like
docker-compose but with Brig's security model.

**Trigger:** You have a multi-cell workload that can't be solved with host
services (e.g., MCP server as a separate cell that Hermes talks to directly).

**Effort:** High. New spec format, dependency ordering, shared lifecycle.

## Out of scope

### Multi-tenant Warden
Multiple users sharing one Brig instance with isolated namespaces. Wrong
scope — Brig is a personal workstation tool. Give each user their own instance.
