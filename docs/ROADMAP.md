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

### Cell substrate: Apple Containerization (VM-per-cell)
**Status:** Deferred — evaluate as Apple's framework matures (macOS 26+).

Replace (or offer alongside) Lima-VM + gVisor with Apple's Containerization
framework, which runs each container in its **own** lightweight VM via
Virtualization.framework. Brig's value — the Warden egress choke point, per-cell
policy, secrets, audit, invariants — is independent of the substrate and sits on
top unchanged; Apple's `container` is a runtime primitive, not a competitor.

Wins: per-cell isolation becomes **hypervisor-enforced**. Today the Lima VM is
the only hard boundary and gVisor is explicitly *not* one (defense-in-depth), so
no-east-west / single-homing are enforced by network topology; VM-per-cell makes
them hardware-enforced. Plus sub-second starts and the end of the
image-store-on-one-shared-VM-disk class of problems (and gVisor provisioning).

Cost / open questions:
- **Network choke point.** Warden is today the sole egress path *inside* brig's
  single VM. With per-container VMs, Warden must be inserted in front of each
  cell-VM's networking (vmnet / per-container IP) so it stays mandatory and
  un-bypassable — the real re-architecture.
- **Invariant model.** The gVisor-centric invariants (5 = gVisor active; the
  shared-VM east-west rules) get re-expressed for a per-VM-boundary world —
  mostly a strengthening, but the ledger and `brig verify` need rework.
- OCI-compatible (image build/run carry over) but Swift/macOS-only and newer
  (container networking was limited on macOS 15, improved on 26 / Tahoe).

**Trigger:** Apple's framework is stable enough to depend on AND you want
stronger per-cell isolation, faster starts, or to stop maintaining Lima+gVisor.
Overlaps with "Brig on Linux" — both are substrate abstractions; do the
`vm_run()` / runtime abstraction once and back it with either.

**Effort:** High. Substrate swap behind the reconciler, plus a genuine re-think
of the network choke point and the invariant ledger.

### Host-side process hardening (macOS seatbelt)
**Status:** Deferred — defense-in-depth for the untrusted-state-dir boundary.

Confine brig's *macOS-side* processes with seatbelt (App Sandbox /
`sandbox-exec` profiles): `brig cell mount-scan` and any host tooling that
touches cell-influenced files (invariant 4 — the state dir is untrusted). A
profile limiting each helper's filesystem reach and denying
unexpected network/exec shrinks the blast radius if a cell plants content a
host-side helper later consumes (the confused-deputy boundary `mount-scan`
already guards). Pairs with — does not replace — the VM boundary.

Scope notes:
- Warden and cells run *inside* the VM, so seatbelt doesn't apply there — this is
  purely host-side helper hardening.
- `sandbox-exec` is deprecated-but-present; the App Sandbox entitlement path is
  the supported route for a signed binary. Pick per brig's distribution model.

**Trigger:** You're hardening the host-side confused-deputy surface (e.g. an
operator process auto-consuming files from a cell's rw mount) and want
OS-enforced confinement beyond `mount-scan` + consumer discipline.

**Effort:** Medium. Per-helper profiles + testing they don't break legitimate
access; more if it needs re-signing / entitlements.

### Hard workspace quota (block-level enforcement)
**Status:** Deferred — soft (reactive) enforcement ships today.

`workspace_quota` is currently a **soft** quota: enforced preventively on
`brig cp` and reactively by `brig system watchdog` (which *stops* a cell whose
`/work` has outgrown its quota). It is not a hard block-quota — a cell can burst
over its limit between watchdog sweeps until it's stopped. A hard cap isn't
possible today because the workspace lives on a **virtiofs** mount (`~/.brig/state`
→ `/state`), which can't carry an XFS/ext4 project quota, and the workspace is
read *directly from macOS* (`safe_open` for `brig cell read`, host-side lifecycle
ops), so it can't simply move inside an ext4 loop image without breaking that
visibility.

A real hard cap means re-architecting where the workspace lives: put it on the
VM's own ext4/xfs disk with per-cell project quotas (or a per-cell loopback ext4
image), and route **all** host access (`cp`, `read`, size) through the VM instead
of direct virtiofs reads. Overlaps with the substrate items above — the
Apple-Containerization / VM-per-cell path dissolves the shared-VM-disk problem
entirely, so evaluate this against that before building it standalone.

**Trigger:** A cell can fill the shared VM disk fast enough that the watchdog's
sweep interval is too coarse, AND you're not moving to a VM-per-cell substrate.

**Effort:** High. Storage re-layout, host-access rerouting through the VM,
provisioning changes, and migration of existing cells' workspaces.

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

### Adversarial-agent lab (containment CTF + jailbreak-under-observation)
**Status:** Deferred — the deterministic floor already exists as a test.

Brig's reason to exist is "run untrusted/agent code and *control + observe* it,"
so the natural validation is to attack it with a real agent. Two experiments,
building on `tests/test_containment_e2e.sh` (`make redteam`) and the canary item:

1. **Containment CTF (agent-driven).** An LLM agent with shell+network tools and
   an explicit "capture the flags by any means" prompt, against tiered flags
   mapped to the invariants: Tier-1 (egress bypass / SSRF / east-west / host
   secret — a break here is a real failure), Tier-2 (gVisor->VM, expected-possible
   defense-in-depth), Tier-3 (VM->macOS, the only hard boundary). `make redteam`
   is the deterministic Tier-1 floor; this is the agent-driven, higher-tier
   escalation. Score on **two** axes: prevention *and* detection (every attempt
   must show in Warden logs / `mount-scan` / audit — "contained but invisible" is
   a partial fail).
2. **Jailbreak-under-observation.** Run a jailbreak suite against an agent *inside*
   a cell and let it be fully compromised — brig's job isn't to stop the jailbreak
   (it's not an LLM-safety layer) but to guarantee zero blast radius and a complete
   forensic trail of what a jailbroken agent *attempts*. Turns brig into a safe lab
   for prompt-injection / agent-red-team research — a capability the bare runtime
   (or Apple's `container`) can't offer.

**Trigger:** You want to validate containment against a real adversary (not just
the scripted probe), or you're doing agent-safety research and need a contained,
observable harness. Pairs with the canary item (flags = canaries) and would
exercise the `novel_allowed` egress-novelty detection if that lands.

**Effort:** Medium. The harness is mostly orchestration (agent + flag scoring +
log-scraping the two axes); the deterministic core is already the e2e test.

### VM + warden autostart at login (consumer feedback: aitelier)
**Status:** Deferred — `restart: always` covers cells, not the VM itself.

`restart: always` re-launches cells on `brig system up`, but the VM + warden
don't come up at host login, so after a reboot something must run
`brig system up` first. Consumers self-heal with a wrapper (aitelier's
`scripts/lib.sh`). An optional, off-by-default brig launchd/login agent would
bring the VM + warden up at login so `restart: always` cells return unattended.

**Trigger:** A consumer wants a truly always-on brig-hosted service without a
wrapper script. **Effort:** Medium (a launchd plist + install/uninstall flow).

### Per-cell credential rotation without restart (consumer feedback: hermes)
**Status:** Deferred — needs a design pass.

Secret files (OAuth tokens) are read at cell start; a rotated value needs a
cell restart to take effect. Cells holding hourly-rotating OAuth tokens want the
new value picked up live (re-read the secret mount, or signal the cell).

**Trigger:** A cell's credential rotates faster than its acceptable restart
cadence. **Effort:** Medium — depends on how the in-cell app consumes the secret.

### Inter-cell routing primitive (`cell_services`) (consumer feedback: hermes)
**Status:** Deferred — host_services + ingress cover most shapes today.

A sanctioned cell→cell address path (without violating no-east-west) for
multi-cell architectures where one cell must call another. Would route through
warden like host_services, keeping the choke point. Overlaps "Cell groups /
compose" below.

**Trigger:** A multi-cell workload that genuinely can't be expressed via
host_services or ingress. **Effort:** High — new routing path + policy surface.

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

### Writable non-`/tmp` HOME mount (consumer feedback: aitelier)
**Status:** Deferred — minor; non-fatal today.

The read-only rootfs (writable only at `/work`, `/tmp`, `/run`) pushes cell
authors to put `HOME` under `/tmp`; some CLIs balk (codex refuses to create
helper binaries under a `/tmp` HOME — non-fatal warning, but a stricter CLI
could fail). A brig-provided small per-cell writable HOME tmpfs *outside* `/tmp`
(e.g. `/home/<cell>`) would let HOME-sensitive CLIs behave without a hand-rolled
mount. **Trigger:** a cell's CLI hard-fails on a `/tmp` HOME. **Effort:** Low
(one more tmpfs mount + a default HOME).

### Cross-source audit query (consumer feedback: hermes)
**Status:** Deferred — needs a correlation-id contract.

`brig cell audit <cell> --since 1h` joining warden's network log with the
consumer's own run/event log by correlation id, for one timeline across the
proxy boundary. **Trigger:** incident triage that spans warden + the app.
**Effort:** Medium — requires a shared correlation id end to end.

### Mount-side `nosymfollow` (consumer feedback: hermes)
**Status:** Deferred — blocked on runtime support.

If podman 5.x / an alternate runtime exposes `nosymfollow` for bind mounts, use
it to kill the host-side symlink confused-deputy at the mount layer, retiring
the consumer-side `safe_open` / `mount-scan` discipline. **Trigger:** the runtime
exposes it. **Effort:** Low once available (a mount flag) — until then, N/A.

## Out of scope

### Multi-tenant Warden
Multiple users sharing one Brig instance with isolated namespaces. Wrong
scope — Brig is a personal workstation tool. Give each user their own instance.
