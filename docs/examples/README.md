# Examples

Drop-in config snippets referenced from the learning + design docs.

| File | Purpose | Referenced by |
|---|---|---|
| `network-policy.example.json` | Example of `~/.brig/cells/network-policy.json` — the process-wide operational config: `rate_limits` / `log_filter` / `log_quota` / `policy_trace` / `notifications`. Egress allow/deny is per-cell, not here. | [`docs/learning/concepts.md`](../learning/concepts.md), [`docs/reference/addons.md`](../reference/addons.md) |
| `brig-logrotate.conf` | Logrotate config for `~/.brig/state/<cell>/network/*.jsonl` on macOS/Linux hosts that wire up logrotate. | [`docs/learning/troubleshooting.md`](../learning/troubleshooting.md) |

Add your own examples here; cross-link from wherever the doc points the
reader at a concrete config file.
