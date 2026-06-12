# Observability

Brig ships with an OpenTelemetry collector that runs as a sibling
container to warden inside the Lima VM. Warden's `otel_export` addon
pushes metrics and logs to it; the brig CLI reads them back out for
`brig system stats` and `brig cell network --otel`.

## The collector

- **Container name:** `brig-otel` (also in `INFRA_CONTAINER_NAMES`, so
  `brig system verify` knows not to flag it as an unauthorized cell on
  the proxy-external network).
- **Image:** `docker.io/otel/opentelemetry-collector-contrib`, pinned by
  digest in `src/brig/config.py:COLLECTOR_IMAGE_DIGEST`. The collector
  refuses to start if the digest hasn't been populated (run
  `./scripts/pin-collector-image.sh` to refresh it after a tag bump).
- **Ports (VM-internal):** OTLP gRPC `4317`, OTLP HTTP `4318`,
  Prometheus scrape `9464`. Lima forwards 127.0.0.1 on the host to
  these so the CLI can reach them.
- **Lifecycle:** started by `brig system up` before warden so warden
  has an emit target from cold start. `brig system down` stops it.
- **On by default.** There is no opt-out flag; the collector is
  considered part of the warden trust boundary (its image is pinned
  and it runs with the same cap-drop/no-new-privileges/read-only
  hardening as warden).

## Reading metrics

```bash
brig system stats          # per-cell summary scraped from the collector
brig system metrics        # raw Prometheus-format counters
```

`brig system stats` aggregates request counts, bytes in/out, blocked
requests, and TLS-mode (mitm vs passthrough) totals per cell. It
exits non-zero with a clear message if the collector isn't running.

## Reading flows

`brig cell network <cell>` defaults to the per-cell JSONL file
warden's `logger` addon writes (rotated, lives inside the VM). When
the JSONL has rolled past the window you care about — or when you
want the same view the collector keeps — use `--otel`:

```bash
brig cell network mycell --otel --tail 100
brig cell network mycell --otel --blocked
```

The two sources agree on recent flows; the OTel side retains longer
(see the retention table below).

## Where the raw data lives

The collector writes logs to a rotated JSONL file inside the VM at
`/var/lib/otel/`:

| Signal | Path | Rotation |
|---|---|---|
| Logs   | `/var/lib/otel/logs.jsonl`   | 100 MB × 5 backups, 7-day max-age |
| Metrics | (in-memory; exposed at `:9464/metrics`) | n/a |

To peek at the raw file from the host:

```bash
limactl shell brig -- sudo cat /var/lib/otel/logs.jsonl | tail -50
```

The configuration template is at
`src/brig/observability/collector_config.yaml`. Operators who want
to export to Tempo / Jaeger / Loki / etc. add an exporter under
`exporters:` and wire it into the corresponding pipeline under
`service.pipelines:`. The file is staged into the VM as
`/cells/otel-collector.yaml` (read-only) so collector restarts pick
up edits to the source-controlled template, not VM-side hand-edits.

## Troubleshooting

- `brig system doctor` reports collector status.
- `brig system stats` fails with a clear "is the collector running?"
  message if the Prometheus endpoint isn't reachable.
- A stuck container (`exited` but still present) is reaped on the
  next `brig system up` — `collector.start()` removes a stale
  container before re-running, so config edits take effect.
