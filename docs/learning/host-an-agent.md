# Hosting an agent in brig

This guide walks through running an agent inside a brig cell so it can talk
to a local model API server on the macOS host through the Warden proxy.
We'll use the [Hermes Agent](https://github.com/NousResearch/hermes-agent)
(NousResearch) as the example, but the same pattern works for any
container that needs cell-isolated egress plus a route back to a service
on the host.

> **Production-shaped reference**: `cells/hermes/` in this repo is the
> canonical worked example — a real `Containerfile`, a `hermes.yaml`
> cell spec, a brig-aware entrypoint, and a phase-by-phase validation
> plan at `cells/hermes/VALIDATION.md`. Start from there and adapt; the
> generic walk-through below covers the same pattern with placeholder
> names.

> Prereqs (already done on this machine):
> - Brig is installed and `brig up` succeeds.
> - A model API server is listening on `127.0.0.1:$MODEL_PORT` on the host.
> - Global policy already declares the host service:
>   `brig policy set global --host-service model:$MODEL_PORT`
>   (warden will forward `model.host.brig` → `host:$MODEL_PORT`).
>
> Verify with `brig health` → both checks `[OK]`.

## 1. Build the agent image inside the VM

Brig runs containers inside the Lima VM via rootful podman, so the image
needs to be available there — not in host docker. From the agent's source
tree:

```bash
limactl shell brig -- sudo podman build \
    -t localhost/my-agent:dev \
    -f Dockerfile .
```

Lima mounts the host home read-only into the VM by default, so a host-side
build context resolves directly:

```bash
limactl shell brig -- sudo podman build \
    -t localhost/my-agent:dev \
    -f "$HOME/path/to/agent/Dockerfile" \
    "$HOME/path/to/agent"
```

## 2. Grant the cell access to the host service

Per-cell ACL: a cell can only reach a `.host.brig` service if its per-cell
policy lists the name explicitly. Global policy declares the port; the
per-cell policy declares the grant.

```bash
brig policy set my-agent --host-service model
```

Verify:

```bash
cat ~/.brig/state/system/policies/my-agent.json
# Should show: "host_services": ["model"]
```

## 3. Add any required secrets

```bash
echo "$MY_API_KEY" | brig secrets add my-api-key
```

Secrets are mounted into the cell as files under `/run/secrets/<name>` and
the cell entrypoint can bridge them to env vars as needed.

## 4. Launch the cell

```bash
brig run \
    --name my-agent \
    --profile dev \
    --secret my-api-key \
    --detach \
    localhost/my-agent:dev \
    [agent args...]
```

Notes:
- `--profile dev` gives 4 GB / 4 CPU. Tighten with `--memory 2g --cpus 2`
  once you know the workload.
- For a one-shot smoke test, drop `--detach` and pass a `--query` or
  `--exec` style flag to the agent's entrypoint.

## 5. Verify it's reaching the host service

```bash
brig logs my-agent -f                    # agent stdout
brig network my-agent --tail 20          # warden's view of the cell's egress
brig network my-agent --blocked          # any requests warden refused
```

A working setup shows `GET /v1/... -> 200` lines in `brig network`, with
the cell's name in the warden log file inside the VM.

## 6. Cleanup

```bash
brig stop my-agent
brig rm my-agent
brig policy rm my-agent      # remove per-cell ACL (drops back to global)
brig secrets rm my-api-key
```

## Troubleshooting

- **`unknown host service: <name>`** — global policy missing the
  `host_services` entry. Re-add:
  `brig policy set global --host-service <name>:<port>`.
- **`host service '<name>': cell '<cell>' has no host_services configured`** —
  per-cell ACL missing.
  `brig policy set <cell> --host-service <name>`.
- **`Connection refused` on host** — the service isn't listening. Confirm
  with `curl http://127.0.0.1:<port>/`.
- **`Cell exited (1)` with no useful logs** — the agent entrypoint likely
  exited because some required dir under `/work` couldn't be created. Make
  sure your profile mounts the cell workspace (the `dev` profile does).
- **Stale subnet after a failed run** — re-running `brig run --name X`
  after the previous attempt errored out leaves the cell + network behind.
  `brig rm -f X` clears it.
