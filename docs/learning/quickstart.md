# Quick Start

Get Brig running in under 5 minutes.

## Prerequisites

- macOS (Apple Silicon or Intel)
- Python 3.10+
- [uv](https://docs.astral.sh/uv/): `curl -LsSf https://astral.sh/uv/install.sh | sh`
- [Lima](https://lima-vm.io/): `brew install lima`

## 1. Install and Start

```bash
git clone https://github.com/d0cd/brig.git
cd brig
make setup
```

`make setup` handles everything: initializes `~/.brig`, creates the Lima VM,
starts the VM, and starts the Warden proxy. First run takes a few minutes
(VM creation + provisioning). Subsequent runs are fast.

## 2. Run Your First Cell

```bash
brig run alpine echo "Hello from a secure cell!"
```

This creates a gVisor-sandboxed container on an isolated network with all
egress filtered through the Warden proxy. The cell name is auto-generated.

## 3. Run a Named Cell

```bash
brig run --name my-cell --policy-allow pypi.org -d python:3.12 python -c "
import time, urllib.request
print(urllib.request.urlopen('https://pypi.org').status)
while True: time.sleep(60)
"
```

Egress is **default-deny**: without `--policy-allow pypi.org` the request is
blocked (403) and the cell crashes before it can sleep. The trailing
`while True: time.sleep(60)` keeps the cell running so
`brig cell exec / files / logs` work. Without it the cell exits
within a second of the urlopen call and the inspection commands below
fail with "cell not running."

Check it:

```bash
brig cell list                     # see all cells
brig cell logs my-cell             # view output
brig cell files my-cell            # list workspace
brig cell exec my-cell -- whoami   # run command inside
brig cell stop my-cell             # stop
brig cell rm my-cell               # remove
```

## 4. Use Profiles

```bash
brig system profiles                 # see available profiles

brig run --profile untrusted alpine sh        # 512m, 1 cpu, restricted
brig run --profile dev python:3.12 bash       # 4g, 4 cpus, generous
brig run --network none alpine sh             # fully airgapped
```

## 5. Manage Secrets

```bash
brig secrets add api-key                      # interactive prompt
brig secrets list                             # see mount paths

brig run --secret api-key alpine cat /run/secrets/api-key
```

Secrets are mounted as read-only files at `/run/secrets/<name>`.
An env var `<NAME>_FILE` points to the path. Values never appear in
env vars, process listings, or container inspect output.

## 6. Copy Files

```bash
# Export from cell (applies quarantine + extension blocking)
brig cell cp my-cell:/work/output.json ./output.json

# Import into cell
brig cell cp ./input.txt my-cell:/work/input.txt
```

## 7. Edit Policy

```bash
brig policy show my-cell                       # view a cell's policy
brig policy set my-cell --allow '*.example.com'  # extend allowlist
brig policy set my-cell --deny evil.com          # extend denylist
brig policy test my-cell api.github.com          # simulate a request
```

Policy lives per-cell. For shared defaults across many cells, declare
them in a trust profile and reference it from the cell yaml's
`profile:` field.

## 8. Shutdown

```bash
brig system down                     # stop all cells + warden
brig system down --vm                # also stop the VM
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "limactl not found" | `brew install lima` |
| "Brig VM is not running" | `brig system up` |
| "Warden proxy is not running" | `brig system up` |
| "Rate limit exceeded" | Wait 60 seconds |
| Cell can't reach the internet | Check `brig policy show` — domain must be in allowlist |

## Next Steps

- [Cell Definition Reference](../design/cell-definition.md) — YAML format for cell definitions
- [Concepts](concepts.md) — how the security model works
- [Workflows](workflows.md) — common use cases
