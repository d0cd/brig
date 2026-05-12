# Quick Start

Get Brig running in under 5 minutes.

## Prerequisites

- macOS (Apple Silicon or Intel)
- Python 3.10+
- [Lima](https://lima-vm.io/): `brew install lima`

## 1. Install and Start

```bash
git clone https://github.com/d0cd/brig.git
cd brig
make install
make up
```

`make up` handles everything: initializes `~/.brig`, creates the Lima VM,
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
brig run --name my-cell -d python:3.12 python -c "
import urllib.request
print(urllib.request.urlopen('https://pypi.org').status)
"
```

Check it:

```bash
brig list                     # see all cells
brig logs my-cell             # view output
brig files my-cell            # list workspace
brig exec my-cell -- whoami   # run command inside
brig stop my-cell             # stop
brig rm my-cell               # remove
```

## 4. Use Profiles

```bash
brig profiles                 # see available profiles

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
brig cp my-cell:/work/output.json ./output.json

# Import into cell
brig cp ./input.txt my-cell:/work/input.txt
```

## 7. Edit Policy

```bash
brig policy show                              # view global policy
brig policy set global --allow *.example.com  # add to allowlist
brig policy set my-cell --deny evil.com       # per-cell deny
```

## 8. Shutdown

```bash
brig down                     # stop all cells + warden
brig down --vm                # also stop the VM
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "limactl not found" | `brew install lima` |
| "Brig VM is not running" | `brig up` |
| "Warden proxy is not running" | `brig up` |
| "Rate limit exceeded" | Wait 60 seconds |
| Cell can't reach the internet | Check `brig policy show` — domain must be in allowlist |

## Next Steps

- [Cell Definition Reference](../design/cell-definition.md) — YAML format for cell definitions
- [Concepts](concepts.md) — how the security model works
- [Workflows](workflows.md) — common use cases
