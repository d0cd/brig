# Quick Start

Get Brig running in 5 minutes.

## Prerequisites

- macOS with Apple Silicon or Intel
- [Lima](https://lima-vm.io/) installed
- Basic familiarity with containers

## 1. Install Lima

```bash
brew install lima
```

## 2. Create the Brig VM

```bash
# Create the Brig VM using the bundled configuration
limactl create --name=brig ~/.brig/lima.yaml
limactl start brig
```

The `lima.yaml` file is created during Brig installation.

## 3. Verify gVisor

```bash
limactl shell brig -- runsc --version
# Should print version info
```

## 4. Run Your First Cell

```bash
# Quick inline run
brig run --name my-cell --image python:3.11-slim -- python -c "print('Hello from Brig!')"

# Or from a config file
brig run -f cells/example-cell.yaml
```

## 5. Interact with Cells

```bash
# Watch stdout logs
brig logs my-cell -f

# Watch network activity
brig network my-cell -f

# Browse the workspace
brig files my-cell

# Stop the cell
brig stop my-cell
```

## 6. View Network Activity

All network requests are logged and attributed to their source cell:

```bash
# Stream network logs
brig network my-cell -f

# Filter for blocked requests
brig network my-cell --json | jq 'select(.blocked)'

# Filter for slow requests
brig network my-cell --json | jq 'select(.ms > 1000)'
```

## 7. Copy Files Out

```bash
# Safe copy with validation
brig cp my-cell:/work/output.json ./output.json

# Copy with sanitization (blocks dangerous file types)
brig cp --sanitize my-cell:/work/report.html ./report.html
```

## 8. Cleanup

```bash
# Stop the cell
brig stop my-cell

# Remove the cell and its network
brig rm my-cell

# Or remove everything including workspace
brig rm --purge my-cell
```

## Next Steps

- Read [Concepts](concepts.md) to understand how Brig works
- See [Workflows](workflows.md) for common use cases
- Check [Troubleshooting](troubleshooting.md) if you hit issues

## Quick Reference

| Command | Description |
|---------|-------------|
| `brig run` | Create and start a cell |
| `brig stop` | Stop a cell gracefully |
| `brig kill` | Kill a cell immediately |
| `brig rm` | Remove a cell |
| `brig list` | List all cells |
| `brig logs` | View cell stdout/stderr |
| `brig network` | View network activity |
| `brig files` | List workspace files |
| `brig cp` | Copy files to/from workspace |
| `brig exec` | Run command in cell |
| `warden status` | Check proxy status |
| `brig diagnose` | Debug connectivity issues |
