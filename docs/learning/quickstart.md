# Quick Start

Get Cell running in 5 minutes.

## Prerequisites

- macOS with Apple Silicon or Intel
- [Lima](https://lima-vm.io/) installed
- Basic familiarity with containers

## 1. Install Lima

```bash
brew install lima
```

## 2. Create the Cell VM

```bash
# Create the Brig VM using the bundled configuration
limactl create --name=cell ~/.brig/lima.yaml
limactl start cell
```

The `lima.yaml` file is created during Cell installation.

## 3. Verify gVisor

```bash
limactl shell cells -- runsc --version
# Should print version info
```

## 4. Run Your First Cell

```bash
# Quick inline run
./cell run --name my-cell --image python:3.11-slim -- python -c "print('Hello from Cell!')"

# Or from a config file
./cell run -f cells/example-cell.yaml
```

## 5. Interact with Cells

```bash
# Watch stdout logs
./cell logs my-cell -f

# Watch network activity
./cell network my-cell -f

# Browse the workspace
./cell files my-cell

# Stop the cell
./cell stop my-cell
```

## 6. View Network Activity

All network requests are logged and attributed to their source cell:

```bash
# Stream network logs
./cell network my-cell -f

# Filter for blocked requests
./cell network my-cell --json | jq 'select(.blocked)'

# Filter for slow requests
./cell network my-cell --json | jq 'select(.ms > 1000)'
```

## 7. Copy Files Out

```bash
# Safe copy with validation
./cell cp my-cell:/work/output.json ./output.json

# Copy with sanitization (blocks dangerous file types)
./cell cp --sanitize my-cell:/work/report.html ./report.html
```

## 8. Cleanup

```bash
# Stop the cell
./cell stop my-cell

# Remove the cell and its network
./cell rm my-cell

# Or remove everything including workspace
./cell rm --purge my-cell
```

## Next Steps

- Read [Concepts](concepts.md) to understand how Cell works
- See [Workflows](workflows.md) for common use cases
- Check [Troubleshooting](troubleshooting.md) if you hit issues

## Quick Reference

| Command | Description |
|---------|-------------|
| `cell run` | Create and start a cell |
| `cell stop` | Stop a cell gracefully |
| `cell kill` | Kill a cell immediately |
| `cell rm` | Remove a cell |
| `cell list` | List all cells |
| `cell logs` | View cell stdout/stderr |
| `cell network` | View network activity |
| `cell files` | List workspace files |
| `cell cp` | Copy files to/from workspace |
| `cell exec` | Run command in cell |
| `cell proxy status` | Check proxy status |
| `cell diagnose` | Debug connectivity issues |
