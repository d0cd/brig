# Brig Installation Guide

## Prerequisites

- **macOS** (required - Brig uses Lima VM which runs on macOS)
- **Python 3.10+** (usually pre-installed on macOS)
- **Lima** (virtual machine manager)

### Install Lima

```bash
brew install lima
```

## Quick Install

```bash
# Clone the repository
git clone https://github.com/d0cd/brig.git
cd brig

# Run the installer
./install.sh
```

The installer will:
1. Check prerequisites
2. Install the brig CLI
3. Initialize `~/.brig` directory structure

## Manual Installation

If you prefer to install manually:

```bash
# Install the CLI
pip3 install .

# Initialize the environment
brig init
```

## VM Setup

After installation, create and start the Lima VM:

```bash
# Create the VM (one-time setup)
limactl create --name=brig ~/.brig/lima.yaml

# Start the VM
limactl start brig
```

## Start Warden

Before running cells, start the Warden proxy inside the VM:

```bash
limactl shell brig -- warden start
```

To start Warden in the background:

```bash
limactl shell brig -- warden start --detach
```

## Verify Installation

```bash
# Check brig CLI
brig --help

# Check VM status
limactl list

# Check warden status (inside VM)
limactl shell brig -- warden status
```

## Run Your First Cell

```bash
brig run --name test --image alpine -- echo "Hello from brig!"
```

## Directory Structure

After initialization, `~/.brig` contains:

```
~/.brig/
├── lima.yaml           # VM configuration
├── network-policy.json # Default network policy
├── cells/              # Cell definitions
│   └── addons/         # Warden mitmproxy addons
├── secrets/            # Secret files (one per secret)
└── state/              # Runtime state
    └── system/         # System logs and allocator state
```

## Troubleshooting

### "brig not found" after installation

Add Python user bin to your PATH:

```bash
export PATH="$HOME/Library/Python/3.10/bin:$PATH"
```

Add this line to your `~/.zshrc` or `~/.bashrc` for persistence.

### Lima VM fails to start

Check Lima status and logs:

```bash
limactl list
limactl shell brig -- journalctl -f
```

### Warden fails to start

Ensure mitmproxy is installed inside the VM:

```bash
limactl shell brig -- pip3 install mitmproxy
```

Check warden logs:

```bash
limactl shell brig -- warden logs show
```

### Permission denied errors

Ensure the install script is executable:

```bash
chmod +x install.sh
```

## Development Installation

For development (editable install):

```bash
./install.sh --dev
```

This installs brig in editable mode so changes to the source are reflected immediately.

## Uninstallation

```bash
# Remove the CLI
pip3 uninstall brig

# Remove the VM (optional)
limactl stop brig
limactl delete brig

# Remove configuration (optional)
rm -rf ~/.brig
```
