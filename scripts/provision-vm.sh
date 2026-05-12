#!/bin/bash
# provision-vm.sh — Ensure the Lima VM has gVisor, crun, and required directories.
#
# Idempotent: safe to run multiple times. Installs missing components
# without touching existing ones.
#
# Usage: ./scripts/provision-vm.sh  (or: make setup calls this automatically)

set -euo pipefail

LIMA_VM="brig"
SHELL_CMD="limactl shell --workdir / $LIMA_VM --"

echo "Provisioning VM '$LIMA_VM'..."

# gVisor (runsc).
if $SHELL_CMD sudo test -x /usr/local/bin/runsc 2>/dev/null; then
    echo "  gVisor: already installed"
else
    echo "  gVisor: installing..."
    $SHELL_CMD sudo bash -c '
        ARCH=$(uname -m)
        [ "$ARCH" = "x86_64" ] && GA=amd64 || GA=arm64
        curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/latest/$GA" \
            -o /usr/local/bin/runsc
        chmod +x /usr/local/bin/runsc
    '
    echo "  gVisor: installed"
fi

# Podman runtime configuration.
if $SHELL_CMD sudo test -f /etc/containers/containers.conf 2>/dev/null; then
    echo "  Podman config: already exists"
else
    echo "  Podman config: setting gVisor as default runtime..."
    $SHELL_CMD sudo bash -c '
        mkdir -p /etc/containers
        cat > /etc/containers/containers.conf << CONF
[engine]
runtime = "runsc"

[engine.runtimes]
runsc = ["/usr/local/bin/runsc"]
crun = ["/usr/bin/crun"]
CONF
    '
    echo "  Podman config: done"
fi

# proxy-external network.
if $SHELL_CMD sudo podman network exists proxy-external 2>/dev/null; then
    echo "  proxy-external network: exists"
else
    echo "  proxy-external network: creating..."
    $SHELL_CMD sudo podman network create proxy-external 2>/dev/null || true
    echo "  proxy-external network: created"
fi

# Required directories.
$SHELL_CMD sudo mkdir -p /var/log/brig/network /var/run/brig/policies 2>/dev/null
echo "  VM directories: ok"

echo "VM provisioned."
