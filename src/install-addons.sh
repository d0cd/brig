#!/bin/bash
# install-addons.sh - Deploy Warden addons to ~/.brig/cells/addons/
#
# Copies mitmproxy addons from src/addons/ to the location expected by
# the Lima VM mount (~/.brig/cells/addons/ -> /cells/addons/).
#
# Usage:
#   ./src/install-addons.sh
#
# Prerequisites:
#   - ~/.brig directory structure exists (created by lima.yaml provisioning)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_ADDONS="$SCRIPT_DIR/addons"
DEST_ADDONS="$HOME/.brig/cells/addons"
DEST_CONFIG="$HOME/.brig/cells"

# Colors for output.
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_ok() { echo -e "${GREEN}OK${NC}: $1"; }
log_err() { echo -e "${RED}ERROR${NC}: $1" >&2; }

# Check source exists.
if [ ! -d "$SRC_ADDONS" ]; then
    log_err "Source addons directory not found: $SRC_ADDONS"
    exit 1
fi

# Create destination directories.
mkdir -p "$DEST_ADDONS"
mkdir -p "$HOME/.brig/secrets"
mkdir -p "$HOME/.brig/state/system"

# Copy addons.
echo "Installing addons to $DEST_ADDONS..."
for addon in "$SRC_ADDONS"/*.py; do
    if [ -f "$addon" ]; then
        name=$(basename "$addon")
        cp "$addon" "$DEST_ADDONS/$name"
        log_ok "Installed $name"
    fi
done

# Copy example policy if no policy exists.
if [ ! -f "$DEST_CONFIG/network-policy.json" ]; then
    if [ -f "$SCRIPT_DIR/config/network-policy.example.json" ]; then
        cp "$SCRIPT_DIR/config/network-policy.example.json" "$DEST_CONFIG/network-policy.json"
        log_ok "Installed example network-policy.json"
    fi
else
    echo "Skipping network-policy.json (already exists)"
fi

# Copy logrotate config.
if [ -f "$SCRIPT_DIR/config/brig-logrotate.conf" ]; then
    cp "$SCRIPT_DIR/config/brig-logrotate.conf" "$DEST_CONFIG/"
    log_ok "Installed brig-logrotate.conf"
fi

echo ""
echo "Installation complete. Files installed to:"
echo "  $DEST_ADDONS/"
ls -la "$DEST_ADDONS/"

echo ""
echo "Next steps:"
echo "  1. Start/restart the VM: limactl start cell"
echo "  2. Restart warden: limactl shell cell -- sudo warden restart"
echo "  3. Verify: limactl shell cell -- sudo warden health"
