#!/bin/bash
# pin-collector-image.sh — fetch the OTel collector image, compute its
# sha256, and update COLLECTOR_IMAGE_DIGEST in src/brig/config.py.
#
# brig refuses to start the collector while COLLECTOR_IMAGE_DIGEST is
# empty (fail closed; no unverified pulls). Run this once per
# collector version bump.
#
# Usage:
#   ./scripts/pin-collector-image.sh [TAG]    # default: COLLECTOR_IMAGE_TAG from config.py
#   ./scripts/pin-collector-image.sh 0.96.0
#
# Prerequisites:
#   - lima VM 'brig' running with podman
#   - write access to src/brig/config.py

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="$REPO_ROOT/src/brig/config.py"

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: $CONFIG not found" >&2
    exit 1
fi

if [[ $# -ge 1 ]]; then
    TAG="$1"
else
    TAG=$(awk -F'"' '/^COLLECTOR_IMAGE_TAG/{print $2}' "$CONFIG")
fi

REPO=$(awk -F'"' '/^COLLECTOR_IMAGE_REPO/{print $2}' "$CONFIG")
if [[ -z "$REPO" || -z "$TAG" ]]; then
    echo "ERROR: could not read COLLECTOR_IMAGE_REPO / COLLECTOR_IMAGE_TAG from $CONFIG" >&2
    exit 1
fi

echo "Pulling $REPO:$TAG inside the brig VM..."
limactl shell brig -- sudo podman pull "$REPO:$TAG" >/dev/null

DIGEST=$(limactl shell brig -- sudo podman inspect "$REPO:$TAG" \
    --format '{{index .RepoDigests 0}}' | awk -F'@' '{print $2}')

if [[ -z "$DIGEST" || "$DIGEST" != sha256:* ]]; then
    echo "ERROR: could not extract sha256 digest (got: '$DIGEST')" >&2
    exit 1
fi

echo "Pinned digest: $DIGEST"

# Update the COLLECTOR_IMAGE_DIGEST line in config.py.
TMP=$(mktemp)
awk -v d="$DIGEST" '
    /^COLLECTOR_IMAGE_DIGEST = / {
        print "COLLECTOR_IMAGE_DIGEST = \"" d "\""
        next
    }
    { print }
' "$CONFIG" > "$TMP"
mv "$TMP" "$CONFIG"

echo "Updated COLLECTOR_IMAGE_DIGEST in $CONFIG"
echo ""
echo "Review the change:"
git -C "$REPO_ROOT" diff -- "$CONFIG"
