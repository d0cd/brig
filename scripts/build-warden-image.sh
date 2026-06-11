#!/bin/bash
# build-warden-image.sh — build the warden image inside the brig VM and
# pin its sha256 in src/warden/proxy.py:WARDEN_IMAGE_DIGEST.
#
# Run this when WARDEN_IMAGE_TAG or the OTel SDK version changes.
# Operator commits the resulting one-line digest update.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKERFILE="$REPO_ROOT/src/warden/image/Dockerfile"
PROXY_PY="$REPO_ROOT/src/warden/proxy.py"

if [[ ! -f "$DOCKERFILE" ]]; then
    echo "ERROR: $DOCKERFILE not found" >&2
    exit 1
fi

TAG=$(awk -F'"' '/^WARDEN_IMAGE_TAG/{print $2}' "$PROXY_PY")
if [[ -z "$TAG" ]]; then
    echo "ERROR: could not read WARDEN_IMAGE_TAG from $PROXY_PY" >&2
    exit 1
fi

IMAGE="localhost/brig-warden:$TAG"

# Stage the Dockerfile into ~/.brig/cells/ so it's visible inside the
# VM via the /cells virtiofs mount. The project tree itself isn't
# mounted; cells/ is.
STAGE="$HOME/.brig/cells/warden-image"
mkdir -p "$STAGE"
cp "$DOCKERFILE" "$STAGE/Dockerfile"

echo "Building $IMAGE inside brig VM..."
# Use crun for the build itself — gVisor's runsc doesn't cooperate
# with buildah's cgroup setup. The built image is unaffected.
limactl shell brig -- sudo podman build --runtime=crun -t "$IMAGE" /cells/warden-image

DIGEST=$(limactl shell brig -- sudo podman inspect "$IMAGE" \
    --format '{{.Id}}' | tr -d '\r\n')

if [[ -z "$DIGEST" ]]; then
    echo "ERROR: could not extract image id" >&2
    exit 1
fi
# podman returns the digest as a bare hex string; prepend sha256:
if [[ "$DIGEST" != sha256:* ]]; then
    DIGEST="sha256:$DIGEST"
fi

echo "Built digest: $DIGEST"

TMP=$(mktemp)
awk -v d="$DIGEST" '
    /^WARDEN_IMAGE_DIGEST = / {
        print "WARDEN_IMAGE_DIGEST = \"" d "\""
        next
    }
    { print }
' "$PROXY_PY" > "$TMP"
mv "$TMP" "$PROXY_PY"

echo "Updated WARDEN_IMAGE_DIGEST in $PROXY_PY"
echo ""
git -C "$REPO_ROOT" diff -- "$PROXY_PY"
