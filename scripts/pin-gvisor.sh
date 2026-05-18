#!/bin/bash
# pin-gvisor.sh — fetch official gVisor sha512s and pin them into
# scripts/provision-vm.sh. Run this once per gVisor version bump.
#
# Usage:
#   ./scripts/pin-gvisor.sh [RELEASE]      # default: current GVISOR_RELEASE
#   ./scripts/pin-gvisor.sh 20251015
#
# What it does:
#   1. Reads GVISOR_RELEASE from provision-vm.sh (or takes from $1)
#   2. Fetches runsc.sha512 for aarch64 and x86_64 from the official
#      storage.googleapis.com release bucket
#   3. Rewrites the GVISOR_SHA512_BY_ARCH map in provision-vm.sh
#   4. Prints a diff for you to review and commit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROVISION="$SCRIPT_DIR/provision-vm.sh"
LIMA_TEMPLATE="$REPO_ROOT/src/brig/vm/lima.yaml.template"

# Both files carry the same GVISOR_RELEASE + SHA512 map. Keep them in sync.
TARGETS=("$PROVISION" "$LIMA_TEMPLATE")

for target in "${TARGETS[@]}"; do
    if [[ ! -f "$target" ]]; then
        echo "ERROR: $target not found" >&2
        exit 1
    fi
done

if [[ $# -ge 1 ]]; then
    RELEASE="$1"
else
    RELEASE=$(awk -F'"' '/^GVISOR_RELEASE=/{print $2}' "$PROVISION")
fi

if [[ -z "$RELEASE" ]]; then
    echo "ERROR: could not determine GVISOR_RELEASE — pass one as \$1" >&2
    exit 1
fi

echo "Pinning gVisor release: $RELEASE"

fetch_sha() {
    local arch="$1"
    local url="https://storage.googleapis.com/gvisor/releases/release/${RELEASE}/${arch}/runsc.sha512"
    # The published .sha512 file is of the form: "<sha>  runsc"
    # Strip the filename portion and trim whitespace.
    curl -fsSL "$url" | awk '{print $1}'
}

SHA_AARCH64=$(fetch_sha aarch64)
SHA_X86_64=$(fetch_sha x86_64)

echo "  aarch64: $SHA_AARCH64"
echo "  x86_64:  $SHA_X86_64"

# In-place rewrite of GVISOR_RELEASE + the SHA512 map in every target.
# Matches lines individually instead of trying to rewrite a multi-line array,
# so it works whether the array is indented (in lima.yaml.template) or not
# (in scripts/provision-vm.sh).
update_file() {
    local target="$1"
    local tmp
    tmp=$(mktemp)
    sed -E "s|^([[:space:]]*)GVISOR_RELEASE=\"[^\"]*\"|\\1GVISOR_RELEASE=\"${RELEASE}\"|" "$target" \
      | sed -E "s|^([[:space:]]*\\[aarch64\\]=\")[^\"]*\"|\\1${SHA_AARCH64}\"|" \
      | sed -E "s|^([[:space:]]*\\[x86_64\\]=\")[^\"]*\"|\\1${SHA_X86_64}\"|" \
      > "$tmp"

    if ! diff -u "$target" "$tmp" > /dev/null; then
        mv "$tmp" "$target"
        echo "  updated $target"
    else
        rm -f "$tmp"
        echo "  no change to $target"
    fi
}

for target in "${TARGETS[@]}"; do
    update_file "$target"
done

echo ""
echo "Review the diffs and commit. Both files must stay in sync (CI checks this)."
