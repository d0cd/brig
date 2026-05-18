#!/bin/bash
# check-gvisor-pin.sh — CI guard for A2 (audit deficiency #2).
#
# Asserts:
#   1. scripts/provision-vm.sh and src/brig/vm/lima.yaml.template declare
#      the same GVISOR_RELEASE and the same SHA512 map.
#   2. Neither file still contains the REPLACE_WITH_* placeholder.
#   3. (Optional, --fetch) The pinned sha512 actually matches what
#      storage.googleapis.com serves today for that release. Drift fails CI.
#
# Usage:
#   ./scripts/check-gvisor-pin.sh           # offline check (files only)
#   ./scripts/check-gvisor-pin.sh --fetch   # also re-fetch + compare

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROVISION="$SCRIPT_DIR/provision-vm.sh"
LIMA_TEMPLATE="$REPO_ROOT/src/brig/vm/lima.yaml.template"

FETCH=0
if [[ "${1:-}" == "--fetch" ]]; then
    FETCH=1
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

extract_release() {
    awk -F'"' '/^[[:space:]]*GVISOR_RELEASE=/{print $2; exit}' "$1"
}

extract_sha() {
    local file="$1"
    local arch="$2"
    awk -F'"' "/\\[${arch}\\]=/{print \$2; exit}" "$file"
}

PROVISION_RELEASE=$(extract_release "$PROVISION")
LIMA_RELEASE=$(extract_release "$LIMA_TEMPLATE")
[[ -n "$PROVISION_RELEASE" ]] || fail "could not extract GVISOR_RELEASE from $PROVISION"
[[ -n "$LIMA_RELEASE" ]] || fail "could not extract GVISOR_RELEASE from $LIMA_TEMPLATE"
[[ "$PROVISION_RELEASE" == "$LIMA_RELEASE" ]] || \
    fail "GVISOR_RELEASE mismatch: $PROVISION has $PROVISION_RELEASE, $LIMA_TEMPLATE has $LIMA_RELEASE"

for arch in aarch64 x86_64; do
    P=$(extract_sha "$PROVISION" "$arch")
    L=$(extract_sha "$LIMA_TEMPLATE" "$arch")
    [[ -n "$P" ]] || fail "could not extract [$arch] sha512 from $PROVISION"
    [[ -n "$L" ]] || fail "could not extract [$arch] sha512 from $LIMA_TEMPLATE"
    [[ "$P" == "$L" ]] || \
        fail "[$arch] sha512 mismatch:\n  $PROVISION: $P\n  $LIMA_TEMPLATE: $L"
    [[ "$P" != REPLACE_WITH_* ]] || \
        fail "[$arch] sha512 is still a placeholder. Run ./scripts/pin-gvisor.sh"
done

echo "OK: provision-vm.sh and lima.yaml.template agree on gVisor pin"
echo "  release: $PROVISION_RELEASE"

if [[ "$FETCH" == "1" ]]; then
    for arch in aarch64 x86_64; do
        UPSTREAM_URL="https://storage.googleapis.com/gvisor/releases/release/${PROVISION_RELEASE}/${arch}/runsc.sha512"
        UPSTREAM=$(curl -fsSL "$UPSTREAM_URL" | awk '{print $1}')
        PINNED=$(extract_sha "$PROVISION" "$arch")
        if [[ "$UPSTREAM" != "$PINNED" ]]; then
            fail "[$arch] pinned sha drifted from upstream\n  pinned:   $PINNED\n  upstream: $UPSTREAM"
        fi
        echo "  [$arch] sha matches upstream"
    done
fi
