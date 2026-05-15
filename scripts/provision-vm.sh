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

# Pinned gVisor release. Fetching latest + the latest sha512 from the same
# TLS endpoint detects corruption but not authenticity — an attacker who
# controls the bucket gets persistent gVisor compromise inside the VM, and
# gVisor is the runtime that enforces invariant 5. Pinning means upgrades
# are explicit and the checksum below has to be reviewed in code review.
#
# To bump: pick a release from https://github.com/google/gvisor/releases,
# fetch its sha512 from the release page, update both lines below, and
# verify locally before merging:
#   curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RELEASE}/${ARCH}/runsc.sha512" \
#       | sha512sum -c
GVISOR_RELEASE="20251015"
declare -A GVISOR_SHA512_BY_ARCH=(
    [aarch64]="REPLACE_WITH_ARM64_SHA512_FROM_RELEASE_PAGE"
    [x86_64]="REPLACE_WITH_AMD64_SHA512_FROM_RELEASE_PAGE"
)

echo "Provisioning VM '$LIMA_VM'..."

# gVisor (runsc) — pinned release, sha512 verified against in-script constant.
if $SHELL_CMD sudo test -x /usr/local/bin/runsc 2>/dev/null; then
    echo "  gVisor: already installed"
else
    echo "  gVisor: installing release ${GVISOR_RELEASE}..."
    HOST_ARCH=$($SHELL_CMD uname -m | tr -d '\r')
    EXPECTED_SHA="${GVISOR_SHA512_BY_ARCH[$HOST_ARCH]:-}"
    if [[ -z "$EXPECTED_SHA" || "$EXPECTED_SHA" == REPLACE_WITH_* ]]; then
        echo "  gVisor: ERROR — no pinned sha512 for arch '$HOST_ARCH'." >&2
        echo "    Update GVISOR_SHA512_BY_ARCH in $0 with the value from" >&2
        echo "    https://github.com/google/gvisor/releases/tag/release-${GVISOR_RELEASE}" >&2
        exit 1
    fi
    $SHELL_CMD sudo bash -c "
        set -e
        ARCH=\$(uname -m)
        URL=\"https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/\${ARCH}/runsc\"
        curl -fsSL \"\$URL\" -o /usr/local/bin/runsc.new
        ACTUAL=\$(sha512sum /usr/local/bin/runsc.new | awk '{print \$1}')
        EXPECTED='${EXPECTED_SHA}'
        if [[ \"\$ACTUAL\" != \"\$EXPECTED\" ]]; then
            echo \"  gVisor: sha512 MISMATCH (got \$ACTUAL, expected \$EXPECTED)\" >&2
            rm -f /usr/local/bin/runsc.new
            exit 1
        fi
        mv /usr/local/bin/runsc.new /usr/local/bin/runsc
        chmod +x /usr/local/bin/runsc
    "
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
    # Restart podman so it picks up the new runtime config.
    $SHELL_CMD sudo systemctl restart podman 2>/dev/null || true
    echo "  Podman config: done (restarted)"
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
