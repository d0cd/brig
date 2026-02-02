#!/bin/bash
# Brig Installation Script
# Installs brig CLI and initializes the environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check we're on macOS
check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "Brig is designed for macOS. Detected: $(uname)"
        exit 1
    fi
    log_info "Detected macOS $(sw_vers -productVersion)"
}

# Check Python version
check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        log_info "Install with: brew install python3"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    REQUIRED_VERSION="3.9"

    if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
        log_error "Python 3.9+ is required. Found: Python $PYTHON_VERSION"
        exit 1
    fi
    log_info "Found Python $PYTHON_VERSION"
}

# Check Lima
check_lima() {
    if ! command -v limactl &> /dev/null; then
        log_warn "Lima is not installed"
        log_info "Install with: brew install lima"
        LIMA_MISSING=1
    else
        LIMA_VERSION=$(limactl --version | head -1 | awk '{print $3}')
        log_info "Found Lima $LIMA_VERSION"
        LIMA_MISSING=0
    fi
}

# Check Podman (will be inside VM, but check host for local debugging)
check_podman() {
    if command -v podman &> /dev/null; then
        PODMAN_VERSION=$(podman --version | awk '{print $3}')
        log_info "Found Podman $PODMAN_VERSION (optional on host)"
    fi
}

# Install brig CLI
install_brig() {
    log_info "Installing brig CLI..."

    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Install in development mode or regular mode
    if [[ "$1" == "--dev" ]]; then
        log_info "Installing in development mode..."
        pip3 install -e "$SCRIPT_DIR" --quiet
    else
        log_info "Installing brig..."
        pip3 install "$SCRIPT_DIR" --quiet
    fi

    # Verify installation
    if command -v brig &> /dev/null; then
        log_info "brig installed successfully"
        brig --help | head -5
    else
        log_warn "brig not found in PATH. You may need to add ~/.local/bin to your PATH:"
        log_info "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
}

# Initialize brig
init_brig() {
    log_info "Initializing brig..."

    # Check if already initialized
    if [[ -d "$HOME/.brig" ]] && [[ -f "$HOME/.brig/lima.yaml" ]]; then
        log_info "Brig already initialized at ~/.brig"
        return 0
    fi

    # Run brig init
    if command -v brig &> /dev/null; then
        brig init
    else
        python3 "$(dirname "${BASH_SOURCE[0]}")/src/brig.py" init
    fi
}

# Print next steps
print_next_steps() {
    echo ""
    echo "=========================================="
    echo "Brig installation complete!"
    echo "=========================================="
    echo ""

    if [[ "$LIMA_MISSING" == "1" ]]; then
        echo "Next steps:"
        echo "  1. Install Lima:"
        echo "       brew install lima"
        echo ""
        echo "  2. Create the brig VM:"
        echo "       limactl create --name=brig ~/.brig/lima.yaml"
        echo ""
        echo "  3. Start the VM:"
        echo "       limactl start brig"
        echo ""
    else
        echo "Next steps:"
        echo "  1. Create the brig VM:"
        echo "       limactl create --name=brig ~/.brig/lima.yaml"
        echo ""
        echo "  2. Start the VM:"
        echo "       limactl start brig"
        echo ""
    fi

    echo "  3. Start the warden proxy (inside VM):"
    echo "       limactl shell brig -- warden start"
    echo ""
    echo "  4. Run your first cell:"
    echo "       brig run --name test --image alpine -- echo 'Hello from brig!'"
    echo ""
    echo "Documentation: https://github.com/d0cd/brig/tree/main/docs"
    echo ""
}

# Main
main() {
    echo "========================================"
    echo "Brig Installation"
    echo "========================================"
    echo ""

    check_macos
    check_python
    check_lima
    check_podman

    echo ""

    # Parse arguments
    DEV_MODE=""
    SKIP_INIT=""
    for arg in "$@"; do
        case $arg in
            --dev)
                DEV_MODE="--dev"
                ;;
            --skip-init)
                SKIP_INIT="1"
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --dev        Install in development mode (editable)"
                echo "  --skip-init  Skip running 'brig init'"
                echo "  --help       Show this help message"
                exit 0
                ;;
        esac
    done

    install_brig $DEV_MODE

    if [[ -z "$SKIP_INIT" ]]; then
        echo ""
        init_brig
    fi

    print_next_steps
}

main "$@"
