#!/usr/bin/env bash
#
# EDOT Cloud Forwarder - AWS Log Source Discovery Tool
# One-line installer for AWS CloudShell and local environments
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/strawgate/edot-cloudforwarder-onboarding-scripts/main/install.sh | bash
#
# This script will:
#   1. Install uv (if not present)
#   2. Clone the repository (or update if exists)
#   3. Run the discovery tool via uv run (auto-installs dependencies)
#

set -euo pipefail

# Configuration
REPO_URL="https://github.com/strawgate/edot-cloudforwarder-onboarding-scripts.git"
INSTALL_DIR="${HOME}/.edot-discovery"
REPO_NAME="edot-cloudforwarder-onboarding-scripts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check for required commands
check_requirements() {
    if ! command -v git &> /dev/null; then
        error "git is required but not installed"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        exit 1
    fi
}

# Install or update uv
setup_uv() {
    if command -v uv &> /dev/null; then
        info "uv is already installed"
        return 0
    fi

    info "Installing uv package manager..."
    if ! curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null; then
        error "Failed to install uv"
        exit 1
    fi

    # Source the updated PATH
    if [[ -f "${HOME}/.local/bin/uv" ]]; then
        export PATH="${HOME}/.local/bin:${PATH}"
    elif [[ -f "${HOME}/.cargo/bin/uv" ]]; then
        export PATH="${HOME}/.cargo/bin:${PATH}"
    fi

    if command -v uv &> /dev/null; then
        info "uv installed successfully"
        return 0
    fi

    error "Could not install uv package manager"
    exit 1
}

# Clone or update the repository
setup_repo() {
    if [[ -d "${INSTALL_DIR}/${REPO_NAME}" ]]; then
        info "Updating existing installation..."
        cd "${INSTALL_DIR}/${REPO_NAME}"

        # Try to pull updates, warn on failure but continue
        if ! git pull --quiet origin main 2>/dev/null; then
            if ! git pull --quiet 2>/dev/null; then
                warn "Failed to update repository at ${INSTALL_DIR}/${REPO_NAME}"
                warn "You may be running stale code. Consider deleting the directory and re-running."
            fi
        fi
    else
        info "Cloning repository..."
        mkdir -p "${INSTALL_DIR}"
        cd "${INSTALL_DIR}"
        git clone --quiet --depth 1 "${REPO_URL}"
        cd "${REPO_NAME}"
    fi
}

# Run the discovery tool
run_discovery() {
    cd "${INSTALL_DIR}/${REPO_NAME}"

    info "Starting EDOT Discovery Tool..."
    echo ""
    # uv run automatically installs dependencies from pyproject.toml
    # Use </dev/tty to ensure interactive prompts work when piped from curl
    uv run edot-discover </dev/tty
}

main() {
    echo ""
    echo "=========================================="
    echo " EDOT Cloud Forwarder Discovery Tool"
    echo "=========================================="
    echo ""

    check_requirements
    setup_uv
    setup_repo
    run_discovery
}

main "$@"
