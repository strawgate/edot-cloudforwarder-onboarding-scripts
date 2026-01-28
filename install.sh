#!/usr/bin/env bash
#
# EDOT Cloud Forwarder - AWS Log Source Discovery Tool
# One-line installer for AWS CloudShell and local environments
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/elastic/edot-cloudforwarder-onboarding-scripts/main/install.sh | bash
#
# This script will:
#   1. Clone the repository (or update if exists)
#   2. Install dependencies using uv
#   3. Run the discovery tool
#

set -euo pipefail

# Configuration
REPO_URL="https://github.com/elastic/edot-cloudforwarder-onboarding-scripts.git"
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

    if ! command -v python3 &> /dev/null; then
        error "python3 is required but not installed"
        exit 1
    fi

    # Check Python version using Python itself (simplest and most reliable)
    local python_version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"; then
        error "Python 3.10+ is required, found Python ${python_version}"
        exit 1
    fi
}

# Install or update uv
setup_uv() {
    if command -v uv &> /dev/null; then
        info "uv is already installed"
        return 0
    fi

    # Try to install uv
    if command -v curl &> /dev/null; then
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

# Install dependencies and run
install_and_run() {
    cd "${INSTALL_DIR}/${REPO_NAME}"

    info "Installing dependencies with uv..."
    uv sync --quiet 2>/dev/null || uv pip install --quiet -r requirements.txt

    info "Starting EDOT Discovery Tool..."
    echo ""
    uv run python discover.py
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
    install_and_run
}

main "$@"
