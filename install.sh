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
#   2. Install dependencies using uv (preferred) or pip
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

    # Check Python version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ "$(echo "$python_version < 3.10" | bc -l 2>/dev/null || echo "0")" == "1" ]]; then
        # bc might not be available, try Python comparison
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
            :
        else
            error "Python 3.10+ is required, found Python $python_version"
            exit 1
        fi
    fi
}

# Install or update uv if possible
setup_uv() {
    if command -v uv &> /dev/null; then
        info "uv is already installed"
        return 0
    fi

    # Try to install uv
    if command -v curl &> /dev/null; then
        info "Installing uv package manager..."
        curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null || true

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

    warn "Could not install uv, falling back to pip"
    return 1
}

# Clone or update the repository
setup_repo() {
    if [[ -d "${INSTALL_DIR}/${REPO_NAME}" ]]; then
        info "Updating existing installation..."
        cd "${INSTALL_DIR}/${REPO_NAME}"
        git pull --quiet origin main 2>/dev/null || git pull --quiet 2>/dev/null || true
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

    if command -v uv &> /dev/null; then
        info "Installing dependencies with uv..."
        uv sync --quiet 2>/dev/null || uv pip install --quiet -r requirements.txt

        info "Starting EDOT Discovery Tool..."
        echo ""
        uv run python discover.py
    else
        info "Installing dependencies with pip..."

        # Check if we're in CloudShell (has --user requirement)
        if [[ -n "${AWS_EXECUTION_ENV:-}" ]] || [[ -d "/home/cloudshell-user" ]]; then
            pip install --user --quiet -r requirements.txt
        else
            # Try virtual environment first
            if [[ ! -d ".venv" ]]; then
                python3 -m venv .venv 2>/dev/null || true
            fi

            if [[ -f ".venv/bin/activate" ]]; then
                source .venv/bin/activate
                pip install --quiet -r requirements.txt
            else
                pip install --user --quiet -r requirements.txt
            fi
        fi

        info "Starting EDOT Discovery Tool..."
        echo ""
        python3 discover.py
    fi
}

main() {
    echo ""
    echo "=========================================="
    echo " EDOT Cloud Forwarder Discovery Tool"
    echo "=========================================="
    echo ""

    check_requirements
    setup_uv || true
    setup_repo
    install_and_run
}

main "$@"
