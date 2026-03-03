#!/bin/bash
#
# SecureOpenClaw Installation Script
#
# This script sets up the MACAW Trust Layer for SecureOpenClaw.
# It guides you through downloading and installing the MACAW client.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACAW_LIB_DIR="$SCRIPT_DIR/macaw_lib"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              SecureOpenClaw Installation${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}▶${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not found."
        echo "   Please install Python 3.9 or later."
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    print_success "Python $PYTHON_VERSION found"

    # Check pip
    if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
        print_error "pip is required but not found."
        exit 1
    fi
    print_success "pip found"

    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is required but not found."
        exit 1
    fi
    print_success "Node.js found"
}

# Check if already installed
check_existing_installation() {
    if [ -f "$MACAW_LIB_DIR/.macaw/config.json" ]; then
        echo ""
        print_warning "MACAW is already installed in macaw_lib/"
        echo ""
        read -p "   Reinstall? This will overwrite existing configuration. (y/N): " response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo ""
            echo "Installation cancelled. Run ./openclaw to start."
            exit 0
        fi
        echo ""
    fi
}

# Guide user to download
guide_download() {
    print_step "MACAW Trust Layer Setup"
    echo ""
    echo "   SecureOpenClaw requires a free MACAW account for policy enforcement."
    echo ""
    echo "   1. Register at console.macawsecurity.ai (free)"
    echo "   2. Download your MACAW client package"
    echo "      - Select your OS (macOS/Linux/Windows)"
    echo "      - Select your Python version ($PYTHON_VERSION)"
    echo ""

    # Try to open browser
    if command -v open &> /dev/null; then
        read -p "   Press Enter to open console.macawsecurity.ai in your browser..."
        open "https://console.macawsecurity.ai" 2>/dev/null || true
    elif command -v xdg-open &> /dev/null; then
        read -p "   Press Enter to open console.macawsecurity.ai in your browser..."
        xdg-open "https://console.macawsecurity.ai" 2>/dev/null || true
    else
        echo "   Please visit: https://console.macawsecurity.ai"
    fi

    echo ""
    echo "   After downloading, enter the path to your zip file below."
    echo "   (You can drag & drop the file into this terminal)"
    echo ""
}

# Get zip file path from user
get_zip_path() {
    while true; do
        read -p "   Path to downloaded zip: " ZIP_PATH

        # Clean up path (remove quotes, trailing spaces, handle drag & drop escaping)
        ZIP_PATH=$(echo "$ZIP_PATH" | tr -d "'\"\\" | xargs)

        if [ -z "$ZIP_PATH" ]; then
            print_error "No path provided. Please enter the path to your downloaded zip."
            continue
        fi

        if [ ! -f "$ZIP_PATH" ]; then
            print_error "File not found: $ZIP_PATH"
            continue
        fi

        if [[ ! "$ZIP_PATH" == *.zip ]]; then
            print_error "File must be a .zip file"
            continue
        fi

        break
    done
}

# Extract and install
install_macaw() {
    print_step "Installing MACAW..."

    # Create macaw_lib directory
    mkdir -p "$MACAW_LIB_DIR"

    # Extract zip
    echo "   Extracting package..."
    unzip -q -o "$ZIP_PATH" -d "$MACAW_LIB_DIR"

    # Handle nested directory (zip creates macaw-client-distro-0.6.x-.../ folder)
    # Find any macaw-* subdirectory and flatten it
    NESTED=$(find "$MACAW_LIB_DIR" -maxdepth 1 -type d -name "macaw-*" | head -1)
    if [ -n "$NESTED" ] && [ "$NESTED" != "$MACAW_LIB_DIR" ]; then
        echo "   Flattening nested directory: $(basename "$NESTED")"
        # Move contents up, handling hidden files (.macaw directory)
        shopt -s dotglob
        for item in "$NESTED"/*; do
            if [ -e "$item" ]; then
                mv -f "$item" "$MACAW_LIB_DIR"/ 2>/dev/null || true
            fi
        done
        shopt -u dotglob
        rmdir "$NESTED" 2>/dev/null || rm -rf "$NESTED" 2>/dev/null || true
    fi

    # Verify extraction
    if [ ! -f "$MACAW_LIB_DIR/.macaw/config.json" ]; then
        # Check if config is elsewhere
        CONFIG_FILE=$(find "$MACAW_LIB_DIR" -name "config.json" -path "*/.macaw/*" | head -1)
        if [ -z "$CONFIG_FILE" ]; then
            print_error "config.json not found in package. Invalid MACAW package?"
            exit 1
        fi
    fi
    print_success "Package extracted"

    # Find and install wheel
    WHEEL=$(find "$MACAW_LIB_DIR" -name "macaw_client*.whl" | head -1)
    if [ -z "$WHEEL" ]; then
        print_error "macaw_client wheel not found in package"
        exit 1
    fi

    echo "   Installing macaw_client..."
    pip3 install --quiet "$WHEEL"
    print_success "macaw_client installed"

    # Install sidecar dependencies
    echo "   Installing sidecar dependencies..."
    pip3 install --quiet httpx pydantic uvicorn fastapi
    print_success "Sidecar dependencies installed"

    # Verify import works
    echo "   Verifying installation..."
    if python3 -c "from macaw_client import MACAWClient" 2>/dev/null; then
        print_success "MACAW client verified"
    else
        print_warning "Could not verify MACAW client import (may still work)"
    fi

    # Create nested .gitignore for safety
    cat > "$MACAW_LIB_DIR/.gitignore" << 'EOF'
# SECURITY: This directory contains API keys - NEVER commit these files
*
!.gitignore
EOF
    print_success "Security gitignore created"
}

# Install pre-commit hook
install_precommit_hook() {
    print_step "Installing pre-commit hook..."

    GIT_DIR="$SCRIPT_DIR/.git"
    HOOKS_DIR="$GIT_DIR/hooks"

    if [ ! -d "$GIT_DIR" ]; then
        print_warning "Not a git repository, skipping pre-commit hook"
        return
    fi

    mkdir -p "$HOOKS_DIR"

    # Create or append to pre-commit hook
    HOOK_FILE="$HOOKS_DIR/pre-commit"
    HOOK_MARKER="# MACAW_LIB_PROTECTION"

    if [ -f "$HOOK_FILE" ] && grep -q "$HOOK_MARKER" "$HOOK_FILE"; then
        print_success "Pre-commit hook already installed"
        return
    fi

    cat >> "$HOOK_FILE" << 'EOF'

# MACAW_LIB_PROTECTION - Prevent accidental commit of API keys
if git diff --cached --name-only | grep -q "^macaw_lib/"; then
    echo ""
    echo "ERROR: Attempting to commit files in macaw_lib/"
    echo ""
    echo "This directory contains API keys and must NEVER be committed."
    echo "Remove these files from staging with:"
    echo "  git reset HEAD macaw_lib/"
    echo ""
    exit 1
fi
EOF

    chmod +x "$HOOK_FILE"
    print_success "Pre-commit hook installed"
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              Installation Complete!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "   Run SecureOpenClaw with:"
    echo ""
    echo "      ./openclaw"
    echo ""
    echo -e "   ${YELLOW}SECURITY REMINDER:${NC}"
    echo "   macaw_lib/ contains your API keys and is gitignored."
    echo "   Never commit this directory or share its contents."
    echo ""
}

# Main
main() {
    print_header
    check_prerequisites
    check_existing_installation
    guide_download
    get_zip_path
    install_macaw
    install_precommit_hook
    print_completion
}

main "$@"
