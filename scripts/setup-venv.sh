#!/bin/bash
# AUTARCH Virtual Environment Setup
# Creates a project-local venv with all dependencies.
# The venv is accessible by any user (including root), eliminating
# the need for sys.path hacks or system-wide pip installs.
#
# Usage:
#   bash scripts/setup-venv.sh          # Create venv and install deps
#   bash scripts/setup-venv.sh --force  # Recreate from scratch
#
# After setup, run AUTARCH with:
#   sudo ./venv/bin/python autarch.py --web

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"
REQ_FILE="$PROJECT_DIR/requirements.txt"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'

echo -e "${CYAN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║    AUTARCH Virtual Environment Setup      ║${RESET}"
echo -e "${CYAN}╚═══════════════════════════════════════════╝${RESET}"
echo ""

# Check Python version
PYTHON=""
for p in python3.13 python3.12 python3.11 python3; do
    if command -v "$p" &>/dev/null; then
        PYTHON="$p"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "${RED}[X] Python 3.10+ not found. Install python3 first.${RESET}"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Using: $PYTHON (Python $PY_VERSION)${RESET}"

# Check for --force flag
if [ "$1" = "--force" ] && [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[!] Removing existing venv...${RESET}"
    rm -rf "$VENV_DIR"
fi

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${CYAN}[*] Creating virtual environment at $VENV_DIR${RESET}"
    # Try python -m venv first, fall back to virtualenv (doesn't need python3-venv package)
    if $PYTHON -m venv "$VENV_DIR" --system-site-packages 2>/dev/null; then
        echo -e "${GREEN}[+] venv created (venv module)${RESET}"
    else
        echo -e "${YELLOW}[!] python3-venv not available, using virtualenv...${RESET}"
        $PYTHON -m pip install --user virtualenv --quiet 2>/dev/null
        $PYTHON -m virtualenv "$VENV_DIR" --system-site-packages
        echo -e "${GREEN}[+] venv created (virtualenv)${RESET}"
    fi
else
    echo -e "${GREEN}[+] venv already exists at $VENV_DIR${RESET}"
fi

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${RESET}"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

# Install requirements
if [ -f "$REQ_FILE" ]; then
    echo -e "${CYAN}[*] Installing requirements from $REQ_FILE${RESET}"
    "$VENV_DIR/bin/pip" install -r "$REQ_FILE" 2>&1 | while read line; do
        if echo "$line" | grep -q "^Successfully\|^Requirement already"; then
            echo -e "  ${GREEN}$line${RESET}"
        elif echo "$line" | grep -qi "error\|fail"; then
            echo -e "  ${YELLOW}$line${RESET}"
        fi
    done
    echo -e "${GREEN}[+] Requirements installed${RESET}"
else
    echo -e "${YELLOW}[!] No requirements.txt found at $REQ_FILE${RESET}"
fi

# Make venv accessible when running as root via sudo
# This is the key: root can use venv/bin/python directly
chmod -R a+rX "$VENV_DIR"

# Verify key packages
echo ""
echo -e "${CYAN}[*] Verifying key packages:${RESET}"
for pkg in flask anthropic openai llama_cpp transformers scapy mcp; do
    if "$VENV_DIR/bin/python" -c "import $pkg" 2>/dev/null; then
        ver=$("$VENV_DIR/bin/python" -c "import $pkg; print(getattr($pkg, '__version__', 'ok'))" 2>/dev/null)
        echo -e "  ${GREEN}✓ $pkg ($ver)${RESET}"
    else
        echo -e "  ${YELLOW}✗ $pkg (not installed or failed)${RESET}"
    fi
done

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║    Setup complete!                        ║${RESET}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "Start AUTARCH with:"
echo -e "  ${CYAN}sudo $VENV_DIR/bin/python $PROJECT_DIR/autarch.py --web${RESET}"
echo ""
echo -e "Or activate the venv first:"
echo -e "  ${CYAN}source $VENV_DIR/bin/activate${RESET}"
echo -e "  ${CYAN}sudo -E python autarch.py --web${RESET}"
echo ""
