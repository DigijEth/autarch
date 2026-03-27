#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  AUTARCH Installer                                              ║
# ║  Autonomous Tactical Agent for Reconnaissance,                  ║
# ║  Counterintelligence, and Hacking                               ║
# ║  By darkHal Security Group & Setec Security Labs                ║
# ╚══════════════════════════════════════════════════════════════════╝

set -e

# ── Colors & Symbols ─────────────────────────────────────────────────
R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'; M='\033[95m'
C='\033[96m'; W='\033[97m'; D='\033[2m'; BLD='\033[1m'; RST='\033[0m'
CHK="${G}✔${RST}"; CROSS="${R}✘${RST}"; DOT="${C}●${RST}"; ARROW="${M}▸${RST}"
WARN="${Y}⚠${RST}"

# ── Paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

# ── State ────────────────────────────────────────────────────────────
INSTALL_LLM_LOCAL=false
INSTALL_LLM_CLOUD=false
INSTALL_LLM_HF=false
INSTALL_SYSTEM_TOOLS=false
INSTALL_NODE_HW=false
GPU_TYPE="none"
TOTAL_STEPS=0
CURRENT_STEP=0

# ── Helper Functions ─────────────────────────────────────────────────

clear_screen() { printf '\033[2J\033[H'; }

# Draw a horizontal rule
hr() {
    local char="${1:-─}"
    printf "${D}"
    printf '%*s' 66 '' | tr ' ' "$char"
    printf "${RST}\n"
}

# Print a styled header
header() {
    printf "\n${BLD}${C}  $1${RST}\n"
    hr
}

# Print a status line
status() { printf "  ${DOT} $1\n"; }
ok()     { printf "  ${CHK} $1\n"; }
fail()   { printf "  ${CROSS} $1\n"; }
warn()   { printf "  ${WARN} $1\n"; }
info()   { printf "  ${ARROW} $1\n"; }

# Progress bar
progress_bar() {
    local pct=$1
    local width=40
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))
    printf "\r  ${D}[${RST}${G}"
    printf '%*s' "$filled" '' | tr ' ' '█'
    printf "${D}"
    printf '%*s' "$empty" '' | tr ' ' '░'
    printf "${RST}${D}]${RST} ${W}%3d%%${RST}" "$pct"
}

step_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local pct=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    progress_bar "$pct"
    printf "  ${D}$1${RST}\n"
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)   OS="linux" ;;
        Darwin*)  OS="macos" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *)        OS="unknown" ;;
    esac
}

# Check if command exists
has() { command -v "$1" &>/dev/null; }

# ── Banner ───────────────────────────────────────────────────────────

show_banner() {
    clear_screen
    printf "${R}${BLD}"
    cat << 'BANNER'

     ▄▄▄       █    ██ ▄▄▄█████▓ ▄▄▄       ██▀███   ▄████▄   ██░ ██
    ▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▀ ▀█  ▓██░ ██▒
    ▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒▓█    ▄ ▒██▀▀██░
    ░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓▓▄ ▄██▒░▓█ ░██
     ▓█   ▓██▒▒▒█████▓   ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒▒ ▓███▀ ░░▓█▒░██▓
     ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ░▒ ▒  ░ ▒ ░░▒░▒
      ▒   ▒▒ ░░░▒░ ░ ░     ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░  ▒    ▒ ░▒░ ░
      ░   ▒    ░░░ ░ ░   ░        ░   ▒     ░░   ░ ░         ░  ░░ ░
          ░  ░   ░                    ░  ░   ░     ░ ░       ░  ░  ░

BANNER
    printf "${RST}"
    printf "${C}${BLD}               ╔══════════════════════════════════╗${RST}\n"
    printf "${C}${BLD}               ║     I N S T A L L E R  v1.0     ║${RST}\n"
    printf "${C}${BLD}               ╚══════════════════════════════════╝${RST}\n"
    printf "${D}         By darkHal Security Group & Setec Security Labs${RST}\n\n"
}

# ── System Check ─────────────────────────────────────────────────────

show_system_check() {
    header "SYSTEM CHECK"

    detect_os
    case "$OS" in
        linux)   ok "OS: Linux ($(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -r))" ;;
        macos)   ok "OS: macOS $(sw_vers -productVersion 2>/dev/null)" ;;
        windows) ok "OS: Windows (MSYS2/Git Bash)" ;;
        *)       warn "OS: Unknown ($(uname -s))" ;;
    esac

    # Python
    if has python3; then
        local pyver=$(python3 --version 2>&1 | awk '{print $2}')
        local pymajor=$(echo "$pyver" | cut -d. -f1)
        local pyminor=$(echo "$pyver" | cut -d. -f2)
        if [ "$pymajor" -ge 3 ] && [ "$pyminor" -ge 10 ]; then
            ok "Python $pyver"
        else
            warn "Python $pyver ${D}(3.10+ recommended)${RST}"
        fi
    elif has python; then
        local pyver=$(python --version 2>&1 | awk '{print $2}')
        ok "Python $pyver ${D}(using 'python' command)${RST}"
    else
        fail "Python not found — install Python 3.10+"
        exit 1
    fi

    # pip
    if has pip3 || has pip; then
        ok "pip available"
    else
        fail "pip not found"
        exit 1
    fi

    # Git
    if has git; then
        ok "Git $(git --version | awk '{print $3}')"
    else
        warn "Git not found ${D}(optional)${RST}"
    fi

    # Node/npm
    if has node && has npm; then
        ok "Node $(node --version) / npm $(npm --version 2>/dev/null)"
    else
        warn "Node.js not found ${D}(needed for hardware WebUSB libs)${RST}"
    fi

    # System tools
    local tools=("nmap" "tshark" "openssl" "adb" "fastboot" "wg" "upnpc")
    local found=()
    local missing=()
    for t in "${tools[@]}"; do
        if has "$t"; then
            found+=("$t")
        else
            missing+=("$t")
        fi
    done
    if [ ${#found[@]} -gt 0 ]; then
        ok "System tools: ${G}${found[*]}${RST}"
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        info "Not found: ${D}${missing[*]}${RST} ${D}(optional)${RST}"
    fi

    # GPU detection
    if has nvidia-smi; then
        local gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        ok "GPU: ${G}$gpu_name${RST} (CUDA)"
        GPU_TYPE="cuda"
    elif has rocm-smi; then
        ok "GPU: AMD ROCm detected"
        GPU_TYPE="rocm"
    elif [ -d "/opt/intel" ] || has xpu-smi; then
        ok "GPU: Intel XPU detected"
        GPU_TYPE="intel"
    elif [ "$OS" = "macos" ]; then
        ok "GPU: Apple Metal (auto via llama-cpp)"
        GPU_TYPE="metal"
    else
        info "No GPU detected ${D}(CPU-only mode)${RST}"
    fi
    echo
}

# ── Interactive Menu ─────────────────────────────────────────────────

show_menu() {
    header "INSTALL OPTIONS"
    echo
    printf "  ${BLD}${W}What would you like to install?${RST}\n\n"

    printf "  ${BLD}${C}[1]${RST} ${W}Core only${RST}          ${D}Flask, OSINT, networking, analysis${RST}\n"
    printf "  ${BLD}${C}[2]${RST} ${W}Core + Local LLM${RST}   ${D}+ llama-cpp-python (GGUF models)${RST}\n"
    printf "  ${BLD}${C}[3]${RST} ${W}Core + Cloud LLM${RST}   ${D}+ anthropic SDK (Claude API)${RST}\n"
    printf "  ${BLD}${C}[4]${RST} ${W}Core + HuggingFace${RST} ${D}+ transformers, torch, accelerate${RST}\n"
    printf "  ${BLD}${C}[5]${RST} ${W}Full install${RST}       ${D}All of the above${RST}\n"
    echo
    printf "  ${BLD}${Y}[S]${RST} ${W}System tools${RST}       ${D}nmap, tshark, openssl, adb (Linux only)${RST}\n"
    printf "  ${BLD}${Y}[H]${RST} ${W}Hardware libs${RST}      ${D}Build WebUSB/Serial JS bundles (needs npm)${RST}\n"
    echo
    printf "  ${BLD}${R}[Q]${RST} ${W}Quit${RST}\n"
    echo
    hr
    printf "  ${BLD}Choice: ${RST}"
    read -r choice

    case "$choice" in
        1) ;;
        2) INSTALL_LLM_LOCAL=true ;;
        3) INSTALL_LLM_CLOUD=true ;;
        4) INSTALL_LLM_HF=true ;;
        5) INSTALL_LLM_LOCAL=true; INSTALL_LLM_CLOUD=true; INSTALL_LLM_HF=true ;;
        s|S) INSTALL_SYSTEM_TOOLS=true ;;
        h|H) INSTALL_NODE_HW=true ;;
        q|Q) printf "\n  ${D}Bye.${RST}\n\n"; exit 0 ;;
        *)   warn "Invalid choice"; show_menu; return ;;
    esac

    # Extras prompt (only for options 1-5)
    if [[ "$choice" =~ ^[1-5]$ ]]; then
        echo
        printf "  ${D}Also install system tools? (nmap, tshark, etc.) [y/N]:${RST} "
        read -r yn
        [[ "$yn" =~ ^[Yy] ]] && INSTALL_SYSTEM_TOOLS=true

        printf "  ${D}Also build hardware JS bundles? (needs npm) [y/N]:${RST} "
        read -r yn
        [[ "$yn" =~ ^[Yy] ]] && INSTALL_NODE_HW=true
    fi
}

# ── Install Functions ────────────────────────────────────────────────

get_pip() {
    if has pip3; then echo "pip3"
    elif has pip; then echo "pip"
    fi
}

get_python() {
    if has python3; then echo "python3"
    elif has python; then echo "python"
    fi
}

create_venv() {
    header "VIRTUAL ENVIRONMENT"

    if [ -d "$VENV_DIR" ]; then
        ok "venv already exists at ${D}$VENV_DIR${RST}"
    else
        status "Creating virtual environment..."
        $(get_python) -m venv "$VENV_DIR"
        ok "Created venv at ${D}$VENV_DIR${RST}"
    fi

    # Activate
    if [ "$OS" = "windows" ]; then
        source "$VENV_DIR/Scripts/activate" 2>/dev/null || source "$VENV_DIR/bin/activate"
    else
        source "$VENV_DIR/bin/activate"
    fi
    ok "Activated venv ${D}($(which python))${RST}"
    echo
}

install_core() {
    header "CORE DEPENDENCIES"

    step_progress "Upgrading pip..."
    $(get_python) -m pip install --upgrade pip setuptools wheel -q 2>&1 | tail -1

    step_progress "Installing core packages..."
    # Install from requirements.txt but skip optional LLM lines
    # Core packages: flask, bcrypt, requests, msgpack, pyserial, esptool, pyshark, qrcode, Pillow
    local core_pkgs=(
        "flask>=3.0"
        "bcrypt>=4.0"
        "requests>=2.31"
        "msgpack>=1.0"
        "pyserial>=3.5"
        "esptool>=4.0"
        "pyshark>=0.6"
        "qrcode>=7.0"
        "Pillow>=10.0"
    )

    for pkg in "${core_pkgs[@]}"; do
        local name=$(echo "$pkg" | sed 's/[>=<].*//')
        step_progress "$name"
        pip install "$pkg" -q 2>&1 | tail -1
    done

    ok "Core dependencies installed"
    echo
}

install_llm_local() {
    header "LOCAL LLM (llama-cpp-python)"

    if [ "$GPU_TYPE" = "cuda" ]; then
        info "CUDA detected — building with GPU acceleration"
        step_progress "llama-cpp-python (CUDA)..."
        CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python>=0.3.16 --force-reinstall --no-cache-dir -q 2>&1 | tail -1
    elif [ "$GPU_TYPE" = "rocm" ]; then
        info "ROCm detected — building with AMD GPU acceleration"
        step_progress "llama-cpp-python (ROCm)..."
        CMAKE_ARGS="-DGGML_HIPBLAS=on" pip install llama-cpp-python>=0.3.16 --force-reinstall --no-cache-dir -q 2>&1 | tail -1
    elif [ "$GPU_TYPE" = "metal" ]; then
        info "Apple Metal — auto-enabled in llama-cpp"
        step_progress "llama-cpp-python (Metal)..."
        pip install llama-cpp-python>=0.3.16 -q 2>&1 | tail -1
    else
        info "CPU-only mode"
        step_progress "llama-cpp-python (CPU)..."
        pip install llama-cpp-python>=0.3.16 -q 2>&1 | tail -1
    fi

    ok "llama-cpp-python installed"
    echo
}

install_llm_cloud() {
    header "CLOUD LLM (Anthropic Claude API)"

    step_progress "anthropic SDK..."
    pip install "anthropic>=0.40" -q 2>&1 | tail -1

    ok "Anthropic SDK installed"
    info "Set your API key in autarch_settings.conf [claude] section"
    echo
}

install_llm_hf() {
    header "HUGGINGFACE (transformers + torch)"

    step_progress "transformers..."
    pip install "transformers>=4.35" -q 2>&1 | tail -1

    step_progress "accelerate..."
    pip install "accelerate>=0.25" -q 2>&1 | tail -1

    # PyTorch — pick the right variant
    step_progress "PyTorch..."
    if [ "$GPU_TYPE" = "cuda" ]; then
        info "Installing PyTorch with CUDA support..."
        pip install torch --index-url https://download.pytorch.org/whl/cu121 -q 2>&1 | tail -1
    elif [ "$GPU_TYPE" = "rocm" ]; then
        info "Installing PyTorch with ROCm support..."
        pip install torch --index-url https://download.pytorch.org/whl/rocm6.0 -q 2>&1 | tail -1
    elif [ "$GPU_TYPE" = "intel" ]; then
        info "Installing PyTorch with Intel XPU support..."
        pip install torch intel-extension-for-pytorch -q 2>&1 | tail -1
    else
        pip install torch -q 2>&1 | tail -1
    fi

    # bitsandbytes (Linux/CUDA only)
    if [ "$OS" = "linux" ] && [ "$GPU_TYPE" = "cuda" ]; then
        step_progress "bitsandbytes (quantization)..."
        pip install "bitsandbytes>=0.41" -q 2>&1 | tail -1
    else
        info "Skipping bitsandbytes ${D}(Linux + CUDA only)${RST}"
    fi

    ok "HuggingFace stack installed"
    echo
}

install_system_tools() {
    header "SYSTEM TOOLS"

    if [ "$OS" != "linux" ]; then
        warn "System tool install is only automated on Linux (apt/dnf/pacman)"
        info "On $OS, install these manually: nmap, wireshark-cli, openssl, android-tools"
        echo
        return
    fi

    # Detect package manager
    local PM=""
    local INSTALL=""
    if has apt-get; then
        PM="apt"
        INSTALL="sudo apt-get install -y"
    elif has dnf; then
        PM="dnf"
        INSTALL="sudo dnf install -y"
    elif has pacman; then
        PM="pacman"
        INSTALL="sudo pacman -S --noconfirm"
    else
        warn "No supported package manager found (apt/dnf/pacman)"
        echo
        return
    fi

    ok "Package manager: ${G}$PM${RST}"

    local packages=()

    # nmap
    if ! has nmap; then
        packages+=("nmap")
        status "Will install: nmap"
    else
        ok "nmap already installed"
    fi

    # tshark
    if ! has tshark; then
        case "$PM" in
            apt)    packages+=("tshark") ;;
            dnf)    packages+=("wireshark-cli") ;;
            pacman) packages+=("wireshark-cli") ;;
        esac
        status "Will install: tshark/wireshark-cli"
    else
        ok "tshark already installed"
    fi

    # openssl
    if ! has openssl; then
        packages+=("openssl")
        status "Will install: openssl"
    else
        ok "openssl already installed"
    fi

    # adb/fastboot
    if ! has adb; then
        case "$PM" in
            apt)    packages+=("android-tools-adb android-tools-fastboot") ;;
            dnf)    packages+=("android-tools") ;;
            pacman) packages+=("android-tools") ;;
        esac
        status "Will install: adb + fastboot"
    else
        ok "adb already installed"
    fi

    # wireguard
    if ! has wg; then
        case "$PM" in
            apt)    packages+=("wireguard wireguard-tools") ;;
            dnf)    packages+=("wireguard-tools") ;;
            pacman) packages+=("wireguard-tools") ;;
        esac
        status "Will install: wireguard-tools"
    else
        ok "wireguard already installed"
    fi

    # miniupnpc
    if ! has upnpc; then
        packages+=("miniupnpc")
        status "Will install: miniupnpc"
    else
        ok "miniupnpc already installed"
    fi

    if [ ${#packages[@]} -gt 0 ]; then
        echo
        info "Installing with: $PM"
        if [ "$PM" = "apt" ]; then
            sudo apt-get update -qq 2>&1 | tail -1
        fi
        $INSTALL ${packages[@]} 2>&1 | tail -5
        ok "System tools installed"
    else
        ok "All system tools already present"
    fi
    echo
}

install_node_hw() {
    header "HARDWARE JS BUNDLES (WebUSB / Web Serial)"

    if ! has npm; then
        fail "npm not found — install Node.js first"
        info "https://nodejs.org or: apt install nodejs npm"
        echo
        return
    fi

    step_progress "npm install..."
    (cd "$SCRIPT_DIR" && npm install --silent 2>&1 | tail -3)

    step_progress "Building bundles..."
    if [ -f "$SCRIPT_DIR/scripts/build-hw-libs.sh" ]; then
        (cd "$SCRIPT_DIR" && bash scripts/build-hw-libs.sh 2>&1 | tail -5)
        ok "Hardware bundles built"
    else
        warn "scripts/build-hw-libs.sh not found"
    fi
    echo
}

# ── Summary ──────────────────────────────────────────────────────────

show_summary() {
    hr "═"
    printf "\n${BLD}${G}  INSTALLATION COMPLETE${RST}\n\n"

    printf "  ${BLD}${W}Quick Start:${RST}\n"
    echo

    if [ "$OS" = "windows" ]; then
        printf "  ${D}# Activate the virtual environment${RST}\n"
        printf "  ${C}source venv/Scripts/activate${RST}\n\n"
    else
        printf "  ${D}# Activate the virtual environment${RST}\n"
        printf "  ${C}source venv/bin/activate${RST}\n\n"
    fi

    printf "  ${D}# Launch the CLI${RST}\n"
    printf "  ${C}python autarch.py${RST}\n\n"

    printf "  ${D}# Launch the web dashboard${RST}\n"
    printf "  ${C}python autarch_web.py${RST}\n\n"

    printf "  ${D}# Open in browser${RST}\n"
    printf "  ${C}https://localhost:8181${RST}\n"
    echo

    if $INSTALL_LLM_LOCAL; then
        printf "  ${ARROW} Local LLM: place a .gguf model in ${D}models/${RST}\n"
        printf "    ${D}and set model_path in autarch_settings.conf [llama]${RST}\n"
    fi
    if $INSTALL_LLM_CLOUD; then
        printf "  ${ARROW} Claude API: set api_key in ${D}autarch_settings.conf [claude]${RST}\n"
    fi
    echo
    hr "═"
    echo
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
    show_banner
    show_system_check
    show_menu

    # Calculate total steps for progress
    TOTAL_STEPS=11  # pip upgrade + 9 core packages + 1 finish
    $INSTALL_LLM_LOCAL && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    $INSTALL_LLM_CLOUD && TOTAL_STEPS=$((TOTAL_STEPS + 1))
    $INSTALL_LLM_HF    && TOTAL_STEPS=$((TOTAL_STEPS + 4))
    $INSTALL_NODE_HW   && TOTAL_STEPS=$((TOTAL_STEPS + 2))

    echo
    create_venv
    install_core

    $INSTALL_LLM_LOCAL  && install_llm_local
    $INSTALL_LLM_CLOUD  && install_llm_cloud
    $INSTALL_LLM_HF    && install_llm_hf
    $INSTALL_SYSTEM_TOOLS && install_system_tools
    $INSTALL_NODE_HW    && install_node_hw

    show_summary
}

main "$@"
