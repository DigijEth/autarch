#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────
# AUTARCH .deb package builder
#
# Usage:  bash scripts/build-deb.sh [version] [--arch arm64|amd64|all]
# Output: dist/autarch_{version}_{arch}.deb
#
# No git. No debhelper. No pybuild. Just dpkg-deb.
# ───────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="autarch"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Parse arguments ──────────────────────────────────────────
FORCE_ARCH=""
VERSION=""

for arg in "$@"; do
    case "$arg" in
        --arch=*) FORCE_ARCH="${arg#--arch=}" ;;
        --arch)   ;; # handled by next iteration
        arm64|amd64|armhf|all)
            if [[ -z "$FORCE_ARCH" ]]; then
                FORCE_ARCH="$arg"
            elif [[ -z "$VERSION" ]]; then
                VERSION="$arg"
            fi
            ;;
        *)
            if [[ -z "$VERSION" && ! "$arg" =~ ^-- ]]; then
                VERSION="$arg"
            fi
            ;;
    esac
done

# Handle "all" — build for multiple architectures
if [[ "$FORCE_ARCH" == "all" ]]; then
    echo "Building for all architectures..."
    for arch in arm64 amd64; do
        bash "$0" ${VERSION:+$VERSION} "$arch"
    done
    exit 0
fi

# ── Detect or override architecture ──────────────────────────
if [[ -n "$FORCE_ARCH" ]]; then
    DEB_ARCH="$FORCE_ARCH"
else
    DEB_ARCH="$(dpkg --print-architecture)"
fi

case "$DEB_ARCH" in
    arm64)  PLATFORM_TAG="linux-arm64"   ;;
    amd64)  PLATFORM_TAG="linux-x86_64"  ;;
    armhf)  PLATFORM_TAG="linux-armhf"   ;;
    *)      PLATFORM_TAG="linux-${DEB_ARCH}" ;;
esac

# ── Determine version ────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -m1 '^VERSION' "$SRC_DIR/autarch.py" | sed 's/.*"\(.*\)".*/\1/')"
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not extract VERSION from autarch.py" >&2
        exit 1
    fi
fi

echo "Building ${APP_NAME} ${VERSION} for ${DEB_ARCH} (${PLATFORM_TAG})"

# ── Paths ─────────────────────────────────────────────────────
DIST_DIR="$SRC_DIR/dist"
BUILD_DIR="$DIST_DIR/.build"
PKG_NAME="${APP_NAME}_${VERSION}_${DEB_ARCH}"
STAGE="$BUILD_DIR/$PKG_NAME"
OPT="$STAGE/opt/autarch"

# Clean previous build
rm -rf "$STAGE"
mkdir -p "$OPT" "$STAGE/DEBIAN" "$STAGE/usr/bin"

# ── Copy application files ────────────────────────────────────
echo "Copying application files..."

# Core Python files at root
cp "$SRC_DIR/autarch.py"       "$OPT/"
cp "$SRC_DIR/requirements.txt" "$OPT/"

# Settings: ship live config (dpkg conffile-protected) AND .default template
cp "$SRC_DIR/autarch_settings.conf" "$OPT/autarch_settings.conf"
cp "$SRC_DIR/autarch_settings.conf" "$OPT/autarch_settings.conf.default"

# User-editable data files
cp "$SRC_DIR/custom_sites.inf"      "$OPT/"
cp "$SRC_DIR/custom_adultsites.json" "$OPT/"

# Documentation
[[ -f "$SRC_DIR/GUIDE.md" ]]       && cp "$SRC_DIR/GUIDE.md" "$OPT/"
[[ -f "$SRC_DIR/user_manual.md" ]] && cp "$SRC_DIR/user_manual.md" "$OPT/"

# Directory trees
for dir in core modules web; do
    cp -a "$SRC_DIR/$dir" "$OPT/"
done

# Data (sites db etc.)
cp -a "$SRC_DIR/data" "$OPT/"

# Hardware config templates
if [[ -d "$SRC_DIR/.config" ]]; then
    cp -a "$SRC_DIR/.config" "$OPT/"
fi

# Bundled tools for THIS architecture
if [[ -d "$SRC_DIR/tools/$PLATFORM_TAG" ]]; then
    mkdir -p "$OPT/tools/$PLATFORM_TAG"
    cp -a "$SRC_DIR/tools/$PLATFORM_TAG/." "$OPT/tools/$PLATFORM_TAG/"
fi

# Android tools (arch-independent — same adb/fastboot for the host)
if [[ -d "$SRC_DIR/android" ]]; then
    cp -a "$SRC_DIR/android" "$OPT/"
fi

# Companion APK (if built)
APK="$SRC_DIR/autarch_companion/app/build/outputs/apk/debug/app-debug.apk"
if [[ -f "$APK" ]]; then
    mkdir -p "$OPT/companion"
    cp "$APK" "$OPT/companion/archon.apk"
fi

# Systemd service
if [[ -f "$SRC_DIR/scripts/autarch-web.service" ]]; then
    mkdir -p "$STAGE/etc/systemd/system"
    cp "$SRC_DIR/scripts/autarch-web.service" "$STAGE/etc/systemd/system/autarch-web.service"
fi

# ── Strip excluded files ──────────────────────────────────────
echo "Stripping excluded files..."

# __pycache__ and .pyc
find "$OPT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$OPT" -name "*.pyc" -delete 2>/dev/null || true

# Backup files
find "$OPT" -name "*.bk" -delete 2>/dev/null || true

# .claude directory
rm -rf "$OPT/.claude"

# node_modules, src (build artifacts)
rm -rf "$OPT/node_modules" "$OPT/src"

# User-generated data that shouldn't ship
rm -f "$OPT"/*_profiles.json

# System/dev files
rm -f "$OPT/system.inf" "$OPT/backupexec_dump.mtf"

# Dev docs
rm -f "$OPT/DEVLOG.md" "$OPT/devjournal.md" "$OPT/autarch_dev.md"
rm -f "$OPT/android_plan.md" "$OPT/master_plan.md"

# Node/package files
rm -f "$OPT/package.json" "$OPT/package-lock.json" "$OPT/.gitignore"

# User data dirs — create empty structure but don't ship contents
for datadir in results dossiers data/captures data/exports data/hardware data/pentest_sessions data/uploads; do
    rm -rf "$OPT/$datadir"
done

# ── Generate DEBIAN/control ───────────────────────────────────
INSTALLED_KB=$(du -sk "$STAGE" | cut -f1)

cat > "$STAGE/DEBIAN/control" <<EOF
Package: ${APP_NAME}
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: darkHal Security Group <noreply@darkhal.local>
Description: AUTARCH - Autonomous Tactical Agent for Reconnaissance,
 Counterintelligence, and Hacking. Self-contained security framework
 with web UI, OSINT tools, network scanning, hardware flashing,
 and optional LLM integration.
Section: utils
Priority: optional
Installed-Size: ${INSTALLED_KB}
Depends: python3 (>= 3.10), python3-pip, python3-venv
Recommends: nmap, tcpdump, tshark, miniupnpc, wireguard-tools
Suggests: metasploit-framework, clamav
EOF

# ── Generate DEBIAN/conffiles ─────────────────────────────────
cat > "$STAGE/DEBIAN/conffiles" <<EOF
/opt/autarch/autarch_settings.conf
/opt/autarch/custom_sites.inf
/opt/autarch/custom_adultsites.json
EOF

# ── Generate DEBIAN/postinst ──────────────────────────────────
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

APP="/opt/autarch"

# First install: ensure live config exists (dpkg ships it, but just in case)
if [ ! -f "$APP/autarch_settings.conf" ]; then
    cp "$APP/autarch_settings.conf.default" "$APP/autarch_settings.conf"
fi

# Create writable data directories
for d in results dossiers data/captures data/exports data/hardware data/pentest_sessions data/uploads; do
    mkdir -p "$APP/$d"
done

# Set permissions on entry point
chmod +x "$APP/autarch.py"

# Set permissions on bundled tools
for f in "$APP"/tools/linux-*/nmap "$APP"/tools/linux-*/tcpdump \
         "$APP"/tools/linux-*/upnpc "$APP"/tools/linux-*/wg; do
    [ -f "$f" ] && chmod +x "$f"
done

# Android binaries
for f in "$APP"/android/adb "$APP"/android/fastboot; do
    [ -f "$f" ] && chmod +x "$f"
done

# Create Python venv and install dependencies
if [ ! -d "$APP/venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$APP/venv"
fi

echo "Installing Python dependencies..."
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet -r "$APP/requirements.txt"

echo "AUTARCH installed successfully."
echo "Run 'autarch --help' to get started."
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

# ── Generate DEBIAN/prerm ─────────────────────────────────────
cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
# Nothing to do before removal — just a placeholder for future needs.
PRERM
chmod 0755 "$STAGE/DEBIAN/prerm"

# ── Generate DEBIAN/postrm ────────────────────────────────────
cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e

APP="/opt/autarch"

if [ "$1" = "purge" ]; then
    # Remove venv (large, regenerable)
    rm -rf "$APP/venv"

    # Remove empty data directories only
    for d in results dossiers data/captures data/exports data/hardware data/pentest_sessions data/uploads data; do
        [ -d "$APP/$d" ] && rmdir --ignore-fail-on-non-empty "$APP/$d" 2>/dev/null || true
    done

    # Remove app dir if completely empty
    rmdir --ignore-fail-on-non-empty "$APP" 2>/dev/null || true
fi
POSTRM
chmod 0755 "$STAGE/DEBIAN/postrm"

# ── Generate /usr/bin/autarch wrapper ─────────────────────────
cat > "$STAGE/usr/bin/autarch" <<'WRAPPER'
#!/bin/bash
exec /opt/autarch/venv/bin/python3 /opt/autarch/autarch.py "$@"
WRAPPER
chmod 0755 "$STAGE/usr/bin/autarch"

# ── Build the .deb ────────────────────────────────────────────
echo "Building .deb package..."
mkdir -p "$DIST_DIR"

DEB_OUT="$DIST_DIR/${PKG_NAME}.deb"

if command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb --build "$STAGE" "$DEB_OUT"
else
    dpkg-deb --build "$STAGE" "$DEB_OUT"
fi

# ── Clean up staging ──────────────────────────────────────────
rm -rf "$BUILD_DIR"

# ── Summary ───────────────────────────────────────────────────
DEB_SIZE=$(du -h "$DEB_OUT" | cut -f1)
echo ""
echo "════════════════════════════════════════════════════"
echo "  Package: $DEB_OUT"
echo "  Size:    $DEB_SIZE"
echo "  Arch:    $DEB_ARCH ($PLATFORM_TAG)"
echo "════════════════════════════════════════════════════"
echo ""
echo "Inspect:   dpkg-deb --info $DEB_OUT"
echo "Contents:  dpkg-deb --contents $DEB_OUT | head -50"
echo "Install:   sudo dpkg -i $DEB_OUT && sudo apt-get install -f"
