#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────
# AUTARCH Windows Package Builder
#
# Creates a standalone Windows-ready ZIP with:
#   - All Python source + web assets
#   - Batch launcher (autarch.bat)
#   - PowerShell installer (install.ps1)
#   - requirements.txt for pip install
#   - Placeholder for Windows tools
#
# Usage:  bash scripts/build-windows.sh [version]
# Output: dist/autarch_{version}_windows.zip
#
# NOTE: This builds a SOURCE distribution, not a frozen .exe.
# The install.ps1 script handles Python venv + dependency install.
# For a frozen .exe, run PyInstaller ON a Windows machine.
# ───────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="autarch"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Determine version ────────────────────────────────────────
if [[ ${1:-} ]]; then
    VERSION="$1"
else
    VERSION="$(grep -m1 '^VERSION' "$SRC_DIR/autarch.py" | sed 's/.*"\(.*\)".*/\1/')"
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not extract VERSION from autarch.py" >&2
        exit 1
    fi
fi

echo "Building ${APP_NAME} ${VERSION} for Windows"

# ── Paths ─────────────────────────────────────────────────────
DIST_DIR="$SRC_DIR/dist"
BUILD_DIR="$DIST_DIR/.win-build"
STAGE="$BUILD_DIR/${APP_NAME}_${VERSION}_windows"

# Clean
rm -rf "$STAGE"
mkdir -p "$STAGE"

# ── Copy application files ────────────────────────────────────
echo "Copying application files..."

# Core
cp "$SRC_DIR/autarch.py"           "$STAGE/"
cp "$SRC_DIR/requirements.txt"     "$STAGE/"

# Config
cp "$SRC_DIR/autarch_settings.conf" "$STAGE/autarch_settings.conf"
cp "$SRC_DIR/autarch_settings.conf" "$STAGE/autarch_settings.conf.default"

# User files
cp "$SRC_DIR/custom_sites.inf"      "$STAGE/"
cp "$SRC_DIR/custom_adultsites.json" "$STAGE/"

# Documentation
[[ -f "$SRC_DIR/GUIDE.md" ]]       && cp "$SRC_DIR/GUIDE.md" "$STAGE/"
[[ -f "$SRC_DIR/user_manual.md" ]] && cp "$SRC_DIR/user_manual.md" "$STAGE/"

# Directory trees
for dir in core modules web; do
    cp -a "$SRC_DIR/$dir" "$STAGE/"
done

# Data (sites db etc.)
cp -a "$SRC_DIR/data" "$STAGE/"

# Config templates
if [[ -d "$SRC_DIR/.config" ]]; then
    cp -a "$SRC_DIR/.config" "$STAGE/"
fi

# Windows tools directory (placeholder — user downloads nmap/tshark etc.)
mkdir -p "$STAGE/tools/windows-x86_64"

# Companion APK
APK="$SRC_DIR/autarch_companion/app/build/outputs/apk/debug/app-debug.apk"
if [[ -f "$APK" ]]; then
    mkdir -p "$STAGE/companion"
    cp "$APK" "$STAGE/companion/archon.apk"
fi

# ── Strip excluded files ──────────────────────────────────────
echo "Stripping excluded files..."
find "$STAGE" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name "*.pyc" -delete 2>/dev/null || true
find "$STAGE" -name "*.bk" -delete 2>/dev/null || true
rm -rf "$STAGE/.claude" "$STAGE/node_modules" "$STAGE/src"
rm -f "$STAGE"/*_profiles.json
rm -f "$STAGE/system.inf" "$STAGE/backupexec_dump.mtf"
rm -f "$STAGE/DEVLOG.md" "$STAGE/devjournal.md" "$STAGE/autarch_dev.md"
rm -f "$STAGE/android_plan.md" "$STAGE/master_plan.md"
rm -f "$STAGE/package.json" "$STAGE/package-lock.json" "$STAGE/.gitignore"
for datadir in results dossiers data/captures data/exports data/hardware data/pentest_sessions data/uploads; do
    rm -rf "$STAGE/$datadir"
done

# ── Create Windows launcher (autarch.bat) ─────────────────────
cat > "$STAGE/autarch.bat" <<'BAT'
@echo off
REM AUTARCH Launcher for Windows
REM Uses Python virtual environment if available, falls back to system Python

setlocal

set "APP_DIR=%~dp0"

if exist "%APP_DIR%venv\Scripts\python.exe" (
    "%APP_DIR%venv\Scripts\python.exe" "%APP_DIR%autarch.py" %*
) else (
    python "%APP_DIR%autarch.py" %*
)

endlocal
BAT

# ── Create web dashboard launcher ─────────────────────────────
cat > "$STAGE/start-web.bat" <<'BAT'
@echo off
REM Start AUTARCH Web Dashboard
setlocal

set "APP_DIR=%~dp0"

echo Starting AUTARCH Web Dashboard...
echo Open your browser to: http://localhost:8181
echo Press Ctrl+C to stop.
echo.

if exist "%APP_DIR%venv\Scripts\python.exe" (
    "%APP_DIR%venv\Scripts\python.exe" "%APP_DIR%autarch.py" --web %*
) else (
    python "%APP_DIR%autarch.py" --web %*
)

endlocal
BAT

# ── Create installer script (PowerShell) ──────────────────────
cat > "$STAGE/install.ps1" <<'PS1'
# AUTARCH Windows Installer
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "  AUTARCH Installer for Windows" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""

$AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "ERROR: Python not found. Install Python 3.10+ from python.org" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Yellow
    exit 1
}

$pyVer = python --version 2>&1
Write-Host "Found: $pyVer" -ForegroundColor Cyan

# Create virtual environment
$venvDir = Join-Path $AppDir "venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
    python -m venv $venvDir
}

# Install dependencies
$pip = Join-Path $venvDir "Scripts\pip.exe"
Write-Host "Installing dependencies..." -ForegroundColor Yellow
& $pip install --quiet --upgrade pip
& $pip install --quiet -r (Join-Path $AppDir "requirements.txt")

# Create data directories
$dataDirs = @("results", "dossiers", "data\captures", "data\exports",
              "data\hardware", "data\pentest_sessions", "data\uploads")
foreach ($d in $dataDirs) {
    $path = Join-Path $AppDir $d
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Create desktop shortcut
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktop "AUTARCH.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $AppDir "autarch.bat"
$shortcut.WorkingDirectory = $AppDir
$shortcut.Description = "AUTARCH Security Platform"
$shortcut.Save()

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run AUTARCH:" -ForegroundColor Cyan
Write-Host "  CLI:  autarch.bat" -ForegroundColor White
Write-Host "  Web:  start-web.bat" -ForegroundColor White
Write-Host "  Manual: python autarch.py --manual" -ForegroundColor White
Write-Host ""
Write-Host "Desktop shortcut created." -ForegroundColor Yellow
Write-Host ""
PS1

# ── Create README for Windows ─────────────────────────────────
cat > "$STAGE/README-WINDOWS.txt" <<'README'
AUTARCH for Windows
===================

Quick Start:
  1. Run install.ps1 (right-click > Run with PowerShell)
     This creates a Python environment and installs dependencies.

  2. Double-click autarch.bat to start the CLI menu.
     Or double-click start-web.bat for the browser dashboard.

Requirements:
  - Python 3.10 or newer (python.org - check "Add to PATH")
  - Windows 10 or newer

Optional Tools (place in tools\windows-x86_64\):
  - nmap.exe       (nmap.org)
  - tshark.exe     (wireshark.org)
  - wg.exe         (wireguard.com)

Manual:
  python autarch.py --manual    (in terminal)
  Open user_manual.md           (any text editor/Markdown viewer)
  http://localhost:8181/manual   (when web dashboard is running)

Companion App:
  The Archon Android companion app APK is in the companion\ folder.
  Install it on your phone via ADB or file transfer.
README

# ── Create the ZIP ────────────────────────────────────────────
echo "Creating ZIP archive..."
mkdir -p "$DIST_DIR"

ZIP_NAME="${APP_NAME}_${VERSION}_windows.zip"
ZIP_OUT="$DIST_DIR/$ZIP_NAME"

(cd "$BUILD_DIR" && zip -r -q "$ZIP_OUT" "$(basename "$STAGE")")

# ── Clean up ──────────────────────────────────────────────────
rm -rf "$BUILD_DIR"

# ── Summary ───────────────────────────────────────────────────
ZIP_SIZE=$(du -h "$ZIP_OUT" | cut -f1)
echo ""
echo "════════════════════════════════════════════════════"
echo "  Package: $ZIP_OUT"
echo "  Size:    $ZIP_SIZE"
echo "════════════════════════════════════════════════════"
echo ""
echo "Transfer this ZIP to a Windows machine and run install.ps1"
