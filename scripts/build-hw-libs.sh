#!/bin/bash
# Build browser-ready bundles for AUTARCH hardware direct-mode libraries
# Run from project root: bash scripts/build-hw-libs.sh
#
# Requires: npm install (run once to install dependencies)
# Output: web/static/js/lib/*.js (committed to project, no node needed at runtime)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$PROJECT_DIR/web/static/js/lib"

mkdir -p "$OUT_DIR"

echo "Building hardware library bundles..."
echo "Output: $OUT_DIR"

# ADB bundle (ya-webadb / Tango)
echo "  [1/3] Building adb-bundle.js..."
npx esbuild "$PROJECT_DIR/src/adb-entry.js" \
    --bundle \
    --format=iife \
    --global-name=YumeAdb \
    --platform=browser \
    --target=chrome89 \
    --outfile="$OUT_DIR/adb-bundle.js" \
    --minify

# Fastboot bundle
echo "  [2/3] Building fastboot-bundle.js..."
npx esbuild "$PROJECT_DIR/src/fastboot-entry.js" \
    --bundle \
    --format=iife \
    --global-name=Fastboot \
    --platform=browser \
    --target=chrome89 \
    --outfile="$OUT_DIR/fastboot-bundle.js" \
    --minify

# ESP32 bundle (esptool-js)
echo "  [3/3] Building esptool-bundle.js..."
npx esbuild "$PROJECT_DIR/src/esptool-entry.js" \
    --bundle \
    --format=iife \
    --global-name=EspTool \
    --platform=browser \
    --target=chrome89 \
    --outfile="$OUT_DIR/esptool-bundle.js" \
    --minify

echo ""
echo "Build complete:"
ls -lh "$OUT_DIR"/*.js
