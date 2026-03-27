#!/bin/bash
# Build Autarch Server Manager
# Usage: bash build.sh
#
# Targets: Linux AMD64 (Debian 13 server)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "══════════════════════════════════════════════════════"
echo "  Building Autarch Server Manager"
echo "══════════════════════════════════════════════════════"
echo

# Resolve dependencies
echo "[1/3] Resolving Go dependencies..."
go mod tidy
echo "  ✔ Dependencies resolved"
echo

# Build for Linux AMD64 (Debian 13 target)
echo "[2/3] Building linux/amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o autarch-server-manager \
    ./cmd/
echo "  ✔ autarch-server-manager ($(ls -lh autarch-server-manager | awk '{print $5}'))"
echo

# Also build for current platform if different
if [ "$(go env GOOS)" != "linux" ] || [ "$(go env GOARCH)" != "amd64" ]; then
    echo "[3/3] Building for current platform ($(go env GOOS)/$(go env GOARCH))..."
    go build \
        -ldflags="-s -w" \
        -o autarch-server-manager-local \
        ./cmd/
    echo "  ✔ autarch-server-manager-local"
else
    echo "[3/3] Current platform is linux/amd64 — skipping duplicate build"
fi

echo
echo "══════════════════════════════════════════════════════"
echo "  Build complete!"
echo ""
echo "  Deploy to server:"
echo "    scp autarch-server-manager root@server:/opt/autarch/"
echo "    ssh root@server /opt/autarch/autarch-server-manager"
echo "══════════════════════════════════════════════════════"
