#!/bin/bash
# Cross-compile autarch-dns for all supported platforms
set -e

VERSION="1.0.0"
OUTPUT_BASE="../../tools"

echo "Building autarch-dns v${VERSION}..."

# Linux ARM64 (Orange Pi 5 Plus)
echo "  → linux/arm64"
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUTPUT_BASE}/linux-arm64/autarch-dns" .

# Linux AMD64
echo "  → linux/amd64"
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUTPUT_BASE}/linux-x86_64/autarch-dns" .

# Windows AMD64
echo "  → windows/amd64"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUTPUT_BASE}/windows-x86_64/autarch-dns.exe" .

echo "Done! Binaries:"
ls -lh "${OUTPUT_BASE}"/*/autarch-dns* 2>/dev/null || true
