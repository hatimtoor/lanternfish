#!/usr/bin/env bash
# Build download-and-run Lanternfish binaries for every platform into ./dist.
# Usage: scripts/build-release.sh [version]   (version defaults to "dev")
set -euo pipefail

VERSION="${1:-dev}"
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/*

cli_targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
for target in "${cli_targets[@]}"; do
  os="${target%/*}"; arch="${target#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  out="dist/lanternfish_${VERSION}_${os}_${arch}${ext}"
  echo "building $out"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/lanternfish
done

# Native desktop window is Windows-only.
for arch in amd64 arm64; do
  out="dist/lanternfish-gui_${VERSION}_windows_${arch}.exe"
  echo "building $out"
  GOOS=windows GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o "$out" ./cmd/lanternfish-gui
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum ./* > SHA256SUMS.txt)
fi
echo "Done. Binaries in ./dist"
