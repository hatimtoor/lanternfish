#!/usr/bin/env bash
# Refresh Lanternfish's signature databases from public sources, then verify
# the build and tests still pass. Run from the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Updating vulnerable-JS-library signatures from retire.js..."
go run ./tools/sigsync

echo "Building and testing the affected package..."
go build ./...
go test ./internal/scan/checks/

echo
echo "Done. Review the diff to internal/scan/checks/data/ and commit if it looks right:"
echo "  git diff --stat internal/scan/checks/data/"
