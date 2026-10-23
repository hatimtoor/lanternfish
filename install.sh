#!/bin/sh
# Install the latest Lanternfish CLI (Linux/macOS). One-liner:
#   curl -fsSL https://raw.githubusercontent.com/hatimtoor/lanternfish/main/install.sh | sh
# Windows: use Scoop (see README) or download the .exe from the Releases page.
#
# Authorized testing only: use Lanternfish against systems you own or are
# explicitly permitted to test.
set -eu

REPO="hatimtoor/lanternfish"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "lanternfish: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux | darwin) ;;
  *) echo "lanternfish: unsupported OS: $os (on Windows use Scoop or the .exe from Releases)" >&2; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "lanternfish: '$1' is required" >&2; exit 1; }; }
need curl

echo "Finding the latest release..."
tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d'"' -f4)
[ -n "$tag" ] || { echo "lanternfish: could not determine the latest release" >&2; exit 1; }

asset="lanternfish_${tag}_${os}_${arch}"
base="https://github.com/$REPO/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($tag)..."
curl -fsSL "$base/$asset" -o "$tmp/lanternfish"

# Verify the checksum when we can.
if curl -fsSL "$base/SHA256SUMS.txt" -o "$tmp/sums" 2>/dev/null; then
  want=$(awk -v a="$asset" '$2==a {print $1}' "$tmp/sums")
  if [ -n "$want" ] && command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/lanternfish" | awk '{print $1}')
    if [ "$want" != "$got" ]; then
      echo "lanternfish: checksum mismatch — aborting" >&2; exit 1
    fi
    echo "Checksum verified."
  fi
fi

chmod +x "$tmp/lanternfish"

# Choose an install directory we can write to.
if [ -w "/usr/local/bin" ]; then
  dest="/usr/local/bin"
  mv "$tmp/lanternfish" "$dest/lanternfish"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
  dest="/usr/local/bin"
  sudo mv "$tmp/lanternfish" "$dest/lanternfish"
else
  dest="$HOME/.local/bin"
  mkdir -p "$dest"
  mv "$tmp/lanternfish" "$dest/lanternfish"
fi

echo "Installed lanternfish to $dest/lanternfish"
case ":$PATH:" in
  *":$dest:"*) ;;
  *) echo "Note: add $dest to your PATH to run 'lanternfish' directly." ;;
esac
echo
echo "New here? Start the legal practice range:  lanternfish lab"
echo "Then try a narrated assessment:            lanternfish guide <url>"
