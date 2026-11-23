#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
arch=$1
case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; esac
version=$(cat VERSION)
name="kaspersky-vm-metrics-$version-linux-$arch"
mkdir -p dist
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
install -m755 "build/$arch/kaspersky-vm-metrics" install.sh "$stage/$name/"
install -m644 VERSION KasperskySans-Regular.ttf README.md AGENTS.md "$stage/$name/"
(cd "$stage/$name" && sha256sum VERSION kaspersky-vm-metrics install.sh KasperskySans-Regular.ttf README.md AGENTS.md > SHA256SUMS)
tar -C "$stage" -czf "$stage/$name.tar.gz" "$name"
mv "$stage/$name.tar.gz" "dist/$name.tar.gz"
echo "dist/$name.tar.gz"
