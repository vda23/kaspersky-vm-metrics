#!/usr/bin/env bash
set -euo pipefail
go_bin=$(command -v "$1")
candidate=$2
preview=$(mktemp -d)
trap 'rm -rf "$preview"' EXIT

# Build the exact development release from its original Git tree.
git archive 52f25aacaf7348b775c621afa560d54c38653968 | tar -x -C "$preview"
(cd "$preview" && CGO_ENABLED=1 "$go_bin" build -trimpath -o kaspersky-vm-metrics .)
KVM_PREVIEW_DIR="$preview" KVM_UPGRADE_BINARY="$candidate" "$go_bin" test -count=1 -v -run '^TestLiveUpgradeFrom' .
