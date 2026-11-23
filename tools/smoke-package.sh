#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
pid=
cleanup() {
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
tar -xzf "$1" -C "$work"
cd "$work"/kaspersky-vm-metrics-*
sha256sum -c SHA256SUMS
program=(./kaspersky-vm-metrics)
if [[ -n ${KVM_QEMU_AARCH64:-} ]]; then
    program=("$KVM_QEMU_AARCH64" "${program[@]}")
fi
test "$("${program[@]}" --version)" = "$(cat VERSION)"
"${program[@]}" --check
"${program[@]}" --bind 127.0.0.1 --port "${SMOKE_PORT:-18999}" > smoke.log 2>&1 &
pid=$!
actual=
for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
        cat smoke.log >&2
        exit 1
    fi
    actual=$("${program[@]}" --port "${SMOKE_PORT:-18999}" --probe 2>/dev/null) && break
    sleep .1
done
test "$actual" = "$(cat VERSION)"
curl -ksSf "https://127.0.0.1:${SMOKE_PORT:-18999}/api/status" > snapshot.json
grep -q '"services_memory_bytes"' snapshot.json
kill -TERM "$pid"
wait "$pid"
pid=
