#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath "${1:?Specify the built kaspersky-vm-metrics binary}")
port=${SMOKE_PORT:-18998}
state_dir=$(mktemp -d /tmp/kvm-metrics-ci-XXXXXXXX)
unit="${state_dir##*/}.service"

cleanup() {
    local status=$?
    if (( status != 0 )); then
        sudo -n journalctl -u "$unit" --no-pager -n 30 >&2 || true
    fi
    sudo -n systemctl stop "$unit" >/dev/null 2>&1 || true
    rm -rf "$state_dir"
}
trap cleanup EXIT

# Type=notify makes systemd-run wait for READY=1. Only this transient unit uses sudo.
sudo -n systemd-run --quiet --collect --unit="$unit" --service-type=notify \
    --uid="$(id -u)" --gid="$(id -g)" --property=NotifyAccess=main \
    --property=WatchdogSec=6s --property=TimeoutStartSec=20s --property=RuntimeMaxSec=60s \
    "$binary" --data-dir "$state_dir" --bind 127.0.0.1 --port "$port"

systemctl is-active --quiet "$unit"
test "$("$binary" --probe --port "$port")" = "$("$binary" --version)"
initial=$(systemctl show "$unit" --property=WatchdogTimestampMonotonic --value)
updated=$initial
for _ in {1..40}; do
    sleep .25
    updated=$(systemctl show "$unit" --property=WatchdogTimestampMonotonic --value)
    if [[ $updated =~ ^[0-9]+$ ]] && (( updated > initial )); then break; fi
done
[[ $updated =~ ^[0-9]+$ ]] && (( updated > initial )) || { echo "systemd did not receive a watchdog heartbeat" >&2; exit 1; }

sudo -n systemctl stop "$unit"
if systemctl is-active --quiet "$unit"; then
    echo "systemd still reports an active service after stop" >&2
    exit 1
fi
echo "systemd confirmed readiness, watchdog, HTTPS and shutdown"
