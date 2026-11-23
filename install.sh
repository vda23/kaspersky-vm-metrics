#!/usr/bin/env bash
# Stable entry point for offline packages and existing administration procedures.
set -euo pipefail
package_dir=$(cd "$(dirname "$0")" && pwd)
program="$package_dir/kaspersky-vm-metrics"
if [ ! -x "$program" ]; then
    echo 'Распакуйте пакет для архитектуры сервера. Для сборки из исходников выполните make package.' >&2
    exit 1
fi
if [ -f "$package_dir/SHA256SUMS" ]; then
    expected=$(awk '$2 == "kaspersky-vm-metrics" {print $1}' "$package_dir/SHA256SUMS")
    actual=$(sha256sum "$program")
    if [ "$expected" != "${actual%% *}" ]; then
        echo 'Контрольная сумма исполняемого файла не совпадает.' >&2
        exit 1
    fi
fi
exec "$program" --installer "$@"
