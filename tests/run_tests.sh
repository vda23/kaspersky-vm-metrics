#!/bin/bash
# Запуск всех тестов:
#   bash tests/run_tests.sh [python3]              — тесты
#   bash tests/run_tests.sh --coverage [python3]   — тесты + отчёт о покрытии с порогами
# UI-тесты требуют playwright (pip install playwright && playwright install chromium), иначе пропускаются.
set -e
COVERAGE=0
if [ "${1:-}" = "--coverage" ]; then COVERAGE=1; shift; fi
PY="${1:-python3}"
[ $# -gt 0 ] && shift
cd "$(dirname "$0")"
"$PY" ../tools/embed_assets.py --check

if [ "$COVERAGE" = 0 ]; then
    exec "$PY" -m unittest discover -s . -p 'test_*.py' "$@"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export KVM_SH_TRACE="$WORK/sh.trace" KVM_JS_COVERAGE="$WORK/js.json"
: > "$KVM_SH_TRACE"
"$PY" -m coverage run --data-file="$WORK/py.coverage" --include='*/kaspersky-vm-metrics.py' \
    -m unittest discover -s . -p 'test_*.py' "$@"
"$PY" ../tools/coverage_report.py --py-data "$WORK/py.coverage" --js "$KVM_JS_COVERAGE" \
    --sh-trace "$KVM_SH_TRACE" --min-py "${MIN_PY:-95}" --min-js "${MIN_JS:-90}" --min-sh "${MIN_SH:-100}"
