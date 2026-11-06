#!/bin/bash
#
# Сборка архива для установки на сервер:
#   bash tools/build_dist.sh   ->   dist/kaspersky-vm-metrics-<версия>.tar.gz
#
# Шрифт и официальные логотипы не хранятся в git: положите их в assets/ перед сборкой
# (KasperskySans-Regular.ttf, logo.svg / logo-dark.svg / logo-light.svg, favicon.svg).
# Если их нет, архив собирается без них — интерфейс использует системный шрифт.
#
# На сервере:
#   tar xzf kaspersky-vm-metrics-<версия>.tar.gz
#   cd kaspersky-vm-metrics-<версия>
#   sudo bash install.sh
#
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
PY="${PYTHON:-python3}"
ASSETS_DIR="${ASSETS_DIR:-$ROOT/assets}"

"$PY" "$ROOT/tools/embed_assets.py" --check
VERSION="$("$PY" "$ROOT/kaspersky-vm-metrics.py" --version)"
NAME="kaspersky-vm-metrics-$VERSION"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/$NAME"
cp "$ROOT/install.sh" "$ROOT/kaspersky-vm-metrics.py" "$ROOT/README.md" "$STAGE/$NAME/"
for asset in KasperskySans-Regular.ttf logo.svg logo.png logo-dark.svg logo-dark.png \
             logo-light.svg logo-light.png favicon.svg favicon.png; do
    if [ -f "$ASSETS_DIR/$asset" ]; then
        cp "$ASSETS_DIR/$asset" "$STAGE/$NAME/"
    fi
done
[ -f "$STAGE/$NAME/KasperskySans-Regular.ttf" ] || echo "Внимание: $ASSETS_DIR/KasperskySans-Regular.ttf не найден — архив без шрифта" >&2
echo "$VERSION" > "$STAGE/$NAME/VERSION"
chmod 644 "$STAGE/$NAME"/*
chmod 755 "$STAGE/$NAME/install.sh" "$STAGE/$NAME/kaspersky-vm-metrics.py"
(cd "$STAGE/$NAME" && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name README.md \
    -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)

mkdir -p "$OUT_DIR"
tar -C "$STAGE" --owner=0 --group=0 -czf "$OUT_DIR/$NAME.tar.gz" "$NAME"
echo "$OUT_DIR/$NAME.tar.gz"
