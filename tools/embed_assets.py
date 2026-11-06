#!/usr/bin/env python3
"""
Встраивает web/index.html, web/app.css, web/app.js, web/favicon.svg и логотип web/brand.png
(base64) в kaspersky-vm-metrics.py, чтобы сервис оставался одним файлом.

    python3 tools/embed_assets.py          # обновить скрипт
    python3 tools/embed_assets.py --check  # проверить, что скрипт синхронизирован (для CI)
"""
import base64
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "kaspersky-vm-metrics.py")
ASSETS = (
    ("INDEX_HTML", "web/index.html"),
    ("APP_CSS", "web/app.css"),
    ("APP_JS", "web/app.js"),
    ("FAVICON_SVG", "web/favicon.svg"),
)
BINARY_ASSETS = (
    ("BRAND_PNG_B64", "web/brand.png"),  # логотип в шапке и значок вкладки
)
BEGIN = "# @@ASSETS-BEGIN@@ (сгенерировано tools/embed_assets.py из каталога web/, не редактировать вручную)"
END = "# @@ASSETS-END@@"
BLOCK_RE = re.compile(r"# @@ASSETS-BEGIN@@.*?# @@ASSETS-END@@|#@@ASSETS@@", re.S)


def build_block():
    parts = [BEGIN]
    for name, rel in ASSETS:
        with io.open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            text = fh.read()
        if "'''" in text or text.endswith("\\"):
            raise SystemExit("%s: содержит ''' или оканчивается на \\ — нельзя встроить как r-строку" % rel)
        parts.append("%s = r'''%s'''" % (name, text))
    for name, rel in BINARY_ASSETS:
        with open(os.path.join(ROOT, rel), "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        lines = [data[i:i + 100] for i in range(0, len(data), 100)]
        parts.append("%s = (\n%s\n)" % (name, "\n".join('    "%s"' % line for line in lines)))
    parts.append(END)
    return "\n\n".join(parts)


def main():
    with io.open(SCRIPT, encoding="utf-8") as fh:
        source = fh.read()
    if not BLOCK_RE.search(source):
        raise SystemExit("маркер блока ассетов не найден в " + SCRIPT)
    block = build_block()
    updated = BLOCK_RE.sub(lambda _m: block, source, count=1)
    if "--check" in sys.argv:
        if updated != source:
            print("kaspersky-vm-metrics.py не синхронизирован с web/: запустите tools/embed_assets.py")
            return 1
        print("OK: ассеты синхронизированы")
        return 0
    with io.open(SCRIPT, "w", encoding="utf-8") as fh:
        fh.write(updated)
    print("Ассеты встроены в " + os.path.basename(SCRIPT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
