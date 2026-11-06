#!/usr/bin/env python3
"""
Сводка покрытия тестами: Python (coverage.py), JavaScript (V8 через Playwright),
функции install.sh (трассировка bash). Вызывается из tests/run_tests.sh --coverage.

    python3 tools/coverage_report.py --py-data .coverage --js js.json --sh-trace sh.trace \
        --min-py 95 --min-js 90 --min-sh 100
"""
import argparse
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def python_coverage(data_file):
    try:
        import coverage
    except ImportError:
        return None, "coverage.py не установлен (pip install coverage)"
    cov = coverage.Coverage(data_file=data_file)
    cov.load()
    out = io.StringIO()
    percent = cov.report(include=["*kaspersky-vm-metrics.py"], show_missing=True, file=out)
    return percent, out.getvalue().strip()


def js_coverage(path):
    if not path or not os.path.exists(path):
        return None, "нет данных (UI-тесты не запускались: нужен playwright + chromium)"
    with open(path) as fh:
        data = json.load(fh)
    return data["percent"], "%d из %d символов app.js выполнены" % (data["covered"], data["total"])


def sh_coverage(trace_path):
    with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as fh:
        functions = re.findall(r"^([a-z_]+)\(\) \{", fh.read(), re.M)
    called = set()
    if trace_path and os.path.exists(trace_path):
        with open(trace_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                match = re.match(r"^\++([a-z_]+)\|", line)
                if match:
                    called.add(match.group(1))
    missing = [f for f in functions if f not in called]
    percent = 100.0 * (len(functions) - len(missing)) / max(len(functions), 1)
    detail = "%d из %d функций" % (len(functions) - len(missing), len(functions))
    if missing:
        detail += "; не вызывались: " + ", ".join(missing)
    return percent, detail


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--py-data")
    parser.add_argument("--js")
    parser.add_argument("--sh-trace")
    parser.add_argument("--min-py", type=float, default=0)
    parser.add_argument("--min-js", type=float, default=0)
    parser.add_argument("--min-sh", type=float, default=0)
    args = parser.parse_args()

    rows = []
    failed = False
    for name, (percent, detail), minimum in (
            ("Python   kaspersky-vm-metrics.py", python_coverage(args.py_data), args.min_py),
            ("JS       web/app.js", js_coverage(args.js), args.min_js),
            ("Bash     install.sh (функции)", sh_coverage(args.sh_trace), args.min_sh)):
        status = "—"
        if percent is not None:
            ok = percent + 1e-9 >= minimum
            failed = failed or not ok
            status = "%.1f%% %s" % (percent, "OK" if ok else "< %.0f%% FAIL" % minimum)
        rows.append((name, status, detail))
    print("\nПокрытие тестами")
    print("=" * 60)
    for name, status, detail in rows:
        print("%-34s %s" % (name, status))
        if detail and not detail.startswith("Name"):
            print("    " + detail.replace("\n", "\n    "))
    print()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
