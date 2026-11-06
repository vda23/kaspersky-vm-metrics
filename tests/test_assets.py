# -*- coding: utf-8 -*-
"""Статические проверки веб-интерфейса: синхронизация, CSP, i18n, синтаксис JS."""
import os
import re
import shutil
import subprocess
import sys
import unittest

from helpers import ROOT, kvm

WEB = os.path.join(ROOT, "web")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class AssetsTest(unittest.TestCase):
    def test_embedded_assets_in_sync(self):
        res = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "embed_assets.py"), "--check"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))
        self.assertEqual(kvm.APP_JS, read("web/app.js"))
        self.assertEqual(kvm.APP_CSS, read("web/app.css"))
        self.assertEqual(kvm.INDEX_HTML, read("web/index.html"))

    def test_html_is_csp_compliant(self):
        html = read("web/index.html")
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>", "inline <script> запрещён CSP")
        self.assertNotRegex(html, r"\sstyle\s*=", "атрибуты style= запрещены CSP")
        self.assertNotRegex(html, r"\son[a-z]+\s*=", "inline-обработчики запрещены CSP")
        self.assertNotIn("<style", html)

    def test_js_does_not_use_dangerous_sinks(self):
        js = read("web/app.js")
        for pattern in (r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"insertAdjacentHTML", r"document\.write",
                        r"\beval\(", r"new Function\("):
            self.assertNotRegex(js, pattern)
        self.assertNotIn("setAttribute('style'", js)

    def test_template_placeholders(self):
        html = kvm.render_index(kvm.build_assets(), "en", "light", "h<o>st").decode("utf-8")
        self.assertNotIn("{{", html)
        self.assertIn("h&lt;o&gt;st", html)
        self.assertIn('data-theme="light"', html)

    def test_i18n_keys_match(self):
        js = read("web/app.js")
        ru = js[js.index("ru: {"):js.index("en: {")]
        en = js[js.index("en: {"):js.index("var STATES")]
        key_re = re.compile(r"(?:^|,)\s*'?([a-zA-Z_][\w-]*)'?:\s*'", re.M)
        ru_keys, en_keys = set(key_re.findall(ru)), set(key_re.findall(en))
        self.assertEqual(ru_keys - en_keys, set())
        self.assertEqual(en_keys - ru_keys, set())
        html = read("web/index.html")
        used = set(re.findall(r'data-i18n(?:-[a-z]+)?="([^"]+)"', html))
        self.assertEqual(used - ru_keys, set())
        used_js = set(k for k in re.findall(r"\bt\('([\w-]+)'", js) if not k.endswith("_"))
        self.assertEqual(used_js - ru_keys, set(), "ключи, используемые в t('...'), должны существовать")
        for state in ("active", "activating", "deactivating", "reloading", "inactive", "failed",
                      "not-found", "masked", "unknown"):
            self.assertIn("st_" + state, ru_keys)

    def test_html_ids_used_by_js_exist(self):
        js, html = read("web/app.js"), read("web/index.html")
        ids = set(re.findall(r"\$\('([\w-]+)'\)", js))
        dynamic = {"root-pw", "root-pw-err"}
        missing = sorted(i for i in ids - dynamic if 'id="%s"' % i not in html)
        self.assertEqual(missing, [])

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_js_syntax(self):
        res = subprocess.run(["node", "--check", os.path.join(WEB, "app.js")],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))

    def test_font_present(self):
        path = os.path.join(ROOT, "assets", kvm.FONT_NAME + ".ttf")
        if not os.path.exists(path):
            self.skipTest("шрифт не хранится в git: положите его в assets/")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(4), b"\x00\x01\x00\x00")
        self.assertIn('url("/font")', read("web/app.css"))
        self.assertIn('"KasperskySans"', read("web/app.css"))


class CompatibilityTest(unittest.TestCase):
    """Код должен оставаться совместимым с Python 3.5 (Astra Linux CE 2.12)."""

    def test_no_py36_syntax(self):
        import ast
        tree = ast.parse(read("kaspersky-vm-metrics.py"))
        problems = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                problems.append("f-string at line %d" % node.lineno)
            elif isinstance(node, ast.AnnAssign):
                problems.append("variable annotation at line %d" % node.lineno)
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in ("capture_output", "text"):
                        problems.append("%s= at line %d" % (kw.arg, node.lineno))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                if "secrets" in names or "ThreadingHTTPServer" in names:
                    problems.append("py3.6+/3.7+ import at line %d" % node.lineno)
            elif isinstance(node, (ast.AsyncFunctionDef, ast.Await)):
                problems.append("async at line %d" % node.lineno)
        self.assertEqual(problems, [])

    @unittest.skipUnless(shutil.which("vermin"), "vermin not installed")
    def test_vermin_minimum_35(self):
        res = subprocess.run(["vermin", "-t=3.5-", "--no-tips", "--violations",
                              os.path.join(ROOT, "kaspersky-vm-metrics.py")],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
