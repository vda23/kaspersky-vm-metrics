# -*- coding: utf-8 -*-
"""Официальные логотипы (необязательные файлы) и загрузка процессора."""
import http.client
import os
import unittest

from helpers import MONO, FakeSystem, ServerFixture, TempDir, kvm

SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>'


class AssetLookupTest(unittest.TestCase):
    def test_find_asset_order(self):
        with TempDir() as d:
            os.makedirs(os.path.join(d, "assets"))
            self.assertIsNone(kvm.find_asset("logo.svg", dirs=(d, os.path.join(d, "assets"))))
            with open(os.path.join(d, "assets", "logo.svg"), "wb") as fh:
                fh.write(SVG)
            self.assertEqual(kvm.find_asset("logo.svg", dirs=(d, os.path.join(d, "assets"))),
                             os.path.join(d, "assets", "logo.svg"))
            with open(os.path.join(d, "logo.svg"), "wb") as fh:
                fh.write(SVG)
            self.assertEqual(kvm.find_asset("logo.svg", dirs=(d, os.path.join(d, "assets"))),
                             os.path.join(d, "logo.svg"), "файл рядом со скриптом важнее assets/")

    def test_load_static(self):
        with TempDir() as d:
            path = os.path.join(d, "x.svg")
            with open(path, "wb") as fh:
                fh.write(SVG)
            item = kvm.load_static(path, "image/svg+xml")
            self.assertEqual(item["data"], SVG)
            self.assertEqual(item["etag"], kvm.etag_for(SVG))


class BrandMarkupTest(unittest.TestCase):
    def test_default_mark(self):
        self.assertEqual(kvm.brand_markup({}), kvm.BRAND_MARK_DEFAULT)

    def test_single_logo_for_both_themes(self):
        html = kvm.brand_markup({"logo": {}})
        self.assertIn('class="brand-logo brand-logo-dark" src="/brand/logo"', html)
        self.assertIn('class="brand-logo brand-logo-light" src="/brand/logo"', html)

    def test_theme_specific_logos(self):
        html = kvm.brand_markup({"logo-dark": {}, "logo-light": {}, "logo": {}})
        self.assertIn('src="/brand/logo-dark"', html)
        self.assertIn('src="/brand/logo-light"', html)
        self.assertNotIn('src="/brand/logo"', html)

    def test_render_index_with_brand(self):
        assets = kvm.build_assets()
        plain = kvm.render_index(assets, "ru", "dark", "h").decode()
        self.assertIn('href="/favicon.svg"', plain)
        self.assertIn('name="static-favicon" content="0"', plain)
        self.assertIn("brand-mark", plain)
        branded = kvm.render_index(assets, "ru", "dark", "h", {"logo": {}, "favicon": {}}).decode()
        self.assertIn('href="/brand/favicon"', branded)
        self.assertIn('name="static-favicon" content="1"', branded)
        self.assertIn("brand-logo", branded)
        self.assertNotIn("{{", branded)


class BrandHttpTest(unittest.TestCase):
    def test_served_when_present(self):
        srv = ServerFixture()
        try:
            srv.app.brand = {"logo": kvm.load_static(self._svg(srv.tmp), "image/svg+xml")}
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("GET", "/brand/logo")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "image/svg+xml")
            self.assertEqual(resp.read(), SVG)
            conn.request("GET", "/brand/favicon")
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.request("GET", "/brand/../../etc/passwd")
            resp = conn.getresponse()
            resp.read()
            self.assertEqual(resp.status, 404)
            conn.request("GET", "/")
            html = conn.getresponse().read().decode()
            self.assertIn('src="/brand/logo"', html)
            conn.close()
        finally:
            srv.close()

    def test_app_loads_branding_from_assets_dir(self):
        with TempDir() as d:
            os.makedirs(os.path.join(d, "assets"))
            with open(os.path.join(d, "assets", "logo-dark.svg"), "wb") as fh:
                fh.write(SVG)
            with open(os.path.join(d, "favicon.png"), "wb") as fh:
                fh.write(b"\x89PNG\r\n\x1a\nfake")
            original = kvm.ASSET_DIRS
            kvm.ASSET_DIRS = (d, os.path.join(d, "assets"))
            try:
                fake = FakeSystem()
                app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO), runner=fake)
            finally:
                kvm.ASSET_DIRS = original
            self.assertEqual(sorted(app.brand), ["favicon", "logo-dark"])
            self.assertEqual(app.brand["favicon"]["type"], "image/png")

    @staticmethod
    def _svg(directory):
        path = os.path.join(directory, "logo.svg")
        with open(path, "wb") as fh:
            fh.write(SVG)
        return path


class CpuUsageTest(unittest.TestCase):
    def test_collector_cpu_percent_between_polls(self):
        with TempDir() as d:
            stat = os.path.join(d, "stat")
            for name, text in (("meminfo", "MemTotal: 1000 kB\nMemFree: 500 kB\n"), ("uptime", "100.0 50.0\n")):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(text)
            with open(stat, "w") as fh:
                fh.write("cpu  100 0 100 800 0 0 0 0\n")
            collector = kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), proc_root=d, clock=MONO)
            first = collector.system_info()
            self.assertEqual(first["cpu_percent"], None, "за 0,25 с счётчики не изменились")
            with open(stat, "w") as fh:
                fh.write("cpu  175 0 125 900 0 0 0 0\n")
            self.assertEqual(collector.system_info()["cpu_percent"], 50.0)
            with open(stat, "w") as fh:
                fh.write("cpu  175 0 125 1000 0 0 0 0\n")
            self.assertEqual(collector.system_info()["cpu_percent"], 0.0)

    def test_missing_proc_stat(self):
        with TempDir() as d:
            collector = kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), proc_root=d, clock=MONO)
            self.assertIsNone(collector.cpu_usage())


if __name__ == "__main__":
    unittest.main()
