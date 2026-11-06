# -*- coding: utf-8 -*-
"""Интеграционные тесты HTTP API на настоящем сервере (127.0.0.1, случайный порт)."""
import http.client
import shutil
import io
import json
import socket
import ssl
import time
import unittest
import warnings
import zipfile
from urllib.parse import quote

from helpers import ServerFixture, kvm


class HttpBase(unittest.TestCase):
    TLS = False

    @classmethod
    def setUpClass(cls):
        cls.srv = ServerFixture(tls=cls.TLS)

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def conn(self):
        if self.TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection("127.0.0.1", self.srv.port, timeout=10, context=ctx)
        return http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)

    def request(self, method, path, body=None, headers=None):
        conn = self.conn()
        hdrs = dict(headers or {})
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def get_json(self, path):
        resp, data = self.request("GET", path)
        return resp, json.loads(data.decode("utf-8"))

    def restart(self, key, password, headers=None, raw=None):
        hdrs = {"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"}
        hdrs.update(headers or {})
        body = raw if raw is not None else json.dumps({"password": password}).encode("utf-8")
        resp, data = self.request("POST", "/api/services/%s/restart" % key, body=body, headers=hdrs)
        try:
            payload = json.loads(data.decode("utf-8"))
        except ValueError:
            payload = None
        return resp.status, payload


class PagesTest(HttpBase):
    def test_index_defaults(self):
        resp, data = self.request("GET", "/")
        self.assertEqual(resp.status, 200)
        html = data.decode("utf-8")
        self.assertIn('<html lang="ru" data-theme="dark">', html)
        self.assertIn("kvm-test.local", html)
        self.assertIn("/static/app.js?v=", html)
        self.assertEqual(resp.getheader("Cache-Control"), "no-cache, no-store, must-revalidate")
        self.assertIn("script-src 'self'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Server"), "kvm-metrics")

    def test_index_query_params_compatible_with_v1(self):
        resp, data = self.request("GET", "/?lang=en&theme=light")
        html = data.decode("utf-8")
        self.assertIn('<html lang="en" data-theme="light">', html)
        self.assertIn("Kaspersky VM | Monitoring", html)
        cookies = resp.msg.get_all("Set-Cookie")
        self.assertTrue(any(c.startswith("kvm_lang=en") for c in cookies))
        self.assertTrue(any(c.startswith("kvm_theme=light") and "SameSite=Strict" in c for c in cookies))

    def test_index_from_cookie_and_invalid_values(self):
        _, data = self.request("GET", "/", headers={"Cookie": "kvm_lang=en; kvm_theme=light"})
        self.assertIn('lang="en" data-theme="light"', data.decode("utf-8"))
        resp, data = self.request("GET", "/?lang=<script>&theme=evil")
        self.assertIn('lang="ru" data-theme="dark"', data.decode("utf-8"))
        self.assertIsNone(resp.getheader("Set-Cookie"))

    def test_static_assets_and_etag(self):
        for path, ctype in (("/static/app.js", "application/javascript"), ("/static/app.css", "text/css"),
                            ("/favicon.svg", "image/svg+xml")):
            resp, data = self.request("GET", path)
            self.assertEqual(resp.status, 200, path)
            self.assertTrue(resp.getheader("Content-Type").startswith(ctype))
            etag = resp.getheader("ETag")
            self.assertTrue(etag)
            resp2, data2 = self.request("GET", path, headers={"If-None-Match": etag})
            self.assertEqual(resp2.status, 304)
            self.assertEqual(data2, b"")

    def test_font_served(self):
        resp, data = self.request("GET", "/font")
        if self.srv.app.font is None:
            self.assertEqual(resp.status, 404)
            return
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "font/ttf")
        self.assertEqual(data[:4], b"\x00\x01\x00\x00")
        self.assertIn("max-age", resp.getheader("Cache-Control"))

    def test_head(self):
        resp, data = self.request("HEAD", "/healthz")
        self.assertEqual(resp.status, 200)
        self.assertEqual(data, b"")

    def test_healthz(self):
        resp, payload = self.get_json("/healthz")
        self.assertEqual(payload, {"ok": True, "version": kvm.__version__})

    def test_unknown_paths(self):
        resp, _ = self.request("GET", "/nope")
        self.assertEqual(resp.status, 404)
        resp, payload = self.get_json("/api/nope")
        self.assertEqual(resp.status, 404)
        self.assertEqual(payload["error"], "not_found")

    def test_methods_not_allowed(self):
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            resp, _ = self.request(method, "/")
            self.assertEqual(resp.status, 405, method)
        resp, payload = self.get_json("/api/status")
        resp, _ = self.request("POST", "/api/status", body=b"{}")
        self.assertEqual(resp.status, 404)

    def test_keep_alive_multiple_requests(self):
        conn = self.conn()
        for _ in range(3):
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            resp.read()
        conn.close()


class StatusApiTest(HttpBase):
    def test_status_shape(self):
        resp, data = self.get_json("/api/status")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertEqual(len(data["services"]), 6)
        self.assertEqual(data["host"], "kvm-test.local")
        self.assertEqual(data["auth"], {"restart": "ok"})
        for key in ("os_name", "cpu_threads", "memory", "uptime_sec"):
            self.assertIn(key, data["system"])
        svc = data["services"][0]
        for key in ("key", "unit", "desc_ru", "desc_en", "state", "pid", "memory_bytes", "uptime_sec", "restart"):
            self.assertIn(key, svc)
        self.assertTrue(data["ports"])

    def test_runner_crash_returns_500_without_details(self):
        self.srv.collector.invalidate()
        self.srv.fake.broken = True
        try:
            resp, payload = self.get_json("/api/status")
        finally:
            self.srv.fake.broken = False
        self.assertEqual(resp.status, 500)
        self.assertEqual(payload, {"ok": False, "error": "internal_error"})


class LogsApiTest(HttpBase):
    def test_index(self):
        _, data = self.get_json("/api/logs")
        files = dict((f["key"], f) for f in data["files"])
        self.assertTrue(files["scanner"]["exists"])
        self.assertFalse(files["missing"]["exists"])
        self.assertEqual(len(data["journals"]), 6)
        self.assertEqual([r["name"] for r in data["reports"]][0], "kaspersky-vm-services-state_28_10_2026.json")

    def test_tail_default_50(self):
        resp, data = self.get_json("/api/logs/file/scanner")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(data["lines"]), 50)
        self.assertTrue(data["lines"][-1].endswith("task 300 processed <b>&amp;"))
        self.assertTrue(data["has_more"])
        self.assertEqual(data["requested"], 50)
        # чтение выполняется командой tail на сервере (сервис работает от root)
        self.assertEqual(data["command"], "tail -n 50 -- " + self.srv.log_path)
        self.assertIn(["tail", "-n", "50", "--", self.srv.log_path], self.srv.fake.calls)

    def test_tail_lines_param_and_clamp(self):
        _, data = self.get_json("/api/logs/file/scanner?lines=7")
        self.assertEqual(len(data["lines"]), 7)
        _, data = self.get_json("/api/logs/file/scanner?lines=999999")
        self.assertEqual(data["requested"], kvm.TAIL_MAX)
        self.assertEqual(len(data["lines"]), 300)
        _, data = self.get_json("/api/logs/file/scanner?lines=abc")
        self.assertEqual(data["requested"], 50)

    def test_tail_errors(self):
        resp, data = self.get_json("/api/logs/file/missing")
        self.assertEqual(resp.status, 404)
        self.assertEqual(data["error"], "file_not_found")
        self.assertTrue(data["command"].startswith("tail -n 50 -- "))
        resp, data = self.get_json("/api/logs/file/unknown")
        self.assertEqual(resp.status, 404)
        self.assertEqual(data["error"], "unknown_log")
        resp, _ = self.request("GET", "/api/logs/file/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(resp.status, 404)

    def test_journal(self):
        resp, data = self.get_json("/api/logs/journal/scanner")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(data["lines"]), 50)
        self.assertEqual(data["kind"], "journal")
        call = [c for c in self.srv.fake.calls if c[0] == "journalctl"][-1]
        self.assertEqual(call[:5], ["journalctl", "-u", "kaspersky-vm-scanner.service", "-n", "50"])
        resp, data = self.get_json("/api/logs/journal/nope")
        self.assertEqual(resp.status, 404)

    def test_report_download(self):
        name = "kaspersky-vm-services-state_27_10_2026.json"
        resp, data = self.request("GET", "/log?file=" + name)
        self.assertEqual(resp.status, 200)
        self.assertIn('filename="%s"' % name, resp.getheader("Content-Disposition"))
        self.assertTrue(data.startswith(b'{"report": "kaspersky-vm-services-state"'))
        for bad in ("../../etc/passwd", "kaspersky-vm-services-state_/../../../etc/passwd", "", "%2e%2e%2fetc"):
            resp, _ = self.request("GET", "/log?file=" + bad)
            self.assertEqual(resp.status, 404, bad)

    def test_archive_json_encoded(self):
        # В исходной версии JSON из encodeURIComponent не декодировался и запрос падал с 500.
        names = ["kaspersky-vm-services-state_26_10_2026.json", "kaspersky-vm-services-state_28_10_2026.json",
                 "../etc/passwd"]
        resp, data = self.request("GET", "/logs-archive?files=" + quote(json.dumps(names)))
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "application/zip")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            self.assertEqual(sorted(zf.namelist()), sorted(names[:2]))

    def test_archive_comma_list_and_empty(self):
        resp, _ = self.request("GET", "/logs-archive?files=kaspersky-vm-services-state_26_10_2026.json,x")
        self.assertEqual(resp.status, 200)
        resp, _ = self.request("GET", "/logs-archive?files=" + quote('["nope"]'))
        self.assertEqual(resp.status, 404)
        resp, _ = self.request("GET", "/logs-archive")
        self.assertEqual(resp.status, 404)


class RestartApiTest(HttpBase):
    def setUp(self):
        self.srv.throttle.success("127.0.0.1")

    def wait_restart(self, key, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, data = self.get_json("/api/status")
            svc = [s for s in data["services"] if s["key"] == key][0]
            if svc["restart"] and not svc["restart"]["in_progress"]:
                return svc
            time.sleep(0.1)
        self.fail("restart did not finish")

    def test_success_flow(self):
        status, payload = self.restart("vms", ServerFixture.PASSWORD)
        self.assertEqual(status, 202)
        self.assertEqual(payload, {"ok": True, "key": "vms", "unit": "kaspersky-vm-vms.service"})
        _, data = self.get_json("/api/status")
        svc = [s for s in data["services"] if s["key"] == "vms"][0]
        self.assertTrue(svc["restart"]["in_progress"])
        self.assertIn(svc["state"], ("activating", "active"))
        status, payload = self.restart("vms", ServerFixture.PASSWORD)
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "in_progress")
        done = self.wait_restart("vms")
        self.assertEqual(done["restart"]["result"], "ok")
        self.assertEqual(done["state"], "active")
        self.assertEqual(done["pid"], 4242)

    def test_failed_start_reported(self):
        self.srv.fake.crash_on_start.add("kaspersky-vm-worker.service")
        try:
            status, _ = self.restart("worker", ServerFixture.PASSWORD)
            self.assertEqual(status, 202)
            done = self.wait_restart("worker")
            self.assertEqual(done["restart"]["result"], "failed")
            self.assertEqual(done["state"], "failed")
        finally:
            self.srv.fake.crash_on_start.discard("kaspersky-vm-worker.service")

    def test_systemctl_error(self):
        self.srv.fake.fail_restart.add("kaspersky-vm-publicapi.service")
        try:
            status, payload = self.restart("publicapi", ServerFixture.PASSWORD)
        finally:
            self.srv.fake.fail_restart.discard("kaspersky-vm-publicapi.service")
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "systemctl_failed")
        self.assertIn("Access denied", payload["message"])

    def test_bad_password_and_lockout(self):
        status, payload = self.restart("scanner", "wrong")
        self.assertEqual((status, payload["error"], payload["attempts_left"]), (401, "bad_password", 2))
        status, payload = self.restart("scanner", "wrong2")
        self.assertEqual(payload["attempts_left"], 1)
        status, payload = self.restart("scanner", "wrong3")
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"], "locked")
        self.assertGreater(payload["retry_after"], 200)
        status, payload = self.restart("scanner", ServerFixture.PASSWORD)
        self.assertEqual(status, 429, "даже верный пароль не принимается во время блокировки")
        self.assertFalse([c for c in self.srv.fake.calls if c[:2] == ["systemctl", "restart"]
                          and c[-1] == "kaspersky-vm-scanner.service"])

    def test_csrf_protection(self):
        status, payload = self.restart("scanner", ServerFixture.PASSWORD, headers={"X-Requested-With": ""})
        self.assertEqual((status, payload["error"]), (403, "csrf"))
        status, payload = self.restart("scanner", ServerFixture.PASSWORD, headers={"Origin": "https://evil.example"})
        self.assertEqual((status, payload["error"]), (403, "csrf"))

    def test_same_origin_header_accepted(self):
        origin = "http://127.0.0.1:%d" % self.srv.port
        status, _ = self.restart("privateapi", ServerFixture.PASSWORD, headers={"Origin": origin})
        self.assertEqual(status, 202)
        self.wait_restart("privateapi")

    def test_bad_requests(self):
        status, payload = self.restart("unknown", ServerFixture.PASSWORD)
        self.assertEqual((status, payload["error"]), (404, "unknown_service"))
        status, payload = self.restart("scanner", None, raw=b"not json")
        self.assertEqual((status, payload["error"]), (400, "bad_request"))
        status, payload = self.restart("scanner", None, raw=b"[1,2]")
        self.assertEqual(status, 400)
        status, payload = self.restart("scanner", None, raw=json.dumps({"password": "x" * 5000}).encode())
        self.assertEqual(status, 400)
        status, payload = self.restart("scanner", None, raw=json.dumps({"password": 123}).encode())
        self.assertEqual((status, payload["error"]), (401, "bad_password"))


class RestartAuthStatesTest(unittest.TestCase):
    def check(self, shadow_hash, expected_status, expected_error, expected_auth):
        srv = ServerFixture(shadow_hash=shadow_hash)
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("POST", "/api/services/scanner/restart", body=b'{"password":"x"}',
                         headers={"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"})
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, expected_status)
            self.assertEqual(payload["error"], expected_error)
            conn.request("GET", "/api/status")
            status = json.loads(conn.getresponse().read().decode("utf-8"))
            self.assertEqual(status["auth"]["restart"], expected_auth)
            conn.close()
        finally:
            srv.close()

    def test_insecure_transport_blocks_password(self):
        srv = ServerFixture()
        try:
            srv.app.insecure = True
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("POST", "/api/services/scanner/restart", body=b'{"password":"%s"}' % ServerFixture.PASSWORD.encode(),
                         headers={"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 403)
            self.assertEqual(json.loads(resp.read().decode("utf-8"))["error"], "insecure_transport")
            conn.request("GET", "/api/status")
            self.assertEqual(json.loads(conn.getresponse().read().decode("utf-8"))["auth"]["restart"], "insecure")
            conn.close()
            self.assertFalse([c for c in srv.fake.calls if c[:2] == ["systemctl", "restart"]])
        finally:
            srv.close()

    def test_root_locked(self):
        self.check("!", 403, "root_locked", "locked")

    def test_shadow_unavailable(self):
        srv = ServerFixture()
        try:
            srv.auth.shadow_paths = ("/nonexistent/shadow",)
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            conn.request("POST", "/api/services/scanner/restart", body=b'{"password":"x"}',
                         headers={"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 503)
            self.assertEqual(json.loads(resp.read().decode("utf-8"))["error"], "auth_unavailable")
            conn.close()
        finally:
            srv.close()


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class TlsTest(HttpBase):
    TLS = True

    def test_https_status(self):
        resp, data = self.get_json("/api/status")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(data["services"]), 6)

    def test_old_tls_rejected(self):
        if not hasattr(ssl, "TLSVersion"):
            self.skipTest("ssl.TLSVersion unavailable")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # novermin (тест пропускается без TLSVersion)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1  # novermin
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1  # novermin
        except (ValueError, ssl.SSLError):
            self.skipTest("TLS 1.1 not supported by local OpenSSL")
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) as raw:
            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                with ctx.wrap_socket(raw) as tls:
                    tls.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
                    tls.recv(10)

    def test_stalled_client_does_not_block_server(self):
        # В исходной версии рукопожатие шло в accept() однопоточного сервера:
        # один «молчащий» TCP-клиент блокировал дашборд для всех.
        stalled = [socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) for _ in range(3)]
        try:
            started = time.time()
            resp, _ = self.get_json("/healthz")
            self.assertEqual(resp.status, 200)
            self.assertLess(time.time() - started, 3)
        finally:
            for s in stalled:
                s.close()

    def test_plain_http_to_tls_port_does_not_kill_server(self):
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
            try:
                raw.recv(100)
            except OSError:
                pass
        resp, _ = self.get_json("/healthz")
        self.assertEqual(resp.status, 200)


class ConcurrencyTest(HttpBase):
    def test_parallel_requests(self):
        import threading
        errors = []

        def worker():
            try:
                for _ in range(5):
                    resp, _ = self.get_json("/api/status")
                    if resp.status != 200:
                        errors.append(resp.status)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])
        shows = [c for c in self.srv.fake.calls if c[:2] == ["systemctl", "show"]]
        self.assertLess(len(shows), 50, "кэш должен схлопывать одновременные запросы")


if __name__ == "__main__":
    unittest.main()
