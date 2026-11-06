# -*- coding: utf-8 -*-
"""Пограничные случаи и обработка ошибок: запуск main(), фоновые задачи, HTTP-ветки."""
import http.client
import io
import json
import os
import socket
import sys
import threading
import time
import unittest
from datetime import datetime

from helpers import MONO, FakeSystem, ServerFixture, TempDir, kvm

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    mock = None


class LogFunctionTest(unittest.TestCase):
    def test_writes_to_stderr_with_prefix(self):
        real_log = getattr(kvm, "real_log", kvm.log)
        buf = io.StringIO()
        saved, sys.stderr = sys.stderr, buf
        try:
            real_log("value=%s", 42)
            real_log("plain")
        finally:
            sys.stderr = saved
        self.assertEqual(buf.getvalue(), "[kvm-metrics] value=42\n[kvm-metrics] plain\n")


class SmallBranchesTest(unittest.TestCase):
    def test_meminfo_non_numeric(self):
        self.assertEqual(kvm.parse_meminfo("MemTotal: abc kB\nMemFree: 5 kB\n"), {"MemFree": 5120})

    def test_cgroup_rss_without_cgroup(self):
        collector = kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), clock=MONO)
        self.assertIsNone(collector.cgroup_rss(""))
        self.assertIsNone(collector.cgroup_rss(None))

    def test_dated_line_scan_limit(self):
        with TempDir() as d:
            path = os.path.join(d, "a.log")
            with open(path, "wb") as fh:
                fh.write(b"x" * 100 + b"\n" + b"undated\n" * 50 + b"2026-11-03 10:00:00 late\n")
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                self.assertEqual(kvm._dated_line_at(fh, 0, size, scan_limit=200), (None, None))
                pos, day = kvm._dated_line_at(fh, 0, size)
            self.assertEqual(day.isoformat(), "2026-11-03")
            with open(path, "rb") as fh:
                self.assertEqual(kvm._dated_line_at(fh, size, size), (None, None))

    def test_report_with_invalid_date_sorted_last(self):
        with TempDir() as d:
            for name in ("kaspersky-vm-services-state_99_99_2026.json", "kaspersky-vm-services-state_01_11_2026.json"):
                open(os.path.join(d, name), "w").close()
            names = [r["name"] for r in kvm.list_reports(d)]
            self.assertEqual(names[-1], "kaspersky-vm-services-state_99_99_2026.json")

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_write_daily_report_cleans_temp_on_error(self):
        with TempDir() as d:
            fake = FakeSystem()
            app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO), runner=fake,
                          log_dir=d, log_files=[], settings_path=os.path.join(d, "settings.json"))
            with mock.patch.object(kvm.os, "rename", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    kvm.write_daily_report(app, d, datetime(2026, 11, 3, 19, 0))
            self.assertEqual(os.listdir(d), [], "временный файл удалён")

    def test_cleanup_missing_dir(self):
        self.assertEqual(kvm.cleanup_old_reports("/nonexistent/dir"), 0)

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_cleanup_ignores_vanished_file(self):
        with TempDir() as d:
            open(os.path.join(d, "kaspersky-vm-services-state_01_01_2020.json"), "w").close()
            with mock.patch.object(kvm.os.path, "getmtime", side_effect=OSError("gone")):
                self.assertEqual(kvm.cleanup_old_reports(d), 0)

    def test_certificate_failure_removes_partial_files(self):
        with TempDir() as d:
            cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")

            def runner(args, timeout=5, c_locale=True):
                if args[1] == "req":
                    open(cert + ".new", "w").close()
                    open(key + ".new", "w").close()
                    return kvm.CmdResult(1, "", "bad config")
                return kvm.CmdResult(1, "", "")
            self.assertFalse(kvm.generate_certificate("h", cert, key, runner=runner, force=True))
            self.assertEqual(os.listdir(d), [])

    def test_self_check_warns_when_crypt_missing(self):
        out = io.StringIO()
        original = kvm.system_crypt
        kvm.system_crypt = lambda word, salt: None
        try:
            self.assertEqual(kvm.self_check(out=out, runner=FakeSystem()), 0)
        finally:
            kvm.system_crypt = original
        self.assertIn("crypt(3) unavailable", out.getvalue())

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_system_crypt_handles_errors(self):
        saved = kvm._crypt_impl
        try:
            kvm._crypt_impl = mock.Mock(side_effect=ValueError("bad salt"))
            self.assertIsNone(kvm.system_crypt("x", "$6$a$"))
            kvm._crypt_impl = False
            self.assertIsNone(kvm.system_crypt("x", "$6$a$"))
        finally:
            kvm._crypt_impl = saved

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_load_crypt_without_libcrypt(self):
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "crypt":
                raise ImportError("removed")
            return real_import(name, *args, **kwargs)
        saved = sys.modules.pop("crypt", None)
        try:
            with mock.patch("builtins.__import__", side_effect=fake_import), \
                    mock.patch("ctypes.CDLL", side_effect=OSError("no lib")):
                self.assertIsNone(kvm._load_crypt())
        finally:
            if saved is not None:
                sys.modules["crypt"] = saved


class HttpBranchesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ServerFixture()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_font_missing(self):
        saved, self.srv.app.font = self.srv.app.font, None
        try:
            status, _ = self.get("/font")
        finally:
            self.srv.app.font = saved
        self.assertEqual(status, 404)

    def test_reports_api(self):
        status, body = self.get("/api/reports")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body.decode())["reports"]), 3)

    def test_log_glob_without_matches(self):
        saved = self.srv.app.log_files_by_key.get("missing")
        self.srv.app.log_files_by_key["missing"] = dict(saved, path=os.path.join(self.srv.tmp, "none-*.log"))
        try:
            status, body = self.get("/api/logs/file/missing")
        finally:
            self.srv.app.log_files_by_key["missing"] = saved
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body.decode())["error"], "file_not_found")

    def test_journal_error(self):
        self.srv.fake.journal["kaspersky-vm-vms.service"] = None
        original = self.srv.fake.__call__

        class Failing(object):
            def __call__(inner, args, timeout=5, c_locale=True):
                if args[0] == "journalctl":
                    return kvm.CmdResult(1, "", "No journal files were found.")
                return original(args, timeout, c_locale)
        saved, self.srv.app.runner = self.srv.app.runner, Failing()
        try:
            status, body = self.get("/api/logs/journal/vms")
        finally:
            self.srv.app.runner = saved
        self.assertEqual(status, 500)
        self.assertIn("No journal files", json.loads(body.decode())["message"])

    def test_archive_single_name_json(self):
        status, _ = self.get("/logs-archive?files=%22kaspersky-vm-services-state_26_10_2026.json%22")
        self.assertEqual(status, 200)

    def test_bad_password_delay(self):
        self.srv.app.fail_delay = 0.05
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
            started = time.time()
            conn.request("POST", "/api/services/scanner/restart", body=b'{"password":"nope"}',
                         headers={"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            self.assertEqual(resp.status, 401)
            self.assertGreaterEqual(time.time() - started, 0.05)
        finally:
            self.srv.app.fail_delay = 0
            self.srv.throttle.success("127.0.0.1")

    def test_connection_dropped_when_too_many_requests(self):
        time.sleep(0.3)  # потоки предыдущих запросов завершены и вернули свои слоты
        slots = self.srv.server._slots
        self.srv.server._slots = threading.BoundedSemaphore(1)
        self.srv.server._slots.acquire()
        try:
            sock = socket.create_connection(("127.0.0.1", self.srv.port), timeout=5)
            sock.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
            self.assertEqual(sock.recv(100), b"", "сервер закрыл соединение без ответа")
            sock.close()
        finally:
            self.srv.server._slots = slots
        status, _ = self.get("/healthz")
        self.assertEqual(status, 200)

    def test_handle_error_logs_unexpected(self):
        logged = []
        saved = kvm.log
        kvm.log = lambda msg, *args: logged.append(msg % args if args else msg)
        try:
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                self.srv.server.handle_error(None, ("10.0.0.1", 1))
            try:
                raise ConnectionResetError("reset")
            except ConnectionResetError:
                self.srv.server.handle_error(None, ("10.0.0.1", 1))
        finally:
            kvm.log = saved
        self.assertEqual(logged, ["request error from 10.0.0.1: boom"])


class BackgroundBranchesTest(unittest.TestCase):
    def run_loop(self, app, context=None, seconds=0.2):
        stop = threading.Event()
        th = threading.Thread(target=kvm.background_loop, args=(app, stop, context, 0.02))
        th.start()
        time.sleep(seconds)
        stop.set()
        th.join()

    def test_report_failure_is_logged_not_fatal(self):
        logged = []
        app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), clock=MONO),
                      runner=FakeSystem(), log_dir="/nonexistent/dir", log_files=[])
        saved_due, saved_log = kvm.report_due, kvm.log
        kvm.report_due = lambda now, last, log_dir=None, hour=19: True
        kvm.log = lambda msg, *args: logged.append(msg % args if args else msg)
        try:
            self.run_loop(app)
        finally:
            kvm.report_due, kvm.log = saved_due, saved_log
        self.assertTrue(any(m.startswith("daily report failed") for m in logged))

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_certificate_renewal(self):
        app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), clock=MONO),
                      runner=FakeSystem(), log_dir="/nonexistent", log_files=[])
        context = mock.Mock()
        logged = []
        with mock.patch.object(kvm, "report_due", return_value=False), \
                mock.patch.object(kvm, "certificate_needs_renewal", return_value=True), \
                mock.patch.object(kvm, "generate_certificate", return_value=True), \
                mock.patch.object(kvm.time, "monotonic", side_effect=[0.0] + [100000.0 + i for i in range(10000)]), \
                mock.patch.object(kvm, "log", side_effect=lambda msg, *a: logged.append(msg)):
            self.run_loop(app, context=context, seconds=0.1)
        context.load_cert_chain.assert_called_with(kvm.CERT_FILE, kvm.KEY_FILE)
        self.assertIn("certificate renewed and reloaded", logged)

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_certificate_renewal_failure_logged(self):
        app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=FakeSystem(), clock=MONO),
                      runner=FakeSystem(), log_dir="/nonexistent", log_files=[])
        logged = []
        with mock.patch.object(kvm, "report_due", return_value=False), \
                mock.patch.object(kvm, "certificate_needs_renewal", side_effect=RuntimeError("x")), \
                mock.patch.object(kvm.time, "monotonic", side_effect=[0.0] + [100000.0 + i for i in range(10000)]), \
                mock.patch.object(kvm, "log", side_effect=lambda msg, *a: logged.append(msg % a if a else msg)):
            self.run_loop(app, context=mock.Mock(), seconds=0.1)
        self.assertTrue(any(m.startswith("certificate renewal failed") for m in logged))


@unittest.skipIf(mock is None, "mock unavailable")
class MainTest(unittest.TestCase):
    """main(): запуск сервера (HTTPS и --no-tls), watchdog, корректная остановка."""

    def start_main(self, argv, environ=None):
        created = {}
        real_create = kvm.create_server

        def create(app, bind, port, context):
            server = real_create(app, "127.0.0.1", 0, context)
            created["server"], created["app"], created["context"] = server, app, context
            created["bind"], created["port"] = bind, port
            return server
        out = io.StringIO()
        fake, real_run = FakeSystem(), kvm.run_cmd

        def runner(args, timeout=5, c_locale=True):
            if args[0] == "openssl":  # настоящий сертификат во временном каталоге
                return real_run(args, timeout, c_locale)
            return fake(args, timeout, c_locale)
        patches = [mock.patch.object(kvm, "create_server", side_effect=create),
                   mock.patch.object(kvm, "run_cmd", side_effect=runner),
                   mock.patch.object(kvm, "LOG_DIR", self.dir),
                   mock.patch.object(kvm, "CERT_FILE", os.path.join(self.dir, "cert.pem")),
                   mock.patch.object(kvm, "KEY_FILE", os.path.join(self.dir, "key.pem")),
                   mock.patch.object(kvm, "sd_notify", side_effect=lambda msg, environ=None: created.setdefault(
                       "notify", []).append(msg)),
                   mock.patch.object(sys, "stdout", out),
                   mock.patch.dict(os.environ, environ or {})]
        for p in patches:
            p.start()
        result = {}

        def target():
            result["rc"] = kvm.main(argv)
        th = threading.Thread(target=target)
        th.start()
        deadline = time.time() + 20
        while "server" not in created and time.time() < deadline:
            time.sleep(0.02)
        while not created.get("notify") and time.time() < deadline:
            time.sleep(0.02)
        return created, th, patches, out

    def stop(self, created, th, patches):
        created["server"].shutdown()
        th.join(10)
        for p in reversed(patches):
            p.stop()

    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    @unittest.skipUnless(__import__("shutil").which("openssl"), "openssl not installed")
    def test_https_start_and_stop(self):
        created, th, patches, out = self.start_main([], {"WATCHDOG_USEC": "3000000", "WATCHDOG_PID": str(os.getpid())})
        try:
            self.assertIsNotNone(created["context"], "сертификат создан, сервер на HTTPS")
            self.assertTrue(os.path.exists(os.path.join(self.dir, "cert.pem")))
            self.assertIn("running on https://", out.getvalue())
            self.assertFalse(created["app"].insecure)
            self.assertIn("READY=1", created["notify"])
        finally:
            self.stop(created, th, patches)
        self.assertIn("STOPPING=1", created["notify"])

    def test_no_tls_mode(self):
        created, th, patches, out = self.start_main(["--no-tls"])
        try:
            self.assertIsNone(created["context"])
            self.assertIn("running on http://", out.getvalue())
            self.assertFalse(created["app"].insecure, "явный режим отладки")
        finally:
            self.stop(created, th, patches)

    def test_custom_port_argument(self):
        """install.sh --port N записывает в unit-файл «--port N»: сервис слушает этот порт."""
        created, th, patches, out = self.start_main(["--no-tls", "--port", "9443"])
        try:
            self.assertEqual((created["bind"], created["port"]), ("0.0.0.0", 9443))
            self.assertIn(":9443", out.getvalue())
            events = [e["message"] for e in created["app"].events.recent() if e["name"] == "monitor_started"]
            self.assertTrue(events and ":9443)" in events[0])
        finally:
            self.stop(created, th, patches)
        created, th, patches, out = self.start_main(["--no-tls"])
        try:
            self.assertEqual(created["port"], 8999, "по умолчанию — 8999")
        finally:
            self.stop(created, th, patches)

    def test_tls_failure_disables_restart(self):
        with mock.patch.object(kvm, "generate_certificate", return_value=False):
            created, th, patches, out = self.start_main([])
            try:
                self.assertIsNone(created["context"])
                self.assertTrue(created["app"].insecure, "без HTTPS пароль root не принимается")
            finally:
                self.stop(created, th, patches)

    def test_tls_context_error(self):
        with mock.patch.object(kvm, "make_ssl_context", side_effect=kvm.ssl.SSLError("bad key")):
            created, th, patches, out = self.start_main([])
            try:
                self.assertIsNone(created["context"])
                self.assertTrue(created["app"].insecure)
            finally:
                self.stop(created, th, patches)

    def test_check_flag(self):
        with mock.patch.object(kvm, "self_check", return_value=7) as check:
            self.assertEqual(kvm.main(["--check"]), 7)
        check.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
