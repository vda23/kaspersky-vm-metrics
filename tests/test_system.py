# -*- coding: utf-8 -*-
"""Сертификат, systemd notify/watchdog, конфигурация, фоновые задачи."""
import os
import shutil
import socket
import ssl
import threading
import time
import unittest
from datetime import datetime

from helpers import FakeClock, FakeSystem, MONO, TempDir, kvm

HAVE_OPENSSL = shutil.which("openssl") is not None


class CertificateTest(unittest.TestCase):
    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_generate_with_san_and_permissions(self):
        with TempDir() as d:
            cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
            self.assertTrue(kvm.generate_certificate("kvm.corp.local", cert, key))
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(cert).st_mode & 0o777, 0o644)
            text = kvm.run_cmd(["openssl", "x509", "-in", cert, "-noout", "-text"]).out
            self.assertIn("DNS:kvm.corp.local", text)
            self.assertIn("DNS:kvm", text)
            self.assertIn("IP Address:127.0.0.1", text)
            self.assertIn("CN = kvm.corp.local", text.replace("CN=", "CN = "))
            self.assertFalse(kvm.certificate_needs_renewal(cert))
            ctx = kvm.make_ssl_context(cert, key)
            self.assertIsInstance(ctx, ssl.SSLContext)
            self.assertFalse([n for n in os.listdir(d) if n.endswith(".new")])

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
    def test_existing_valid_certificate_kept(self):
        with TempDir() as d:
            cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
            kvm.generate_certificate("a.local", cert, key)
            with open(cert, "rb") as fh:
                before = fh.read()
            calls = []

            def runner(args, timeout=5, c_locale=True):
                calls.append(args)
                return kvm.run_cmd(args, timeout)
            self.assertTrue(kvm.generate_certificate("a.local", cert, key, runner=runner))
            with open(cert, "rb") as fh:
                self.assertEqual(fh.read(), before)
            self.assertEqual(calls[0][:2], ["openssl", "x509"])
            self.assertEqual(len(calls), 1)

    def test_renewal_decision(self):
        with TempDir() as d:
            cert = os.path.join(d, "cert.pem")
            self.assertTrue(kvm.certificate_needs_renewal(cert))
            open(cert, "w").close()
            for rc, expected in ((0, False), (1, True), (127, False)):
                runner = lambda args, timeout=5, c_locale=True, rc=rc: kvm.CmdResult(rc, "", "")
                self.assertEqual(kvm.certificate_needs_renewal(cert, runner), expected)

    def test_openssl_failure_keeps_old_files(self):
        with TempDir() as d:
            cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
            with open(cert, "w") as fh:
                fh.write("OLD")
            with open(key, "w") as fh:
                fh.write("OLDKEY")

            def runner(args, timeout=5, c_locale=True):
                if args[1] == "x509":
                    return kvm.CmdResult(1, "", "")  # истекает
                return kvm.CmdResult(1, "", "boom")
            self.assertTrue(kvm.generate_certificate("x", cert, key, runner=runner))
            with open(cert) as fh:
                self.assertEqual(fh.read(), "OLD")

    def test_cn_sanitized(self):
        seen = {}

        def runner(args, timeout=5, c_locale=True):
            cnf = args[args.index("-config") + 1]
            with open(cnf) as fh:
                seen["cnf"] = fh.read()
            return kvm.CmdResult(1, "", "fail")
        with TempDir() as d:
            kvm.generate_certificate("bad host/$(rm -rf)", os.path.join(d, "c"), os.path.join(d, "k"),
                                     runner=runner, force=True)
        self.assertIn("CN = badhostrm-rf", seen["cnf"])


class SdNotifyTest(unittest.TestCase):
    def test_no_socket(self):
        self.assertFalse(kvm.sd_notify("READY=1", environ={}))

    def test_path_socket(self):
        with TempDir() as d:
            path = os.path.join(d, "notify.sock")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            srv.bind(path)
            try:
                self.assertTrue(kvm.sd_notify("READY=1", environ={"NOTIFY_SOCKET": path}))
                self.assertEqual(srv.recv(100), b"READY=1")
            finally:
                srv.close()

    def test_abstract_socket(self):
        name = "kvm-test-%d" % os.getpid()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        srv.bind("\0" + name)
        try:
            self.assertTrue(kvm.sd_notify("WATCHDOG=1", environ={"NOTIFY_SOCKET": "@" + name}))
            self.assertEqual(srv.recv(100), b"WATCHDOG=1")
        finally:
            srv.close()

    def test_dead_socket(self):
        self.assertFalse(kvm.sd_notify("READY=1", environ={"NOTIFY_SOCKET": "/nonexistent/sock"}))

    def test_watchdog_interval(self):
        self.assertIsNone(kvm.watchdog_interval({}))
        self.assertAlmostEqual(kvm.watchdog_interval({"WATCHDOG_USEC": "60000000"}), 20.0)
        self.assertIsNone(kvm.watchdog_interval({"WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "1"}))
        self.assertAlmostEqual(kvm.watchdog_interval({"WATCHDOG_USEC": "3000000",
                                                      "WATCHDOG_PID": str(os.getpid())}), 1.0)

    def test_watchdog_loop_pings_only_when_alive(self):
        with TempDir() as d:
            path = os.path.join(d, "wd.sock")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            srv.bind(path)
            srv.settimeout(1)
            old = os.environ.get("NOTIFY_SOCKET")
            os.environ["NOTIFY_SOCKET"] = path

            class Srv(object):
                heartbeat = time.monotonic()
            server = Srv()
            stop = threading.Event()

            def beat():
                while not stop.is_set():
                    server.heartbeat = time.monotonic()
                    time.sleep(0.02)
            beater = threading.Thread(target=beat)
            beater.start()
            loop = threading.Thread(target=kvm.watchdog_loop, args=(server, stop, 0.1))
            loop.start()
            try:
                self.assertEqual(srv.recv(100), b"WATCHDOG=1")
                stop.set()
                beater.join()
                loop.join()
                # сервер «завис»: heartbeat не обновляется -> пингов нет
                stop.clear()
                server.heartbeat = time.monotonic() - 100
                loop = threading.Thread(target=kvm.watchdog_loop, args=(server, stop, 0.05))
                loop.start()
                srv.settimeout(0.3)
                with self.assertRaises(socket.timeout):
                    srv.recv(100)
            finally:
                stop.set()
                loop.join()
                srv.close()
                if old is None:
                    os.environ.pop("NOTIFY_SOCKET", None)
                else:
                    os.environ["NOTIFY_SOCKET"] = old


class AppAndSelfCheckTest(unittest.TestCase):
    def test_app_logs_index(self):
        with TempDir() as d:
            log = os.path.join(d, "a.log")
            with open(log, "w") as fh:
                fh.write("x\n")
            fake = FakeSystem()
            app = kvm.App(log_files=[{"key": "a", "path": log}, {"key": "g", "path": os.path.join(d, "*.nomatch")}],
                          collector=kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO), runner=fake, log_dir=d)
            idx = app.logs_index()
            self.assertTrue(idx["files"][0]["exists"])
            self.assertEqual(idx["files"][0]["resolved"], log)
            self.assertFalse(idx["files"][1]["exists"])
            self.assertIsNone(idx["files"][1]["resolved"])
            self.assertEqual(len(idx["journals"]), 6)

    def test_services_definition(self):
        keys = [s["key"] for s in kvm.SERVICES]
        self.assertEqual(keys, ["scanner", "vms", "worker", "privateapi", "publicapi", "postgresql"])
        for svc in kvm.SERVICES:
            self.assertTrue(svc["unit"].endswith(".service"))
            self.assertTrue(svc["desc_ru"] and svc["desc_en"])
            self.assertTrue(kvm.KEY_RE.match(svc["key"]))

    def test_no_user_config_anymore(self):
        self.assertFalse(hasattr(kvm, "load_config"), "настройка через config.json убрана")
        self.assertFalse(hasattr(kvm, "CONFIG_FILE"))

    def test_app_does_not_mutate_global_services(self):
        fake = FakeSystem()
        app = kvm.App(collector=None, runner=fake)
        app.services[0]["unit"] = "changed.service"
        self.assertEqual(kvm.SERVICES[0]["unit"], "kaspersky-vm-scanner.service")

    def test_self_check_ok(self):
        import io
        out = io.StringIO()
        self.assertEqual(kvm.self_check(out=out, runner=FakeSystem()), 0)
        self.assertIn("OK " + kvm.__version__, out.getvalue())

    def test_self_check_fails_when_assets_broken(self):
        import io
        original = kvm.build_assets
        kvm.build_assets = lambda: (_ for _ in ()).throw(RuntimeError("bad assets"))
        try:
            out = io.StringIO()
            self.assertEqual(kvm.self_check(out=out, runner=FakeSystem()), 1)
            self.assertIn("FAIL web assets", out.getvalue())
        finally:
            kvm.build_assets = original

    def test_self_check_reports_units_and_logs(self):
        import io
        fake = FakeSystem()
        fake.units["postgresql-15.service"] = fake.units.pop("postgresql.service")
        fake.units.pop("kaspersky-vm-publicapi.service")
        out = io.StringIO()
        self.assertEqual(kvm.self_check(out=out, runner=fake), 0)
        text = out.getvalue()
        self.assertIn("INFO unit kaspersky-vm-scanner.service: active", text)
        self.assertIn("INFO unit postgresql-15.service: active", text, "имя СУБД найдено автоматически")
        self.assertIn("WARN unit kaspersky-vm-publicapi.service not found on this server", text)
        self.assertIn("INFO log worker: /var/log/kaspersky/vulnerability-management/worker/worker.log", text)
        self.assertNotIn("config.json", text)

    def test_check_cli_does_not_open_port(self):
        import subprocess, sys as _sys
        res = subprocess.run([_sys.executable, kvm.__file__, "--check"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertIn(("OK " + kvm.__version__).encode(), res.stdout)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            kvm.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


class DetectUnitTest(unittest.TestCase):
    """Автоопределение имени службы СУБД по маскам — без настройки пользователем."""

    PATTERNS = ["postgresql*.service", "postgrespro*.service"]

    def fake(self, units):
        fake = FakeSystem()
        fake.units.pop("postgresql.service")
        for name, props in units.items():
            base = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": 900,
                    "MemoryCurrent": 1, "TasksCurrent": 1, "NRestarts": 0, "since": MONO() - 100,
                    "ControlGroup": "/system.slice/" + name, "Result": "success", "restart_at": None}
            base.update(props)
            fake.units[name] = base
        return fake

    def test_plain_postgresql(self):
        self.assertEqual(kvm.detect_unit(FakeSystem(), self.PATTERNS, "postgresql.service"), "postgresql.service")

    def test_pgdg_versioned_unit(self):
        fake = self.fake({"postgresql-15.service": {}})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgresql-15.service")

    def test_debian_wrapper_prefers_real_cluster(self):
        fake = self.fake({"postgresql.service": {"SubState": "exited", "MainPID": 0},
                          "postgresql@15-main.service": {}})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgresql@15-main.service")

    def test_postgres_pro(self):
        fake = self.fake({"postgrespro-std-15.service": {}})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgrespro-std-15.service")

    def test_active_beats_old_inactive_install(self):
        fake = self.fake({"postgresql-13.service": {"ActiveState": "inactive", "SubState": "dead", "MainPID": 0},
                          "postgresql-15.service": {}})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgresql-15.service")

    def test_stopped_database_still_found(self):
        fake = self.fake({"postgresql-15.service": {"ActiveState": "failed", "SubState": "failed", "MainPID": 0}})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgresql-15.service")

    def test_nothing_found_keeps_default(self):
        fake = self.fake({})
        self.assertEqual(kvm.detect_unit(fake, self.PATTERNS, "postgresql.service"), "postgresql.service")

    def test_systemctl_unavailable_keeps_default(self):
        runner = lambda args, timeout=5, c_locale=True: kvm.CmdResult(127, "", "not found")
        self.assertEqual(kvm.detect_unit(runner, self.PATTERNS, "postgresql.service"), "postgresql.service")

    def test_parse_unit_list(self):
        text = ("postgresql.service loaded active exited PostgreSQL RDBMS\n"
                "● postgresql@14-main.service loaded failed failed PostgreSQL Cluster 14-main\n"
                "postgresql@.service static -\n"
                "something.socket loaded active listening x\n")
        self.assertEqual(kvm.parse_unit_list(text), ["postgresql.service", "postgresql@14-main.service"])

    def test_collector_uses_detected_unit_for_status_restart_and_journal(self):
        fake = self.fake({"postgresql-15.service": {}})
        app = kvm.App(collector=None, runner=fake)
        # App создаёт свой StatusCollector на тех же копиях служб
        data = app.collector.get(force=True)
        pg = [svc for svc in data["services"] if svc["key"] == "postgresql"][0]
        self.assertEqual(pg["unit"], "postgresql-15.service")
        self.assertEqual(pg["state"], "active")
        self.assertEqual(app.services_by_key["postgresql"]["unit"], "postgresql-15.service")

    def test_detection_is_cached(self):
        fake = self.fake({"postgresql-15.service": {}})
        clock = FakeClock(start=500.0)
        collector = kvm.StatusCollector([dict(svc) for svc in kvm.SERVICES], runner=fake, clock=clock, ttl=0)
        collector.collect()
        collector.collect()
        lists = [c for c in fake.calls if c[:2] == ["systemctl", "list-units"]]
        self.assertEqual(len(lists), 1)
        clock.advance(301)
        collector.collect()
        self.assertEqual(len([c for c in fake.calls if c[:2] == ["systemctl", "list-units"]]), 2)


class LogPathsTest(unittest.TestCase):
    def test_vms_log_has_date_in_name(self):
        vms = [f for f in kvm.LOG_FILES if f["key"] == "vms"][0]
        self.assertEqual(vms["path"], "/var/log/kaspersky/vulnerability-management/vms/vms*.log")
        with TempDir() as d:
            os.makedirs(os.path.join(d, "vms"))
            old = os.path.join(d, "vms", "vms_2026-10-28T101500.log")
            new = os.path.join(d, "vms", "vms_2026-10-29T231005.log")
            for path, age in ((old, 3600), (new, 0)):
                open(path, "w").close()
                os.utime(path, (time.time() - age, time.time() - age))
            pattern = vms["path"].replace(kvm.LOG_DIR_KVM, d)
            self.assertEqual(kvm.resolve_log_path(pattern), new)

    def test_other_logs_fixed_names(self):
        paths = dict((f["key"], f["path"]) for f in kvm.LOG_FILES)
        base = "/var/log/kaspersky/vulnerability-management/"
        self.assertEqual(paths["worker"], base + "worker/worker.log")
        self.assertEqual(paths["scanner"], base + "scanner/scanner.log")
        self.assertEqual(paths["privateapi"], base + "privateapi/privateapi.log")
        self.assertEqual(paths["publicapi"], base + "publicapi/publicapi.log")


class BackgroundLoopTest(unittest.TestCase):
    def test_writes_report_once(self):
        with TempDir() as d:
            fake = FakeSystem()
            app = kvm.App(collector=kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO),
                          runner=fake, log_dir=d, log_files=[], settings_path=os.path.join(d, "settings.json"))
            stop = threading.Event()
            original = kvm.report_due
            calls = []

            def due(now, last_date, log_dir=None, hour=19):
                calls.append(last_date)
                return last_date is None
            kvm.report_due = due
            try:
                th = threading.Thread(target=kvm.background_loop, args=(app, stop, None, 0.02))
                th.start()
                time.sleep(0.3)
                stop.set()
                th.join()
            finally:
                kvm.report_due = original
            reports = [n for n in os.listdir(d) if kvm.REPORT_RE.match(n)]
            self.assertEqual(reports, [kvm.REPORT_PREFIX + datetime.now().strftime("%d_%m_%Y") + ".json"])
            self.assertTrue(any(c is not None for c in calls), "last_date обновляется после записи")


if __name__ == "__main__":
    unittest.main()
