# -*- coding: utf-8 -*-
"""Отчёты о состоянии (JSON), журнал событий, отправка в SIEM (syslog + CEF), монитор состояний."""
import http.client
import json
import os
import socket
import stat
import threading
import time
import unittest
from datetime import datetime

from helpers import MONO, FakeSystem, ServerFixture, TempDir, kvm

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    mock = None

JSON_LOG = (
    '{"level":"info","timestamp":"2026-11-04T23:59:58.100+0300","logger":"vm_worker","message":"yesterday"}\n'
    '{"level":"error","timestamp":"2026-11-04T23:59:59.100+0300","logger":"vm_worker","message":"old error"}\n'
    '{"level":"info","timestamp":"2026-11-05T00:00:01.000+0300","logger":"vm_worker","message":"started"}\n'
    '{"level":"warn","timestamp":"2026-11-05T08:00:00.000+0300","logger":"vm_worker","message":"slow"}\n'
    '{"level":"error","timestamp":"2026-11-05T12:26:44.782+0300","logger":"vm_worker",'
    '"message":"task failed","error":"connection refused"}\n'
    '{"level":"ERROR","timestamp":"2026-11-05T12:30:00.000+0300","component":"vm_worker","msg":"db timeout"}\n'
)


def write(path, text, mode="w"):
    with open(path, mode) as fh:
        fh.write(text)
    return path


def make_app(tmp, log_files=None, fake=None):
    fake = fake or FakeSystem()
    collector = kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO, ttl=0)
    collector.fqdn = "kvm.test.local"
    return kvm.App(collector=collector, runner=fake, log_dir=tmp, log_files=log_files or [],
                   settings_path=os.path.join(tmp, "settings.json"), fail_delay=0)


class Listener(object):
    """Приёмник syslog на 127.0.0.1: TCP (строки) или UDP (датаграммы)."""

    def __init__(self, proto="tcp"):
        self.proto = proto
        self.data = []
        self.conns = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        if proto == "tcp":
            self.sock.listen(5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while True:
                if self.proto == "udp":
                    self.data.append(self.sock.recvfrom(65535)[0])
                    continue
                conn, _ = self.sock.accept()
                self.conns.append(conn)
                threading.Thread(target=self.read, args=(conn,), daemon=True).start()
        except OSError:
            pass

    def read(self, conn):
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                self.data.append(chunk)
        except OSError:
            pass

    def text(self):
        return b"".join(self.data).decode("utf-8")

    def wait(self, count, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            n = len(self.data) if self.proto == "udp" else self.text().count("\n")
            if n >= count:
                return True
            time.sleep(0.02)
        return False

    def drop_clients(self):
        for conn in self.conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self.conns = []

    def close(self):
        self.drop_clients()
        self.sock.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
class JsonLogTest(unittest.TestCase):
    def test_line_date_json(self):
        self.assertEqual(kvm.line_date(b'{"level":"info","timestamp":"2026-11-05T12:26:44.782+0300"}\n').isoformat(),
                         "2026-11-05")
        self.assertEqual(kvm.line_date(b'  {"time": "2026-01-02 10:00:00"}').isoformat(), "2026-01-02")
        self.assertIsNone(kvm.line_date(b'{"level":"info","message":"no time"}'))
        self.assertIsNone(kvm.line_date(b'{"timestamp":"2026-13-45T00:00:00"}'))
        self.assertEqual(kvm.line_date(b"2026-11-03 17:02:17 INFO x").isoformat(), "2026-11-03")

    def test_line_level(self):
        self.assertEqual(kvm.line_level(b'{"level":"error","message":"x"}'), "error")
        self.assertEqual(kvm.line_level(b'{"level":"FATAL"}'), "error")
        self.assertEqual(kvm.line_level(b'{"severity":"warning"}'), "warn")
        self.assertIsNone(kvm.line_level(b'{"level":"info","message":"error in text is not a level"}'))
        self.assertIsNone(kvm.line_level(b'{"message":"no level"}'))
        self.assertEqual(kvm.line_level(b"2026-11-03 17:02:17 ERROR scanner: boom"), "error")
        self.assertEqual(kvm.line_level(b"2026-11-03 17:02:17 WARN scanner"), "warn")
        self.assertEqual(kvm.line_level(b"ts=1 level=error msg=x"), "error")
        self.assertIsNone(kvm.line_level(b"ts=1 level=info msg=x"))
        self.assertIsNone(kvm.line_level(b"2026-11-03 INFO all good"))

    def test_summarize(self):
        self.assertEqual(kvm.summarize_log_line(
            b'{"timestamp":"T","logger":"L","message":"task failed","error":"refused"}\n'),
            {"time": "T", "source": "L", "message": "task failed: refused"})
        self.assertEqual(kvm.summarize_log_line(b'{"error":"only error"}')["message"], "only error")
        self.assertEqual(kvm.summarize_log_line(b'{"msg":"m","err":"m"}')["message"], "m")
        self.assertEqual(kvm.summarize_log_line(b'{"x":1}')["message"], '{"x":1}')
        self.assertEqual(kvm.summarize_log_line(b"{broken json")["message"], "{broken json")
        self.assertEqual(kvm.summarize_log_line(b"plain ERROR line\n"), {"time": "", "source": "", "message": "plain ERROR line"})
        self.assertEqual(len(kvm.summarize_log_line(b"x" * 900)["message"]), 500)

    def test_scan_counts_and_last_errors(self):
        with TempDir() as d:
            path = write(os.path.join(d, "w.log"), JSON_LOG)
            scan = kvm.scan_log_levels(path)
            self.assertEqual((scan["lines"], scan["errors"], scan["warnings"]), (6, 3, 1))
            self.assertFalse(scan["truncated"])
            self.assertEqual(scan["next_offset"], os.path.getsize(path))
            self.assertEqual([e["message"] for e in scan["last_errors"]],
                             ["old error", "task failed: connection refused", "db timeout"])
            self.assertEqual(kvm.scan_log_levels(path, keep=0)["last_errors"], [])

    def test_scan_partial_last_line_and_truncation(self):
        with TempDir() as d:
            path = write(os.path.join(d, "w.log"), JSON_LOG + '{"level":"error","timestamp":"2026-11-05')
            scan = kvm.scan_log_levels(path)
            self.assertEqual(scan["errors"], 3, "незавершённая строка не учитывается")
            self.assertEqual(scan["next_offset"], len(JSON_LOG.encode()))
            # окно меньше файла: начинаем с середины строки и пропускаем её
            scan = kvm.scan_log_levels(path, max_bytes=len(JSON_LOG.encode()) // 2)
            self.assertTrue(scan["truncated"])
            self.assertLess(scan["lines"], 6)
            # окно ровно на границе строки
            lines = JSON_LOG.encode().splitlines(True)
            tail = len(lines[-1]) + len(b'{"level":"error","timestamp":"2026-11-05')
            scan = kvm.scan_log_levels(path, max_bytes=tail)
            self.assertEqual((scan["lines"], scan["errors"]), (1, 1))

    def test_today_offset_json_log(self):
        with TempDir() as d:
            path = write(os.path.join(d, "w.log"), JSON_LOG * 300)
            day = datetime(2026, 11, 5).date()
            offset = kvm.today_offset(path, day)
            self.assertNotIn(offset, (None, 0))
            with open(path, "rb") as fh:
                fh.seek(offset)
                self.assertIn(b"2026-11-05", fh.readline())

    def test_today_zip_detects_json_dates(self):
        with TempDir() as d:
            path = write(os.path.join(d, "worker.log"), JSON_LOG)
            out = os.path.join(d, "out.zip")
            with open(out, "wb") as fh:
                included = kvm.build_today_logs_zip([{"key": "worker", "path": path}], fh,
                                                    now=datetime(2026, 11, 5, 13, 0))
            self.assertEqual(included[0]["mode"], "today")
            self.assertEqual(included[0]["bytes"], len(JSON_LOG.encode()) - len("".join(JSON_LOG.splitlines(True)[:2]).encode()))


class ReportPartsTest(unittest.TestCase):
    def test_report_date_and_listing_order(self):
        self.assertEqual(kvm.report_date("kaspersky-vm-services-state_05_11_2026.json"), datetime(2026, 11, 5))
        self.assertEqual(kvm.report_date("kaspersky-vm-services-state_xx.json"), datetime.min)
        with TempDir() as d:
            for name in ("kaspersky-vm-services-state_05_11_2026.json", "kaspersky-vm-services-state_05_11_2026.txt"):
                write(os.path.join(d, name), "x")
            reports = kvm.list_reports(d)
            self.assertEqual([r["name"] for r in reports], ["kaspersky-vm-services-state_05_11_2026.json"],
                             "только JSON-отчёты")

    def test_disk_usage_dedupes_and_skips_missing(self):
        disks = kvm.disk_usage(("/", "/", "/nonexistent-path-xyz"))
        self.assertEqual(len(disks), 1)
        disk = disks[0]
        self.assertEqual(disk["path"], "/")
        self.assertTrue(0 <= disk["percent"] <= 100)
        self.assertEqual(set(disk), {"path", "total_bytes", "used_bytes", "free_bytes", "percent"})

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_disk_usage_empty_fs(self):
        fake = os.statvfs_result((4096, 4096, 0, 0, 0, 0, 0, 0, 0, 255))
        with mock.patch.object(kvm.os, "statvfs", return_value=fake):
            self.assertEqual(kvm.disk_usage(("/",))[0]["percent"], 0.0)

    def test_certificate_info(self):
        with TempDir() as d:
            cert = write(os.path.join(d, "cert.pem"), "x")
            self.assertIsNone(kvm.certificate_info(os.path.join(d, "none.pem")))

            def runner(out, rc=0):
                return lambda args, timeout=5, c_locale=True: kvm.CmdResult(rc, out, "")
            info = kvm.certificate_info(cert, runner("notAfter=Nov  5 12:00:00 2027 GMT\n"),
                                        now=datetime(2026, 11, 5, 12, 0))
            self.assertEqual(info, {"not_after": "2027-11-05T12:00:00Z", "days_left": 365})
            self.assertIsNone(kvm.certificate_info(cert, runner("garbage")))
            self.assertIsNone(kvm.certificate_info(cert, runner("notAfter=Xyz  5 12:00:00 2027 GMT")))
            self.assertIsNone(kvm.certificate_info(cert, runner("", rc=1)))
            self.assertIsNotNone(kvm.certificate_info(cert, runner("notAfter=Jan 15 01:02:03 2030 GMT")))

    def test_log_today_summary_cases(self):
        with TempDir() as d:
            now = datetime.now()
            item = {"key": "worker", "title_ru": "Служба", "path": os.path.join(d, "missing.log")}
            self.assertEqual(kvm.log_today_summary(item, now)["exists"], False)

            old = write(os.path.join(d, "old.log"), "2020-01-01 ERROR x\n")
            past = time.time() - 3 * 86400
            os.utime(old, (past, past))
            entry = kvm.log_today_summary(dict(item, path=old), now)
            self.assertEqual((entry["exists"], entry["today"]["errors"], entry["today"]["date_format"]), (True, 0, "n/a"))

            today = now.strftime("%Y-%m-%d")
            fresh = write(os.path.join(d, "fresh.log"),
                          "2020-01-01 10:00:00 ERROR old\n%s 10:00:00 ERROR new\n%s 10:00:01 WARN w\n" % (today, today))
            entry = kvm.log_today_summary(dict(item, path=fresh), now)
            self.assertEqual((entry["today"]["errors"], entry["today"]["warnings"]), (1, 1))
            self.assertEqual(entry["today"]["date_format"], "detected")
            self.assertNotIn("next_offset", entry["today"])

            nodate = write(os.path.join(d, "nodate.log"), "ERROR a\nERROR b\n")
            entry = kvm.log_today_summary(dict(item, path=nodate), now)
            self.assertEqual((entry["today"]["errors"], entry["today"]["date_format"]), (2, "unknown (whole file)"))

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_log_today_summary_read_error(self):
        with TempDir() as d:
            path = write(os.path.join(d, "w.log"), "x\n")
            with mock.patch.object(kvm, "today_offset", side_effect=OSError("denied")):
                entry = kvm.log_today_summary({"key": "w", "title_ru": "W", "path": path})
            self.assertEqual(entry["error"], "denied")


class StateReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def test_ok_report_structure(self):
        today = datetime.now().strftime("%Y-%m-%d")
        log = write(os.path.join(self.dir, "worker.log"),
                    '{"level":"info","timestamp":"%sT01:00:00","message":"ok"}\n' % today)
        app = make_app(self.dir, [{"key": "worker", "title_ru": "Служба фоновых задач", "path": log}])
        with mock.patch.object(kvm, "disk_usage", return_value=[{"path": "/", "percent": 10.0}]), \
                mock.patch.object(kvm, "certificate_info", return_value={"days_left": 300, "not_after": "x"}):
            report = kvm.build_state_report(app, "on-demand")
        self.assertEqual(report["summary"]["status"], "ok", report["summary"]["problems"])
        self.assertEqual(report["schema"], kvm.REPORT_SCHEMA)
        self.assertEqual(report["kind"], "on-demand")
        self.assertEqual(report["monitor_version"], kvm.__version__)
        self.assertEqual(report["summary"]["services_running"], 6)
        self.assertEqual(report["logs"][0]["today"]["lines"], 1)
        for svc in report["services"]:
            self.assertTrue(svc["active_since"])
            self.assertTrue(svc["description"])
        self.assertIn("db_connections", report["services"][-1])
        self.assertIn("kernel", report["system"])
        self.assertIn("used_percent", report["system"]["memory"])
        self.assertEqual(report["siem"]["state"], "off")
        json.dumps(report)  # сериализуется

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_problems_and_statuses(self):
        today = datetime.now().strftime("%Y-%m-%d")
        log = write(os.path.join(self.dir, "worker.log"),
                    '{"level":"error","timestamp":"%sT01:00:00","message":"boom"}\n' % today)
        fake = FakeSystem()
        app = make_app(self.dir, [{"key": "worker", "title_ru": "Служба фоновых задач", "path": log}], fake)
        app.restarts.results["scanner"] = {"result": "ok", "started": time.time() - 5, "finished": time.time()}
        with mock.patch.object(kvm, "disk_usage", return_value=[{"path": "/var", "percent": 95.0}]), \
                mock.patch.object(kvm, "certificate_info", return_value={"days_left": 10, "not_after": "x"}), \
                mock.patch.object(kvm, "parse_meminfo", return_value={"MemTotal": 100, "MemFree": 1, "MemAvailable": 5}):
            report = kvm.build_state_report(app)
        codes = sorted(p["code"] for p in report["summary"]["problems"])
        self.assertEqual(codes, ["certificate_expiring", "disk_high", "log_errors", "memory_high"])
        self.assertEqual(report["summary"]["status"], "warning")
        self.assertEqual(report["summary"]["log_errors_today"], 1)
        scanner = [s for s in report["services"] if s["key"] == "scanner"][0]
        self.assertEqual(scanner["last_restart_from_dashboard"]["result"], "ok")

        fake.stop("kaspersky-vm-vms.service")
        with mock.patch.object(kvm, "disk_usage", return_value=[]), \
                mock.patch.object(kvm, "certificate_info", return_value=None):
            report = kvm.build_state_report(app)
        self.assertEqual(report["summary"]["status"], "critical")
        self.assertEqual(report["summary"]["services_not_running"], ["vms"])
        vms = [s for s in report["services"] if s["key"] == "vms"][0]
        self.assertIsNone(vms["active_since"])

    def test_events_in_report(self):
        app = make_app(self.dir)
        app.events.emit("auth_failed", "x", client="10.0.0.1")
        report = kvm.build_state_report(app)
        self.assertEqual(report["summary"]["events_24h"], 1)
        self.assertEqual(report["events_24h"][0]["name"], "auth_failed")

    def test_iso_local(self):
        value = kvm.iso_local(0)
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$")
        self.assertRegex(kvm.iso_local(), r"[+-]\d{2}:\d{2}$")

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_iso_local_negative_offset_and_no_gmtoff(self):
        class TM(object):
            tm_gmtoff = -5 * 3600 - 1800

        with mock.patch.object(kvm.time, "localtime", return_value=TM()), \
                mock.patch.object(kvm.time, "strftime", return_value="2026-01-01T00:00:00"):
            self.assertEqual(kvm.iso_local(1), "2026-01-01T00:00:00-05:30")

        class NoOff(object):
            tm_gmtoff = None

        with mock.patch.object(kvm.time, "localtime", return_value=NoOff()), \
                mock.patch.object(kvm.time, "strftime", return_value="2026-01-01T00:00:00"), \
                mock.patch.object(kvm.time, "timezone", -3 * 3600):
            self.assertEqual(kvm.iso_local(1), "2026-01-01T00:00:00+03:00")


# ---------------------------------------------------------------------------
class EventBusTest(unittest.TestCase):
    def test_emit_recent_listeners(self):
        clock = [1000.0]
        bus = kvm.EventBus(maxlen=3, clock=lambda: clock[0])
        got = []
        bus.subscribe(got.append)
        bus.subscribe(lambda e: 1 / 0)  # сломанный подписчик не мешает
        for i in range(5):
            clock[0] += 10
            event = bus.emit("service_down", "m%d" % i, unit="u", state=None)
        self.assertEqual(event["signature"], 201)
        self.assertEqual(event["fields"], {"unit": "u"}, "None-поля отбрасываются")
        self.assertEqual(len(got), 5)
        self.assertEqual([e["message"] for e in bus.recent()], ["m2", "m3", "m4"])
        self.assertEqual([e["message"] for e in bus.recent(since=1045)], ["m4"])
        self.assertEqual([e["message"] for e in bus.recent(limit=1)], ["m4"])
        self.assertIsInstance(bus.recent()[0]["time"], str)

    def test_all_event_types_well_formed(self):
        sigs = [v[0] for v in kvm.EVENT_TYPES.values()]
        self.assertEqual(len(sigs), len(set(sigs)), "Signature ID уникальны")
        self.assertEqual(sorted(set(v[1] for v in kvm.EVENT_TYPES.values())), [1, 2, 3, 4, 5], "шкала важности 1–5")
        for name, (sig, sev, cat, title) in kvm.EVENT_TYPES.items():
            self.assertTrue(1 <= sev <= 5, name)
            self.assertTrue(title and cat)


class CefFormatTest(unittest.TestCase):
    EVENT = {"time": 1793875070.5, "signature": 300, "title": "Wrong | root\\password", "severity": 3,
             "category": "auth", "message": "a=b\nc\\d\re",
             "fields": {"client": "10.0.0.7", "user": "root", "unit": "x.service", "count": 3, "percent": 91.5,
                        "state": "", "key": None}}

    def test_cef(self):
        cef = kvm.format_cef(self.EVENT, "kvm.local", "1.0.0")
        self.assertTrue(cef.startswith("CEF:0|Kaspersky|Kaspersky VM Metrics|1.0.0|300|Wrong \\| root\\\\password|3|"))
        self.assertIn("rt=1793875070500 dvchost=kvm.local cat=auth msg=a\\=b c\\\\d e src=", cef)
        self.assertIn("src=10.0.0.7 suser=root", cef)
        self.assertIn("cnt=3", cef)
        self.assertIn("cs1Label=unit cs1=x.service", cef)
        self.assertIn("cfp1Label=percent cfp1=91.5", cef)
        self.assertNotIn("cs2", cef, "пустые поля не выводятся")
        cef = kvm.format_cef(dict(self.EVENT, fields={"client": "not an ip"}), "h")
        self.assertNotIn("src=", cef)
        self.assertIn("|%s|" % kvm.__version__, cef)

    def test_syslog_header_and_severity_map(self):
        line = kvm.format_syslog(self.EVENT, "kvm local")
        tm = time.localtime(self.EVENT["time"])
        stamp = "%s %d %02d:%02d:%02d" % (kvm.MONTHS[tm.tm_mon - 1], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
        self.assertTrue(line.startswith("<132>%s kvmlocal CEF:0|" % stamp), line)
        self.assertNotIn("  ", line, "везде по одному пробелу, в том числе в дате")
        self.assertEqual([kvm.syslog_severity(s) for s in (0, 1, 2, 3, 4, 5)], [6, 6, 5, 4, 3, 2],
                         "важность 1–5 -> info, notice, warning, error, critical")
        self.assertTrue(kvm.format_syslog(self.EVENT, " ").startswith("<132>%s - " % stamp))

    def test_single_spaces_everywhere(self):
        event = dict(self.EVENT, time=time.mktime((2026, 11, 6, 9, 5, 7, 0, 0, -1)),
                     message="Last: 2026-11-06 10:56:44.737\t\t1134905  ERR \t vmde    Failed\r\n  next",
                     fields={"file": "/var/log/a  b.log", "unit": " x.service "})
        line = kvm.format_syslog(event, "kvm.local")
        self.assertTrue(line.startswith("<132>Nov 6 09:05:07 kvm.local CEF:0|"), line)
        self.assertIn("msg=Last: 2026-11-06 10:56:44.737 1134905 ERR vmde Failed next ", line)
        self.assertIn("filePath=/var/log/a b.log", line)
        self.assertIn("cs1=x.service", line)
        self.assertNotIn("  ", line)
        self.assertNotIn("\t", line)
        bus = kvm.EventBus()
        ev = bus.emit("log_errors", "a\t\tb   c\n d", key="vms")
        self.assertEqual(ev["message"], "a b c d", "сообщение в панели — тоже с одиночными пробелами")
        self.assertEqual(kvm.one_space("  x \t y\n"), "x y")

    def test_encode_limits(self):
        long_line = "x" * 3000 + "\n" + "я" * 9000
        udp = kvm.encode_syslog(long_line, "udp")
        self.assertLessEqual(len(udp), kvm.SIEM_UDP_MAX)
        self.assertTrue(udp.endswith(b"..."))
        self.assertNotIn(b"\n", udp)
        tcp = kvm.encode_syslog(long_line, "tcp")
        self.assertLessEqual(len(tcp), kvm.SIEM_TCP_MAX + 1)
        self.assertTrue(tcp.endswith(b"...\n"))
        tcp.decode("utf-8")  # обрезка не ломает UTF-8
        self.assertEqual(kvm.encode_syslog("short", "tcp"), b"short\n")
        self.assertEqual(kvm.encode_syslog("short", "udp"), b"short")


class SettingsTest(unittest.TestCase):
    def test_normalize(self):
        ok, err = kvm.normalize_siem({"host": " 10.0.0.5 ", "port": "514", "protocol": "udp"})
        self.assertEqual((ok, err), ({"enabled": True, "host": "10.0.0.5", "port": 514, "protocol": "udp"}, None))
        ok, _ = kvm.normalize_siem({"host": "[fe80::1]", "port": ""})
        self.assertEqual((ok["host"], ok["port"], ok["protocol"]), ("fe80::1", kvm.SIEM_RECOMMENDED_PORT, "tcp"))
        ok, _ = kvm.normalize_siem({"enabled": False, "host": ""})
        self.assertEqual(ok["enabled"], False)
        for raw, code in (([], "bad_request"), ({"host": "h", "protocol": "tls"}, "bad_protocol"),
                          ({"host": "h", "port": "abc"}, "bad_port"), ({"host": "h", "port": 0}, "bad_port"),
                          ({"host": "h", "port": 70000}, "bad_port"), ({"host": "a b;rm"}, "bad_host"),
                          ({"host": 5}, "host_required"), ({"enabled": True}, "host_required")):
            self.assertEqual(kvm.normalize_siem(raw), (None, code), raw)

    def test_load_save(self):
        with TempDir() as d:
            path = os.path.join(d, "settings.json")
            self.assertEqual(kvm.load_settings(path), {})
            write(path, "[1]")
            self.assertEqual(kvm.load_settings(path), {})
            write(path, "{bad")
            self.assertEqual(kvm.load_settings(path), {})
            kvm.save_settings({"siem": {"host": "h"}}, path)
            self.assertEqual(kvm.load_settings(path), {"siem": {"host": "h"}})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_save_failure_cleans_temp(self):
        with TempDir() as d:
            with mock.patch.object(kvm.os, "rename", side_effect=OSError("ro")):
                with self.assertRaises(OSError):
                    kvm.save_settings({}, os.path.join(d, "settings.json"))
            self.assertEqual(os.listdir(d), [])

    def test_app_loads_stored_settings(self):
        with TempDir() as d:
            kvm.save_settings({"siem": {"enabled": True, "host": "127.0.0.1", "port": 6000, "protocol": "udp"}},
                              os.path.join(d, "settings.json"))
            app = make_app(d)
            self.assertEqual(app.siem.status()["port"], 6000)
            self.assertEqual(app.siem.status()["state"], "waiting")
            kvm.save_settings({"siem": {"enabled": True, "host": "bad host!"}}, os.path.join(d, "settings.json"))
            app = make_app(d)
            self.assertEqual(app.siem.status()["state"], "off")


class SyslogSenderTest(unittest.TestCase):
    def event(self, bus=None, msg="hello"):
        return (bus or kvm.EventBus()).emit("service_down", msg, unit="kaspersky-vm-vms.service")

    def test_tcp_delivery_and_reconnect(self):
        lst = Listener("tcp")
        sender = kvm.SyslogSender("kvm.local", max_backoff=0.1)
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": lst.port, "protocol": "tcp"})
        sender.start()
        sender.start()  # повторный вызов не создаёт второй поток
        try:
            bus = kvm.EventBus()
            bus.subscribe(sender.submit)
            bus.emit("service_down", "first", unit="u")
            self.assertTrue(lst.wait(1))
            self.assertIn("CEF:0|Kaspersky|Kaspersky VM Metrics|", lst.text())
            self.assertTrue(sender.status()["stats"]["connected"])
            lst.drop_clients()  # SIEM закрыла соединение
            time.sleep(0.1)
            bus.emit("service_up", "second", unit="u")
            self.assertTrue(lst.wait(2), lst.text())
            self.assertIn("second", lst.text())
            st = sender.status()
            self.assertEqual((st["state"], st["stats"]["sent"]), ("ok", 2))
            self.assertTrue(st["stats"]["last_sent_time"])
        finally:
            sender.stop()
            lst.close()
        self.assertFalse(sender.submit(self.event()), "после остановки события не принимаются")

    def test_udp_delivery(self):
        lst = Listener("udp")
        sender = kvm.SyslogSender("kvm.local")
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": lst.port, "protocol": "udp"})
        sender.start()
        try:
            sender.submit(self.event())
            self.assertTrue(lst.wait(1))
            self.assertTrue(lst.data[0].startswith(b"<"))
            self.assertFalse(lst.data[0].endswith(b"\n"))
        finally:
            sender.stop()
            lst.close()

    def test_failure_is_retried_with_backoff(self):
        port = free_port()
        sender = kvm.SyslogSender("kvm.local", timeout=0.5, max_backoff=0.05)
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": port, "protocol": "tcp"})
        sender.start()
        try:
            sender.submit(self.event())
            deadline = time.time() + 5
            while sender.stats["failed"] < 2 and time.time() < deadline:
                time.sleep(0.02)
            st = sender.status()
            self.assertEqual(st["state"], "error")
            self.assertGreaterEqual(st["stats"]["failed"], 1)
            self.assertEqual(st["stats"]["queued"], 1, "событие остаётся в очереди")
            self.assertTrue(st["stats"]["last_error"])
            # SIEM появилась на том же порту — очередь доставляется
            lst = socket.socket()
            lst.bind(("127.0.0.1", port))
            lst.listen(1)
            try:
                deadline = time.time() + 5
                while sender.stats["sent"] < 1 and time.time() < deadline:
                    time.sleep(0.05)
                self.assertEqual(sender.stats["sent"], 1)
            finally:
                lst.close()
        finally:
            sender.stop(flush_timeout=0.5)

    def test_queue_overflow_and_disable(self):
        sender = kvm.SyslogSender("h", queue_max=2)
        self.assertFalse(sender.submit(self.event()), "выключено — не копим")
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        for _ in range(3):
            self.assertTrue(sender.submit(self.event()))
        st = sender.status()
        self.assertEqual((st["stats"]["queued"], st["stats"]["dropped"]), (2, 1))
        sender.configure({"enabled": False, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        self.assertEqual(sender.status()["stats"]["queued"], 0)
        self.assertEqual(sender.status()["state"], "off")
        sender.stop()  # без потока — сразу

    def test_configure_change_resets_error_and_closes(self):
        sender = kvm.SyslogSender("h")
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        sender.stats.update({"last_error": "x", "last_error_time": time.time()})
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        self.assertEqual(sender.status()["state"], "error", "те же настройки — ошибка остаётся")
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": 2, "protocol": "tcp"})
        self.assertEqual(sender.status()["state"], "waiting")

    def test_tcp_alive_detects_errors(self):
        sender = kvm.SyslogSender("h")
        a, b = socket.socketpair()
        sender._sock = a
        self.assertTrue(sender._tcp_alive())
        b.close()
        self.assertFalse(sender._tcp_alive())
        a.close()
        self.assertFalse(sender._tcp_alive(), "закрытый сокет")
        sender._sock = None

    def test_send_test_event(self):
        lst = Listener("tcp")
        bus = kvm.EventBus()
        try:
            ok, err = kvm.send_test_event({"host": "127.0.0.1", "port": lst.port, "protocol": "tcp"}, "h", bus, "10.1.1.1")
            self.assertEqual((ok, err), (True, None))
            self.assertTrue(lst.wait(1))
            self.assertIn("|900|Test event|1|", lst.text())
            self.assertEqual(bus.recent()[-1]["name"], "siem_test")
        finally:
            lst.close()
        udp = Listener("udp")
        try:
            self.assertEqual(kvm.send_test_event({"host": "127.0.0.1", "port": udp.port, "protocol": "udp"}, "h"),
                             (True, None))
            self.assertTrue(udp.wait(1))
        finally:
            udp.close()
        ok, err = kvm.send_test_event({"host": "127.0.0.1", "port": free_port(), "protocol": "tcp"}, "h")
        self.assertFalse(ok)
        self.assertTrue(err)


class DeliveryStatusTest(unittest.TestCase):
    """Состояние доставки каждого события и строка, как она уходит в SIEM (для панели в интерфейсе)."""

    def test_statuses_queued_sent_dropped(self):
        sender = kvm.SyslogSender("h", queue_max=2)
        bus = kvm.EventBus()
        bus.subscribe(sender.submit)
        off = bus.emit("service_down", "while off", unit="u")
        self.assertNotIn("siem", off, "SIEM выключена — события не в очереди")
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        first = bus.emit("service_down", "1", unit="u")
        second = bus.emit("service_down", "2", unit="u")
        third = bus.emit("service_down", "3", unit="u")
        self.assertEqual([first["siem"], second["siem"], third["siem"]], ["dropped", "queued", "queued"],
                         "переполненная очередь вытесняет самое старое")
        sender.configure({"enabled": False, "host": "127.0.0.1", "port": 1, "protocol": "tcp"})
        self.assertEqual([second["siem"], third["siem"]], ["dropped", "dropped"], "выключение — очередь не отправлена")

    def test_sent_status_and_raw_line(self):
        lst = Listener("tcp")
        sender = kvm.SyslogSender("kvm.local")
        bus = kvm.EventBus()
        bus.subscribe(sender.submit)
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": lst.port, "protocol": "tcp"})
        sender.start()
        try:
            bus.emit("service_failed", "boom", unit="kaspersky-vm-worker.service", key="worker", state="failed")
            self.assertTrue(lst.wait(1))
            deadline = time.time() + 2
            while bus.recent()[-1].get("siem") != "sent" and time.time() < deadline:
                time.sleep(0.02)
            item = bus.recent(raw=lambda e: kvm.format_syslog(e, "kvm.local"))[-1]
            self.assertEqual(item["siem"], "sent")
            self.assertRegex(item["siem_time"], r"^\d{4}-\d{2}-\d{2}T")
            self.assertEqual(item["raw"] + "\n", lst.text(), "в панели — ровно та строка, что ушла в SIEM")
            self.assertIn("|202|Service failed|5|", item["raw"])
            self.assertTrue(item["raw"].startswith("<130>"))
        finally:
            sender.stop()
            lst.close()

    def test_test_event_sent_once_and_logged(self):
        lst = Listener("tcp")
        sender = kvm.SyslogSender("h")
        bus = kvm.EventBus()
        bus.subscribe(sender.submit)
        sender.configure({"enabled": True, "host": "127.0.0.1", "port": lst.port, "protocol": "tcp"})
        sender.start()
        try:
            ok, err = kvm.send_test_event({"host": "127.0.0.1", "port": lst.port, "protocol": "tcp"}, "h", bus, "10.1.1.1")
            self.assertTrue(ok, err)
            time.sleep(0.4)
            self.assertEqual(lst.text().count("|900|"), 1, "тестовое событие не дублируется через очередь")
            event = bus.recent()[-1]
            self.assertEqual((event["name"], event["siem"], event["message"]),
                             ("siem_test", "sent", "Kaspersky VM Metrics test event"))
            self.assertEqual(event["fields"], {"client": "10.1.1.1", "target": "127.0.0.1:%d/tcp" % lst.port})
        finally:
            sender.stop()
            lst.close()
        ok, err = kvm.send_test_event({"host": "127.0.0.1", "port": free_port(), "protocol": "tcp"}, "h", bus, None)
        self.assertFalse(ok)
        self.assertEqual(bus.recent()[-1]["siem"], "dropped", "неудачный тест виден в списке как «не отправлено»")


# ---------------------------------------------------------------------------
class StateMonitorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()
        self.fake = FakeSystem()
        self.log = write(os.path.join(self.dir, "worker.log"), JSON_LOG)
        self.app = make_app(self.dir, [{"key": "worker", "title_ru": "Служба", "title_en": "Worker",
                                        "path": self.log}], self.fake)
        self.mon = kvm.StateMonitor(self.app, disk_paths=())

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def names(self):
        return [e["name"] for e in self.app.events.recent()]

    def test_service_transitions(self):
        self.mon.tick()
        self.assertEqual(self.names(), [], "первый проход — только базовое состояние")
        self.fake.stop("kaspersky-vm-worker.service", failed=True)
        self.fake.stop("kaspersky-vm-vms.service")
        self.mon.tick()
        self.assertEqual(sorted(self.names()), ["service_down", "service_failed"])
        self.fake.set("kaspersky-vm-vms.service", ActiveState="activating")
        self.mon.tick()
        self.assertEqual(len(self.names()), 2, "переходные состояния не порождают событий")
        self.fake.set("kaspersky-vm-vms.service", ActiveState="active", SubState="running", MainPID=77)
        self.mon.tick()
        self.assertEqual(self.names()[-1], "service_up")
        self.fake.set("kaspersky-vm-vms.service", NRestarts=2)
        self.mon.tick()
        event = self.app.events.recent()[-1]
        self.assertEqual((event["name"], event["fields"]["count"]), ("service_auto_restart", 2))

    def test_manual_restart_is_not_reported_as_down(self):
        self.mon.tick()
        data = self.app.collector.get(force=True)
        for svc in data["services"]:
            if svc["key"] == "scanner":
                svc["state"] = "inactive"
                svc["restart"] = {"in_progress": True}
        self.mon.check_services(data)
        self.assertEqual(self.names(), [])

    def test_memory_and_disk_with_hysteresis(self):
        data = {"system": {"memory": {"total": 100, "available": 5}}, "services": []}
        self.mon.check_system(data)
        self.mon.check_system(data)
        data["system"]["memory"]["available"] = 12  # 88% — ещё не норма (гистерезис)
        self.mon.check_system(data)
        data["system"]["memory"]["available"] = 20
        self.mon.check_system(data)
        self.assertEqual(self.names(), ["memory_high", "memory_ok"])
        self.mon.check_system({"system": {"memory": {}}, "services": []})
        disks = [[{"path": "/var", "percent": 95.0}], [{"path": "/var", "percent": 87.0}],
                 [{"path": "/var", "percent": 80.0}]]
        with mock.patch.object(kvm, "disk_usage", side_effect=disks):
            for _ in disks:
                self.mon.check_system({"system": {}, "services": []})
        self.assertEqual(self.names()[2:], ["disk_high", "disk_ok"])

    def test_log_errors(self):
        self.mon.check_logs()
        self.assertEqual(self.names(), [], "старые ошибки при запуске не отправляются")
        write(self.log, '{"level":"error","timestamp":"2026-11-05T13:00:00","message":"new fail"}\n'
                        '{"level":"error","timestamp":"2026-11-05T13:00:01","message":"again', "a")
        self.mon.check_logs()
        event = self.app.events.recent()[-1]
        self.assertEqual((event["name"], event["fields"]["count"]), ("log_errors", 1))
        self.assertIn("new fail", event["message"])
        write(self.log, '"}\n', "a")  # строка дописана — учитывается один раз
        self.mon.check_logs()
        self.assertEqual(self.app.events.recent()[-1]["fields"]["count"], 1)
        self.assertEqual(len(self.names()), 2)
        self.mon.check_logs()
        self.assertEqual(len(self.names()), 2, "без новых строк — без событий")
        write(self.log, '{"level":"error","message":"after rotate"}\n')  # файл пересоздан и стал меньше
        self.mon.check_logs()
        self.assertIn("after rotate", self.app.events.recent()[-1]["message"])

    def test_new_log_file_after_start_is_read_from_beginning(self):
        pattern = os.path.join(self.dir, "vms*.log")
        self.app.log_files = [{"key": "vms", "title_en": "VMS", "path": pattern}]
        write(os.path.join(self.dir, "vms_2026.log"), '{"level":"error","message":"boot fail"}\n')
        self.mon.check_logs()
        self.assertEqual(self.names(), [], "файл, существовавший при запуске, — базовая точка")
        write(os.path.join(self.dir, "vms_2027.log"), '{"level":"error","message":"new file fail"}\n')
        os.utime(os.path.join(self.dir, "vms_2027.log"), (time.time() + 5, time.time() + 5))
        self.mon.check_logs()
        self.assertIn("new file fail", self.app.events.recent()[-1]["message"])

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_log_read_error_skipped(self):
        with mock.patch.object(kvm, "scan_log_levels", side_effect=OSError("denied")):
            self.mon.check_logs()
        self.assertEqual(self.mon.log_offsets, {})

    def test_tick_scans_logs_by_interval_and_run_stops(self):
        clock = [0.0]
        mon = kvm.StateMonitor(self.app, clock=lambda: clock[0], log_scan_interval=60, disk_paths=())
        mon.tick()
        first = mon.last_log_scan
        clock[0] = 30
        mon.tick()
        self.assertEqual(mon.last_log_scan, first)
        clock[0] = 61
        mon.tick()
        self.assertEqual(mon.last_log_scan, 61)
        stop = threading.Event()
        calls = []

        def tick():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")  # ошибка не останавливает монитор
            stop.set()
        mon.tick = tick
        mon.run(stop, interval=0.01)
        self.assertEqual(len(calls), 2)


class RestartEventsTest(unittest.TestCase):
    def test_restart_lifecycle_events(self):
        fake = FakeSystem(restart_delay=0)
        rm = kvm.RestartManager(runner=fake, clock=MONO, settle=0, timeout=30)
        bus = kvm.EventBus()
        rm.events = bus
        svc = kvm.SERVICES[0]
        rm.start(svc, 1, "10.0.0.2")
        rm.annotate([{"key": svc["key"], "unit": svc["unit"], "state": "active", "since_mono": 2, "restart": None}])
        self.assertEqual([e["name"] for e in bus.recent()], ["restart_requested", "restart_ok"])
        rm.start(svc, 2, "10.0.0.2")
        rm.annotate([{"key": svc["key"], "unit": svc["unit"], "state": "failed", "since_mono": 2, "restart": None}])
        self.assertEqual(bus.recent()[-1]["name"], "restart_failed")
        fake.fail_restart.add(svc["unit"])
        rm.start(svc, 2, "10.0.0.2")
        last = bus.recent()[-1]
        self.assertEqual((last["name"], last["fields"]["outcome"]), ("restart_failed", "failure"))

    def test_timeout_event(self):
        clock = [0.0]
        rm = kvm.RestartManager(runner=FakeSystem(), clock=lambda: clock[0], settle=0, timeout=5)
        bus = kvm.EventBus()
        rm.events = bus
        svc = kvm.SERVICES[1]
        rm.start(svc, 1, "c")
        clock[0] = 10
        rm.annotate([{"key": svc["key"], "unit": svc["unit"], "state": "activating", "since_mono": 1, "restart": None}])
        self.assertEqual(bus.recent()[-1]["name"], "restart_timeout")

    def test_no_bus_is_fine(self):
        rm = kvm.RestartManager(runner=FakeSystem())
        rm.emit("restart_ok", "x")


# ---------------------------------------------------------------------------
class ReportSiemHttpTest(unittest.TestCase):
    HDRS = {"X-Requested-With": "kvm-metrics", "Content-Type": "application/json"}

    def setUp(self):
        self.srv = ServerFixture()
        self.lst = Listener("tcp")

    def tearDown(self):
        self.srv.app.siem.stop(flush_timeout=0.2)
        self.lst.close()
        self.srv.close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=15)
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def post(self, path, body, headers=None):
        hdrs = dict(self.HDRS)
        hdrs.update(headers or {})
        resp, data = self.request("POST", path, body, hdrs)
        return resp.status, json.loads(data.decode("utf-8"))

    def siem_body(self, **kw):
        body = {"password": ServerFixture.PASSWORD, "enabled": True, "host": "127.0.0.1",
                "port": self.lst.port, "protocol": "tcp"}
        body.update(kw)
        return body

    def test_report_now(self):
        before = sorted(os.listdir(self.srv.tmp))
        resp, data = self.request("GET", "/api/report-now")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertRegex(resp.getheader("Content-Disposition"),
                         r'attachment; filename="kaspersky-vm-services-state_\d{2}_\d{2}_\d{4}_\d{6}\.json"')
        report = json.loads(data.decode("utf-8"))
        self.assertEqual(report["kind"], "on-demand")
        self.assertEqual(report["host"], "kvm-test.local")
        self.assertEqual([entry["key"] for entry in report["logs"]], ["scanner", "missing"])
        self.assertEqual(sorted(os.listdir(self.srv.tmp)), before, "отчёт по требованию не сохраняется на диск")

    def test_json_report_download_content_type(self):
        name = kvm.REPORT_PREFIX + "29_10_2026.json"
        write(os.path.join(self.srv.tmp, name), '{"a": 1}')
        resp, data = self.request("GET", "/log?file=" + name)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertEqual(data, b'{"a": 1}')

    def test_siem_get_and_status(self):
        resp, data = self.request("GET", "/api/siem")
        payload = json.loads(data.decode("utf-8"))
        self.assertEqual(payload["recommended"], {"protocol": "tcp", "port": 5144, "standard_port": 514})
        self.assertEqual(payload["config"]["state"], "off")
        self.assertEqual(len(payload["events"]), len(kvm.EVENT_TYPES))
        self.assertEqual([e["signature"] for e in payload["events"]], sorted(e["signature"] for e in payload["events"]))
        resp, data = self.request("GET", "/api/status")
        self.assertEqual(json.loads(data.decode("utf-8"))["siem"], {"state": "off", "enabled": False})

    def test_save_settings_and_forward_events(self):
        self.srv.app.siem.start()
        status, payload = self.post("/api/siem", self.siem_body())
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["config"]["host"], "127.0.0.1")
        path = os.path.join(self.srv.tmp, "settings.json")
        self.assertEqual(kvm.load_settings(path)["siem"]["port"], self.lst.port)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertTrue(self.lst.wait(1), "событие об изменении настроек ушло в SIEM")
        self.assertIn("|310|SIEM forwarding settings changed|", self.lst.text())
        self.assertEqual(payload["recent"][0]["name"], "settings_changed")
        # неверный пароль — событие auth_failed тоже уходит в SIEM
        status, payload = self.post("/api/services/scanner/restart", {"password": "wrong"})
        self.assertEqual(status, 401)
        self.assertTrue(self.lst.wait(2))
        self.assertIn("|300|Wrong root password|", self.lst.text())
        self.assertIn("src=127.0.0.1", self.lst.text())
        # выключение
        status, payload = self.post("/api/siem", self.siem_body(enabled=False, host=""))
        self.assertEqual(status, 200)
        self.assertEqual(payload["config"]["state"], "off")

    def test_save_validation_and_auth(self):
        status, payload = self.post("/api/siem", self.siem_body(port=99999))
        self.assertEqual((status, payload["error"]), (400, "bad_port"))
        status, payload = self.post("/api/siem", self.siem_body(), headers={"X-Requested-With": "x"})
        self.assertEqual((status, payload["error"]), (403, "csrf"))
        self.assertEqual(self.srv.app.events.recent()[-1]["name"], "csrf_rejected")
        status, payload = self.post("/api/siem", self.siem_body(password="nope"))
        self.assertEqual((status, payload["error"]), (401, "bad_password"))
        resp, data = self.request("POST", "/api/siem", b"not json", self.HDRS)
        self.assertEqual(resp.status, 400)
        self.assertFalse(os.path.exists(os.path.join(self.srv.tmp, "settings.json")))

    def test_lockout_emits_auth_locked(self):
        for _ in range(3):
            status, payload = self.post("/api/siem", self.siem_body(password="nope"))
        self.assertEqual((status, payload["error"]), (429, "locked"))
        self.assertEqual(self.srv.app.events.recent()[-1]["name"], "auth_locked")

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_save_failure(self):
        with mock.patch.object(kvm, "save_settings", side_effect=OSError("read-only")):
            status, payload = self.post("/api/siem", self.siem_body())
        self.assertEqual((status, payload["error"], payload["message"]), (500, "save_failed", "read-only"))

    def test_test_event_endpoint(self):
        status, payload = self.post("/api/siem/test", self.siem_body())
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["target"], "127.0.0.1:%d" % self.lst.port)
        self.assertTrue(self.lst.wait(1))
        self.assertIn("Test event", self.lst.text())
        resp, data = self.request("GET", "/api/siem")
        recent = json.loads(data.decode("utf-8"))["recent"]
        self.assertEqual((recent[0]["name"], recent[0]["siem"]), ("siem_test", "sent"))
        self.assertEqual(recent[0]["raw"] + "\n", self.lst.text(), "в API — ровно отправленная строка")
        status, payload = self.post("/api/siem/test", self.siem_body(port=free_port()))
        self.assertEqual((status, payload["error"]), (502, "send_failed"))
        status, payload = self.post("/api/siem/test", self.siem_body(host=""))
        self.assertEqual((status, payload["error"]), (400, "host_required"))
        status, payload = self.post("/api/siem/test", self.siem_body(password="x"))
        self.assertEqual(status, 401)
        self.assertFalse(os.path.exists(os.path.join(self.srv.tmp, "settings.json")), "тест не сохраняет настройки")

    def test_recent_five_and_all_events(self):
        bus = self.srv.app.events
        for i in range(12):
            bus.emit("auth_failed", "Wrong root password (restart), attempts left: %d" % i, client="10.0.0.%d" % i)
        resp, data = self.request("GET", "/api/siem")
        payload = json.loads(data.decode("utf-8"))
        total = payload["total"]
        self.assertGreaterEqual(total, 12)
        self.assertEqual(len(payload["recent"]), 5, "в панели — 5 последних событий")
        self.assertIn("attempts left: 11", payload["recent"][0]["message"], "новые сверху")
        resp, data = self.request("GET", "/api/siem/events?lines=3")
        ev = json.loads(data.decode("utf-8"))
        self.assertEqual((ev["kind"], ev["total"], ev["has_more"], len(ev["lines"])), ("siem", total, True, 3))
        self.assertIn("attempts left: 9", ev["lines"][0], "в окне — от старых к новым")
        self.assertIn("attempts left: 11", ev["lines"][-1])
        self.assertTrue(ev["lines"][-1].startswith("<132>"))
        self.assertIn("|Kaspersky VM Metrics|", ev["lines"][-1])
        resp, data = self.request("GET", "/api/siem/events?lines=1000")
        ev = json.loads(data.decode("utf-8"))
        self.assertEqual((len(ev["lines"]), ev["has_more"]), (total, False))
        resp, data = self.request("GET", "/api/siem/events?lines=bad")
        self.assertEqual(len(json.loads(data.decode("utf-8"))["lines"]), min(total, kvm.TAIL_DEFAULT))


class MainLifecycleTest(unittest.TestCase):
    def test_sigterm_handler(self):
        with self.assertRaises(SystemExit):
            kvm._sigterm(15, None)
        result = []
        th = threading.Thread(target=lambda: result.append(kvm.install_sigterm_handler()))
        th.start()
        th.join()
        self.assertEqual(result, [False], "вне главного потока обработчик не ставится")
        if mock is not None:
            with mock.patch.object(kvm.signal, "signal") as sig:
                self.assertTrue(kvm.install_sigterm_handler())
            sig.assert_called_once_with(kvm.signal.SIGTERM, kvm._sigterm)


if __name__ == "__main__":
    unittest.main()
