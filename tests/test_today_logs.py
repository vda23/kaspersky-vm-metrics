# -*- coding: utf-8 -*-
"""Скачивание логов компонентов за сегодня: поиск начала дня, архив, HTTP."""
import http.client
import io
import os
import random
import time
import unittest
import zipfile
from datetime import date, datetime, timedelta

from helpers import ServerFixture, TempDir, kvm

DAY = date(2026, 11, 3)
NOW = datetime(2026, 11, 3, 17, 5, 0)


def write_log(path, days, per_day=50, stack_every=0, fmt="{d:%Y-%m-%d} {h:02d}:{m:02d}:00 INFO line {n}"):
    """Лог с записями за несколько дней по порядку; stack_every — строки продолжения без даты."""
    n = 0
    with open(path, "w") as fh:
        for day in days:
            for i in range(per_day):
                n += 1
                fh.write(fmt.format(d=day, h=i // 60 % 24, m=i % 60, n=n) + "\n")
                if stack_every and n % stack_every == 0:
                    fh.write("Traceback (most recent call last):\n  File \"x.py\", line 1\nValueError: boom\n")
    return path


class LineDateTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(kvm.line_date(b"2026-11-03 17:02:17 INFO x"), DAY)
        self.assertEqual(kvm.line_date(b"2026-11-03T17:02:17.123+03:00 x"), DAY)
        self.assertEqual(kvm.line_date(b"[2026-11-03 17:02:17] x"), DAY)
        self.assertEqual(kvm.line_date(b"03.11.2026 17:02:17 x"), DAY)
        self.assertEqual(kvm.line_date(b"03.11.2026,17:02 x"), DAY)
        self.assertEqual(kvm.line_date(b"2026/11/03 17:02:17 x"), DAY)

    def test_not_dates(self):
        for line in (b"  File \"x.py\", line 1", b"Traceback", b"", b"2026-13-45 10:00:00 bad", b"x 2026-11-03 10:00"):
            self.assertIsNone(kvm.line_date(line), line)


class TodayOffsetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def first_today_line(self, path):
        with open(path, "rb") as fh:
            data = fh.read()
        start = kvm.today_offset(path, DAY)
        return start, data[start:].split(b"\n", 1)[0] if start is not None and start < len(data) else b""

    def test_mixed_days(self):
        path = write_log(os.path.join(self.dir, "a.log"), [DAY - timedelta(days=2), DAY - timedelta(days=1), DAY])
        start, line = self.first_today_line(path)
        self.assertTrue(line.startswith(b"2026-11-03 00:00:00"), line)
        with open(path, "rb") as fh:
            fh.seek(start)
            self.assertEqual(fh.read().count(b"\n"), 50)

    def test_all_today(self):
        path = write_log(os.path.join(self.dir, "a.log"), [DAY])
        self.assertEqual(kvm.today_offset(path, DAY), 0)

    def test_nothing_today(self):
        path = write_log(os.path.join(self.dir, "a.log"), [DAY - timedelta(days=1)])
        self.assertEqual(kvm.today_offset(path, DAY), os.path.getsize(path))

    def test_undated_file(self):
        path = os.path.join(self.dir, "a.log")
        with open(path, "w") as fh:
            fh.write("no dates here\n" * 100)
        self.assertIsNone(kvm.today_offset(path, DAY))

    def test_empty_file(self):
        path = os.path.join(self.dir, "a.log")
        open(path, "w").close()
        self.assertIsNone(kvm.today_offset(path, DAY))

    def test_stack_traces_before_today(self):
        path = write_log(os.path.join(self.dir, "a.log"), [DAY - timedelta(days=1), DAY], stack_every=7)
        start, line = self.first_today_line(path)
        self.assertTrue(line.startswith(b"2026-11-03 "), line)

    def test_russian_date_format(self):
        path = write_log(os.path.join(self.dir, "a.log"), [DAY - timedelta(days=1), DAY],
                         fmt="{d:%d.%m.%Y} {h:02d}:{m:02d}:00 line {n}")
        start, line = self.first_today_line(path)
        self.assertTrue(line.startswith(b"03.11.2026 00:00:00"), line)

    def test_binary_search_matches_linear_scan(self):
        rnd = random.Random(42)
        for case in range(25):
            days = [DAY - timedelta(days=k) for k in range(rnd.randint(1, 4), 0, -1)]
            if rnd.random() < 0.8:
                days.append(DAY)
            path = write_log(os.path.join(self.dir, "r%d.log" % case), days, per_day=rnd.randint(1, 3000),
                             stack_every=rnd.choice([0, 3, 50]))
            with open(path, "rb") as fh:
                data = fh.read()
            expected = len(data)
            pos = 0
            for raw in data.split(b"\n"):
                if kvm.line_date(raw) == DAY:
                    expected = pos
                    break
                pos += len(raw) + 1
            self.assertEqual(kvm.today_offset(path, DAY), expected, "case %d" % case)


class TodayZipTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()
        midday = datetime(2026, 11, 3, 12, 0).timestamp()
        yesterday = datetime(2026, 11, 2, 12, 0).timestamp()
        self.worker = write_log(os.path.join(self.dir, "worker.log"), [DAY - timedelta(days=1), DAY])
        os.makedirs(os.path.join(self.dir, "vms"))
        self.vms_old = write_log(os.path.join(self.dir, "vms", "vms_2026-11-01T080000.log"), [DAY - timedelta(days=2)])
        self.vms_mid = write_log(os.path.join(self.dir, "vms", "vms_2026-11-02T090000.log"), [DAY - timedelta(days=1), DAY])
        self.vms_new = write_log(os.path.join(self.dir, "vms", "vms_2026-11-03T095411.log"), [DAY])
        self.plain = os.path.join(self.dir, "plain.log")
        with open(self.plain, "w") as fh:
            fh.write("undated line\n" * 10)
        self.stale = write_log(os.path.join(self.dir, "stale.log"), [DAY - timedelta(days=1)])
        for path in (self.worker, self.vms_mid, self.vms_new, self.plain):
            os.utime(path, (midday, midday))
        for path in (self.vms_old, self.stale):
            os.utime(path, (yesterday, yesterday))
        self.files = [
            {"key": "worker", "path": self.worker},
            {"key": "vms", "path": os.path.join(self.dir, "vms", "vms*.log")},
            {"key": "plain", "path": self.plain},
            {"key": "stale", "path": self.stale},
            {"key": "missing", "path": os.path.join(self.dir, "nope.log")},
        ]

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def build(self, files=None):
        buf = io.BytesIO()
        included = kvm.build_today_logs_zip(files if files is not None else self.files, buf, now=NOW, host="kvm.test")
        buf.seek(0)
        return zipfile.ZipFile(buf), included

    def test_contents(self):
        zf, included = self.build()
        names = sorted(zf.namelist())
        self.assertEqual(names, ["README.txt", "plain/plain.log", "vms/vms_2026-11-02T090000.log",
                                 "vms/vms_2026-11-03T095411.log", "worker/worker.log"])
        worker = zf.read("worker/worker.log").decode()
        self.assertEqual(worker.count("\n"), 50)
        self.assertTrue(worker.startswith("2026-11-03 00:00:00"))
        self.assertNotIn("2026-11-02", worker)
        self.assertNotIn("2026-11-02", zf.read("vms/vms_2026-11-02T090000.log").decode(),
                         "из файла, начатого вчера, берутся только строки за сегодня")
        self.assertEqual(zf.read("plain/plain.log").decode().count("\n"), 10, "формат не распознан — файл целиком")
        readme = zf.read("README.txt").decode()
        self.assertIn("Logs for: 03.11.2026", readme)
        self.assertIn("Host: kvm.test", readme)
        self.assertIn("whole-file", readme)
        modes = dict((e["file"], e["mode"]) for e in included)
        self.assertEqual(modes[self.worker], "today")

    def test_no_logs_today(self):
        zf, included = self.build([{"key": "stale", "path": self.stale}])
        self.assertEqual(zf.namelist(), ["README.txt"])
        self.assertIn("No component log entries for today", zf.read("README.txt").decode())
        self.assertEqual(included, [])

    def test_unreadable_file_reported(self):
        original = kvm.today_offset

        def boom(path, day):
            raise IOError("Permission denied")
        kvm.today_offset = boom
        try:
            zf, included = self.build([{"key": "worker", "path": self.worker}])
        finally:
            kvm.today_offset = original
        self.assertIn("error: Permission denied", zf.read("README.txt").decode())

    def test_no_temp_files_left(self):
        import tempfile
        before = set(os.listdir(tempfile.gettempdir()))
        self.build()
        leftovers = [n for n in set(os.listdir(tempfile.gettempdir())) - before if n.startswith(".kvm-logs-")]
        self.assertEqual(leftovers, [])


class DayZipTest(TodayZipTest):
    """Архив за выбранный прошлый день: границы дня, ротированные копии (в том числе .gz)."""

    def build_day(self, day, files=None):
        buf = io.BytesIO()
        included = kvm.build_today_logs_zip(files if files is not None else self.files, buf, now=NOW,
                                            host="kvm.test", day=day)
        buf.seek(0)
        return zipfile.ZipFile(buf), included

    def test_yesterday(self):
        zf, included = self.build_day(DAY - timedelta(days=1))
        worker = zf.read("worker/worker.log").decode()
        self.assertEqual(worker.count("\n"), 50, "только строки за вчера — до начала сегодняшнего дня")
        self.assertTrue(worker.startswith("2026-11-02 00:00:00"))
        self.assertNotIn("2026-11-03", worker)
        self.assertEqual(zf.read("stale/stale.log").decode().count("\n"), 50, "файл не менялся после того дня — до конца")
        self.assertNotIn("vms/vms_2026-11-01T080000.log", zf.namelist(), "изменён до выбранного дня")
        self.assertNotIn("2026-11-03", zf.read("vms/vms_2026-11-02T090000.log").decode())
        self.assertNotIn("plain/plain.log", zf.namelist(), "без дат, изменён позже — не относится к дню")
        readme = zf.read("README.txt").decode()
        self.assertIn("Logs for: 02.11.2026", readme)
        self.assertEqual(dict((e["file"], e["mode"]) for e in included)[self.worker], "day")

    def test_rotated_copies(self):
        import gzip
        two_days = DAY - timedelta(days=2)
        rotated = write_log(self.worker + ".1", [two_days - timedelta(days=1), two_days])
        gz_src = write_log(os.path.join(self.dir, "src.log"), [two_days, two_days + timedelta(days=1)], stack_every=7)
        with open(gz_src, "rb") as src, gzip.open(self.worker + "-20261102.gz", "wb") as dst:
            dst.write(src.read())
        undated = self.worker + ".2.gz"
        with gzip.open(undated, "wb") as dst:
            dst.write(b"undated\n")
        late = datetime(2026, 11, 2, 1, 0).timestamp()
        for path in (rotated, self.worker + "-20261102.gz", undated):
            os.utime(path, (late, late))
        zf, included = self.build_day(two_days, [{"key": "worker", "path": self.worker}])
        names = sorted(zf.namelist())
        self.assertEqual(names, ["README.txt", "worker/worker.log-20261102", "worker/worker.log.1"])
        plain = zf.read("worker/worker.log.1").decode()
        self.assertEqual(plain.count("\n"), 50)
        self.assertTrue(plain.startswith("2026-11-01"))
        gz = zf.read("worker/worker.log-20261102").decode()
        self.assertTrue(gz.startswith("2026-11-01 00:00:00"))
        self.assertNotIn("2026-11-02", gz)
        self.assertIn("Traceback", gz, "строки продолжения сохраняются")
        modes = dict((os.path.basename(e["file"]), e["mode"]) for e in included)
        self.assertNotIn("worker.log.2.gz", modes, "в .gz без дат нечего выбирать")
        self.assertEqual(modes["worker.log-20261102.gz"], "day")

    def test_broken_gz_reported(self):
        bad = self.worker + ".9.gz"
        with open(bad, "wb") as fh:
            fh.write(b"not gzip")
        zf, included = self.build_day(DAY - timedelta(days=1), [{"key": "worker", "path": self.worker}])
        self.assertIn("worker.log.9.gz", zf.read("README.txt").decode())
        self.assertTrue([e for e in included if e["file"] == bad and e["mode"].startswith("error")])

    def test_no_logs_for_day(self):
        zf, included = self.build_day(date(2025, 1, 1), [{"key": "worker", "path": os.path.join(self.dir, "nope.log")}])
        self.assertIn("No component log entries for 01.01.2025.", zf.read("README.txt").decode())

    def test_parse_day(self):
        self.assertEqual(kvm.parse_day("2026-11-02"), date(2026, 11, 2))
        today = date.today()
        self.assertEqual(kvm.parse_day(today.isoformat()), today)
        for bad in ("", None, "2026-13-01", "02.11.2026", (today + timedelta(days=1)).isoformat(), "1969-12-31"):
            self.assertIsNone(kvm.parse_day(bad), bad)


class TodayHttpTest(unittest.TestCase):
    def test_endpoint(self):
        srv = ServerFixture()
        try:
            now = time.time()
            with open(srv.log_path, "a") as fh:
                fh.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " INFO today's entry\n")
            os.utime(srv.log_path, (now, now))
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=20)
            conn.request("GET", "/logs-today")
            resp = conn.getresponse()
            data = resp.read()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("Content-Type"), "application/zip")
            disposition = resp.getheader("Content-Disposition")
            self.assertIn("kaspersky-vm-logs_kvm-test.local_%s.zip" % datetime.now().strftime("%d_%m_%Y"), disposition)
            self.assertEqual(int(resp.getheader("Content-Length")), len(data))
            zf = zipfile.ZipFile(io.BytesIO(data))
            self.assertIn("scanner/scanner.log", zf.namelist())
            self.assertIn("today's entry", zf.read("scanner/scanner.log").decode())
            conn.request("HEAD", "/logs-today")
            resp = conn.getresponse()
            self.assertEqual(resp.read(), b"")
            self.assertEqual(resp.status, 200)
            yesterday = date.today() - timedelta(days=1)
            conn.request("GET", "/logs-day?date=" + yesterday.isoformat())
            resp = conn.getresponse()
            data = resp.read()
            self.assertEqual(resp.status, 200)
            self.assertIn("kaspersky-vm-logs_kvm-test.local_%s.zip" % yesterday.strftime("%d_%m_%Y"),
                          resp.getheader("Content-Disposition"))
            self.assertIn("Logs for: %s" % yesterday.strftime("%d.%m.%Y"),
                          zipfile.ZipFile(io.BytesIO(data)).read("README.txt").decode())
            for bad in ("", "?date=tomorrow", "?date=" + (date.today() + timedelta(days=1)).isoformat()):
                conn.request("GET", "/logs-day" + bad)
                resp = conn.getresponse()
                body = resp.read()
                self.assertEqual(resp.status, 400, bad)
                self.assertIn(b"bad_date", body)
            conn.close()
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
