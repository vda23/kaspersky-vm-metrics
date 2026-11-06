# -*- coding: utf-8 -*-
import os
import time
import unittest
import zipfile
import io
import json
from datetime import datetime, timedelta

from helpers import MONO, FakeSystem, TempDir, kvm


def write(path, data, mode="wb"):
    with open(path, mode) as fh:
        fh.write(data)
    return path


class TailCommandTest(unittest.TestCase):
    def test_root_runs_plain_tail(self):
        self.assertEqual(kvm.tail_command("/var/log/a.log", 50, euid=0),
                         ["tail", "-n", "50", "--", "/var/log/a.log"])

    def test_non_root_uses_sudo_without_password_prompt(self):
        self.assertEqual(kvm.tail_command("/var/log/a.log", 50, euid=1000),
                         ["sudo", "-n", "tail", "-n", "50", "--", "/var/log/a.log"])

    def test_never_follows(self):
        # «tail -f» не завершается и подвесил бы HTTP-запрос
        for euid in (0, 1000):
            self.assertNotIn("-f", kvm.tail_command("/x", 50, euid=euid))

    def test_count_is_integer(self):
        self.assertEqual(kvm.tail_command("/x", 7.9, euid=0)[2], "7")

    def test_classify_errors(self):
        R = kvm.CmdResult
        cases = [
            (R(1, "", "tail: cannot open '/x' for reading: No such file or directory"), ("file_not_found", 404)),
            (R(1, "", "tail: cannot open '/x' for reading: Permission denied"), ("permission_denied", 403)),
            (R(1, "", "sudo: a password is required"), ("permission_denied", 403)),
            (R(1, "", "sudo: a terminal is required to read the password"), ("permission_denied", 403)),
            (R(124, "", "timeout"), ("timeout", 504)),
            (R(1, "", "tail: error reading '/x': Is a directory"), ("read_error", 500)),
        ]
        for res, expected in cases:
            self.assertEqual(kvm.classify_tail_error(res), expected, res.err)


class ReadLogTailTest(unittest.TestCase):
    """read_log_tail с настоящим tail (coreutils) по реальным файлам."""

    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def lines_file(self, count, newline_end=True, name="a.log"):
        body = "\n".join("line %d" % i for i in range(1, count + 1))
        if newline_end:
            body += "\n"
        return write(os.path.join(self.dir, name), body.encode("utf-8"))

    def tail(self, path, count, runner=None):
        return kvm.read_log_tail(runner or kvm.run_cmd, path, count, euid=0)

    def test_last_50_of_many(self):
        path = self.lines_file(1000)
        lines, code, status, command, _ = self.tail(path, 50)
        self.assertIsNone(code)
        self.assertEqual(status, 200)
        self.assertEqual(len(lines), 50)
        self.assertEqual(lines[0], "line 951")
        self.assertEqual(lines[-1], "line 1000")
        self.assertEqual(command, "tail -n 50 -- " + path)

    def test_fewer_lines_than_requested(self):
        lines = self.tail(self.lines_file(10), 50)[0]
        self.assertEqual(lines, ["line %d" % i for i in range(1, 11)])

    def test_no_trailing_newline(self):
        self.assertEqual(self.tail(self.lines_file(5, newline_end=False), 2)[0], ["line 4", "line 5"])

    def test_empty_file(self):
        path = write(os.path.join(self.dir, "empty.log"), b"")
        self.assertEqual(self.tail(path, 50)[0], [])

    def test_crlf_ansi_and_bad_utf8(self):
        path = write(os.path.join(self.dir, "w.log"), b"a\r\n\x1b[31mred\x1b[0m\r\n\xff\xfe bad\r\n")
        lines = self.tail(path, 10)[0]
        self.assertEqual(lines[0], "a")
        self.assertEqual(lines[1], "red")
        self.assertIn("bad", lines[2])

    def test_cyrillic(self):
        path = write(os.path.join(self.dir, "ru.log"), "первая\nвторая\n".encode("utf-8"))
        self.assertEqual(self.tail(path, 1)[0], ["вторая"])

    def test_very_long_line_truncated(self):
        path = write(os.path.join(self.dir, "long.log"), b"x" * (kvm.TAIL_MAX_LINE + 500) + b"\n")
        self.assertEqual(len(self.tail(path, 1)[0][0]), kvm.TAIL_MAX_LINE + 2)

    def test_missing_file(self):
        lines, code, status, _, message = self.tail(os.path.join(self.dir, "nope.log"), 5)
        self.assertIsNone(lines)
        self.assertEqual((code, status), ("file_not_found", 404))
        self.assertIn("No such file", message)

    def test_path_with_spaces_and_shell_chars_is_one_argument(self):
        name = "-weird name; touch pwned $(id).log"
        path = write(os.path.join(self.dir, name), b"ok\n")
        lines, code, _, _, _ = self.tail(path, 5)
        self.assertIsNone(code)
        self.assertEqual(lines, ["ok"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "pwned")))

    def test_runner_receives_command_and_timeout(self):
        seen = {}

        def runner(args, timeout=5, c_locale=True):
            seen["args"], seen["timeout"] = args, timeout
            return kvm.CmdResult(0, "a\nb\nc\n", "")
        lines, code, _, _, _ = kvm.read_log_tail(runner, "/var/log/x.log", 2, euid=1000)
        self.assertEqual(lines, ["b", "c"])
        self.assertEqual(seen["args"], ["sudo", "-n", "tail", "-n", "2", "--", "/var/log/x.log"])
        self.assertEqual(seen["timeout"], 10)

    def test_sudo_denied(self):
        runner = lambda args, timeout=5, c_locale=True: kvm.CmdResult(1, "", "sudo: a password is required")
        lines, code, status, command, _ = kvm.read_log_tail(runner, "/var/log/x.log", 50, euid=1000)
        self.assertEqual((code, status), ("permission_denied", 403))
        self.assertTrue(command.startswith("sudo -n tail -n 50 -- "))


class DefaultLogFilesTest(unittest.TestCase):
    def test_worker_path_from_requirements(self):
        files = dict((f["key"], f) for f in kvm.normalize_log_files(kvm.LOG_FILES))
        self.assertEqual(files["worker"]["path"], "/var/log/kaspersky/vulnerability-management/worker/worker.log")
        self.assertEqual(len(files), len(kvm.LOG_FILES))
        service_keys = set(s["key"] for s in kvm.SERVICES)
        for f in files.values():
            self.assertIn(f["service"], service_keys)
            self.assertTrue(f["path"].startswith("/var/log/kaspersky/vulnerability-management/"))


class ResolveTest(unittest.TestCase):
    def test_glob_picks_newest(self):
        with TempDir() as d:
            old = write(os.path.join(d, "svc-1.log"), b"old")
            new = write(os.path.join(d, "svc-2.log"), b"new")
            os.utime(old, (time.time() - 100, time.time() - 100))
            self.assertEqual(kvm.resolve_log_path(os.path.join(d, "svc-*.log")), new)
            self.assertIsNone(kvm.resolve_log_path(os.path.join(d, "none-*.log")))

    def test_plain_path(self):
        self.assertEqual(kvm.resolve_log_path("/var/log/x.log"), "/var/log/x.log")

    def test_file_meta(self):
        with TempDir() as d:
            path = write(os.path.join(d, "m.log"), b"12345")
            meta = kvm.file_meta(path)
            self.assertTrue(meta["exists"])
            self.assertEqual(meta["size"], 5)
            self.assertFalse(kvm.file_meta(os.path.join(d, "x"))["exists"])


class ReportsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def make(self, name, data=b"report"):
        return write(os.path.join(self.dir, name), data)

    def test_list_filters_and_sorts_by_date(self):
        self.make("kaspersky-vm-services-state_02_01_2026.json")
        self.make("kaspersky-vm-services-state_31_12_2025.json")
        self.make("kaspersky-vm-services-state_10_01_2026.json")
        self.make("kaspersky-vm-services-state_bad.json")
        self.make("kaspersky-vm-services-state_04_01_2026.txt")
        self.make("kaspersky-vm-services-state_03_01_2026.log")
        self.make("other.txt")
        reports = kvm.list_reports(self.dir)
        names = [r["name"] for r in reports]
        self.assertEqual(names, ["kaspersky-vm-services-state_10_01_2026.json",
                                 "kaspersky-vm-services-state_02_01_2026.json",
                                 "kaspersky-vm-services-state_31_12_2025.json"])

    def test_list_missing_dir(self):
        self.assertEqual(kvm.list_reports(os.path.join(self.dir, "missing")), [])

    def test_report_path_rejects_traversal(self):
        self.make("kaspersky-vm-services-state_01_01_2026.json")
        self.assertIsNotNone(kvm.report_path("kaspersky-vm-services-state_01_01_2026.json", self.dir))
        for bad in ("../../etc/passwd", "kaspersky-vm-services-state_/../../etc/shadow",
                    "kaspersky-vm-services-state_01_01_2026.json/..", "/etc/passwd", "", None, 5,
                    "kaspersky-vm-services-state_02_01_2026.json"):
            self.assertIsNone(kvm.report_path(bad, self.dir), bad)

    def test_zip(self):
        self.make("kaspersky-vm-services-state_01_01_2026.json", b"one")
        self.make("kaspersky-vm-services-state_02_01_2026.json", b"two")
        data, added = kvm.build_reports_zip(["kaspersky-vm-services-state_01_01_2026.json",
                                             "kaspersky-vm-services-state_02_01_2026.json",
                                             "../../etc/passwd"], self.dir)
        self.assertEqual(added, 2)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            self.assertEqual(sorted(zf.namelist()), ["kaspersky-vm-services-state_01_01_2026.json",
                                                     "kaspersky-vm-services-state_02_01_2026.json"])
            self.assertEqual(zf.read("kaspersky-vm-services-state_02_01_2026.json"), b"two")
        self.assertEqual(os.listdir(self.dir).__len__(), 2)  # архив не пишется на диск

    def test_write_daily_report_json(self):
        fake = FakeSystem()
        fake.stop("kaspersky-vm-worker.service", failed=True)
        collector = kvm.StatusCollector(kvm.SERVICES, runner=fake, clock=MONO)
        collector.fqdn = "kvm.test.local"
        app = kvm.App(collector=collector, runner=fake, log_dir=self.dir, log_files=[],
                      settings_path=os.path.join(self.dir, "settings.json"))
        path = kvm.write_daily_report(app, self.dir, datetime(2026, 10, 28, 19, 0, 5))
        self.assertEqual(os.path.basename(path), "kaspersky-vm-services-state_28_10_2026.json")
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["report"], "kaspersky-vm-services-state")
        self.assertEqual(report["kind"], "daily")
        self.assertEqual(report["host"], "kvm.test.local")
        self.assertTrue(report["generated"].startswith("2026-10-28T19:00:05"))
        self.assertEqual(report["summary"]["status"], "critical")
        self.assertEqual(report["summary"]["services_not_running"], ["worker"])
        worker = [s for s in report["services"] if s["key"] == "worker"][0]
        self.assertEqual((worker["state"], worker["pid"]), ("failed", 0))
        self.assertIn("disks", report["system"])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o644")
        self.assertFalse([n for n in os.listdir(self.dir) if n.startswith(".report-")])
        self.assertEqual(app.events.recent()[-1]["name"], "report_created")

    def test_cleanup_old_reports(self):
        old = self.make("kaspersky-vm-services-state_01_01_2020.json")
        fresh = self.make("kaspersky-vm-services-state_02_01_2020.json")
        other = self.make("keep-me.txt")
        past = time.time() - 8 * 86400
        for path in (old, other):
            os.utime(path, (past, past))
        self.assertEqual(kvm.cleanup_old_reports(self.dir), 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(fresh))
        self.assertTrue(os.path.exists(other))

    def test_report_due(self):
        day = datetime(2026, 10, 28, 19, 0, 30)
        self.assertTrue(kvm.report_due(day, None, self.dir))
        self.assertFalse(kvm.report_due(day.replace(hour=18, minute=59), None, self.dir))
        self.assertFalse(kvm.report_due(day, day.date(), self.dir))
        self.assertTrue(kvm.report_due(day.replace(hour=23), (day - timedelta(days=1)).date(), self.dir))
        self.make("kaspersky-vm-services-state_28_10_2026.json")
        self.assertFalse(kvm.report_due(day, None, self.dir))


if __name__ == "__main__":
    unittest.main()
