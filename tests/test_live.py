# -*- coding: utf-8 -*-
"""Real-time просмотр логов (SSE + tail -F / journalctl -f) и встроенный логотип."""
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
import unittest

from helpers import ServerFixture, TempDir, kvm

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    mock = None


def py_cmd(code):
    return [sys.executable, "-c", code]


class Collector(object):
    """write() для live_stream: копит отправленное; может «отвалиться» после N записей."""

    def __init__(self, fail_after=None):
        self.chunks = []
        self.fail_after = fail_after

    def __call__(self, data):
        if self.fail_after is not None and len(self.chunks) >= self.fail_after:
            raise BrokenPipeError("client gone")
        self.chunks.append(data)

    def events(self):
        out = []
        for block in b"".join(self.chunks).decode("utf-8").split("\n\n"):
            lines = block.split("\n")
            name = [l[7:] for l in lines if l.startswith("event: ")]
            data = [l[6:] for l in lines if l.startswith("data: ")]
            if name:
                out.append((name[0], json.loads(data[0])))
        return out

    def lines(self):
        return [line for name, data in self.events() if name == "lines" for line in data]


class Clock(object):
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 0.05
        return self.now


class HelpersTest(unittest.TestCase):
    def test_tail_follow_command(self):
        self.assertEqual(kvm.tail_command("/x.log", 50, euid=0, follow=True), ["tail", "-n", "50", "-F", "--", "/x.log"])
        self.assertEqual(kvm.tail_command("/x.log", 5, euid=1000, follow=True)[:3], ["sudo", "-n", "tail"])
        self.assertNotIn("-F", kvm.tail_command("/x.log", 5, euid=0))

    def test_line_splitter(self):
        sp = kvm.LineSplitter()
        self.assertEqual(sp.feed(b"one\ntw"), ["one"])
        self.assertEqual(sp.feed(b"o\r\n\x1b[31mred\x1b[0m\n"), ["two", "red"])
        self.assertEqual(sp.flush(), [])
        sp.feed(b"tail")
        self.assertEqual(sp.flush(), ["tail"])
        long_line = sp.feed(b"x" * (kvm.TAIL_MAX_LINE * 4 + 10))
        self.assertEqual(len(long_line), 1, "строка без перевода отдаётся кусками")
        self.assertTrue(long_line[0].endswith(" …"))
        self.assertEqual(sp.feed("я\n".encode("utf-8")[:1] + b"\n"), ["�"])
        journal = kvm.LineSplitter(journal=True)
        self.assertEqual(journal.feed(b"-- Logs begin --\nreal\n"), ["real"])

    def test_sse_event(self):
        self.assertEqual(kvm.sse_event("lines", ["a\nb", "я"]), 'event: lines\ndata: ["a\\nb","я"]\n\n'.encode("utf-8"))

    def test_client_closed(self):
        a, b = socket.socketpair()
        try:
            self.assertFalse(kvm.client_closed(a), "нет данных — соединение живо")
            b.sendall(b"x")
            self.assertFalse(kvm.client_closed(a), "лишние байты от клиента игнорируются")
            b.close()
            self.assertTrue(kvm.client_closed(a))
            self.assertEqual(a.gettimeout(), None, "таймаут сокета восстановлен")
        finally:
            a.close()
        self.assertTrue(kvm.client_closed(a), "закрытый сокет")

    def test_stop_process_handles_finished(self):
        kvm.stop_process(None)
        proc = kvm.spawn_process(py_cmd("pass"))
        proc.wait()
        kvm.stop_process(proc)


class LiveStreamTest(unittest.TestCase):
    def run_stream(self, code, **kw):
        out = Collector(kw.pop("fail_after", None))
        reason = kvm.live_stream(out, kvm.spawn_process, lambda target, switched: py_cmd(code), poll=0.05, **kw)
        return reason, out

    def test_process_output_then_exit(self):
        reason, out = self.run_stream("import sys,time\nprint('a'); print('b'); sys.stdout.flush(); time.sleep(0.3)\n"
                                      "sys.stdout.write('c'); sys.stdout.flush()", flush_every=0)
        self.assertEqual(reason, "exited")
        self.assertEqual(out.lines(), ["a", "b", "c"], "хвост без перевода строки отправляется при выходе")
        self.assertEqual(out.events()[-1], ("end", {"reason": "exited", "rc": 0}))
        self.assertTrue(out.chunks[0].startswith(b"retry:"))

    def test_time_limit_and_heartbeat(self):
        reason, out = self.run_stream("import time; time.sleep(30)", clock=Clock(), max_seconds=1.0, heartbeat=0.2)
        self.assertEqual(reason, "time_limit")
        self.assertIn(b": ping\n\n", out.chunks)
        self.assertEqual(out.events()[-1][1]["reason"], "time_limit")

    def test_server_stopping(self):
        stop = threading.Event()
        stop.set()
        reason, out = self.run_stream("import time; time.sleep(30)", stop=stop)
        self.assertEqual(reason, "server_stopping")

    def test_client_gone_on_write_kills_process(self):
        procs = []

        def spawn(args):
            procs.append(kvm.spawn_process(args))
            return procs[-1]
        out = Collector(fail_after=1)
        reason = kvm.live_stream(out, spawn, lambda t, s: py_cmd("import time\nwhile True:\n print('x', flush=True); time.sleep(0.05)"),
                                 flush_every=0, poll=0.05)
        self.assertEqual(reason, "client_closed")
        self.assertIsNotNone(procs[0].poll(), "процесс tail завершён")

    def test_client_socket_closed(self):
        a, b = socket.socketpair()
        threading.Timer(0.3, b.close).start()
        try:
            reason, out = self.run_stream("import time; time.sleep(30)", conn=a)
        finally:
            a.close()
        self.assertEqual(reason, "client_closed")
        self.assertNotIn("end", [e[0] for e in out.events()], "закрывшемуся клиенту ничего не пишем")

    def test_switch_to_new_file(self):
        targets = ["/a.log", "/a.log", "/b.log"]
        spawned = []

        def resolve():
            return targets.pop(0) if len(targets) > 1 else targets[0]

        def command_for(target, switched):
            spawned.append((target, switched))
            return py_cmd("import time; print(%r, flush=True); time.sleep(%s)" % (target, 30 if not switched else 0.2))
        out = Collector()
        reason = kvm.live_stream(out, kvm.spawn_process, command_for, resolve=resolve, check_every=0.1, flush_every=0, poll=0.05)
        self.assertEqual(spawned, [("/a.log", False), ("/b.log", True)])
        self.assertIn(("switch", {"path": "/b.log"}), out.events())
        self.assertEqual(reason, "exited")
        self.assertIn("/b.log", out.lines())

    def test_large_batches_flushed(self):
        reason, out = self.run_stream("import time\nfor i in range(1200): print(i)\nimport sys; sys.stdout.flush(); time.sleep(0.2)",
                                      flush_every=100)
        self.assertEqual(len(out.lines()), 1200)
        batches = [len(d) for e, d in out.events() if e == "lines"]
        self.assertGreater(len(batches), 2)
        self.assertLessEqual(max(batches), 500, "событие — не больше 500 строк")


class LiveHttpTest(unittest.TestCase):
    TLS = False

    def setUp(self):
        self.srv = ServerFixture(tls=self.TLS)

    def tearDown(self):
        self.srv.close()

    def conn(self):
        if self.TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection("127.0.0.1", self.srv.port, timeout=10, context=ctx)
        return http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)

    def read_until(self, resp, marker, timeout=5):
        buf = b""
        deadline = time.time() + timeout
        while marker not in buf and time.time() < deadline:
            chunk = resp.fp.read1(65536) if hasattr(resp.fp, "read1") else resp.read(1)
            if not chunk:
                break
            buf += chunk
        return buf

    def test_file_stream_follows_appended_lines(self):
        calls = []
        real_spawn = self.srv.app.spawn

        def spawn(args):
            calls.append(list(args))
            return real_spawn(args)
        self.srv.app.spawn = spawn
        c = self.conn()
        c.request("GET", "/api/logs/live/file/scanner?lines=1")
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "text/event-stream; charset=utf-8")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        head = self.read_until(resp, b"task 300")
        self.assertIn(b'event: meta', head)
        self.assertIn(b'"path":"%s"' % self.srv.log_path.encode(), head)
        self.assertIn(b"task 300", head)
        self.assertNotIn(b"task 299", head, "lines=1 — одна последняя строка")
        with open(self.srv.log_path, "a") as fh:
            fh.write('{"level":"error","message":"live!"}\n')
        self.assertIn(b"live!", self.read_until(resp, b"live!"))
        self.assertEqual(calls[0][-5:], ["-n", "1", "-F", "--", self.srv.log_path])
        self.assertEqual(self.srv.app.live_slots._value, kvm.LIVE_MAX_STREAMS - 1)
        resp.close()
        c.close()
        deadline = time.time() + 3
        while self.srv.app.live_slots._value != kvm.LIVE_MAX_STREAMS and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.srv.app.live_slots._value, kvm.LIVE_MAX_STREAMS, "поток освобождён после закрытия")

    def test_journal_stream_uses_journalctl(self):
        calls = []

        def spawn(args):
            calls.append(args)
            return kvm.spawn_process(py_cmd("print('-- Logs begin --'); print('Nov 05 kvm worker[1]: started', flush=True)"))
        self.srv.app.spawn = spawn
        c = self.conn()
        c.request("GET", "/api/logs/live/journal/worker?lines=5")
        resp = c.getresponse()
        body = self.read_until(resp, b"event: end")
        resp.close()
        c.close()
        self.assertEqual(calls[0], ["journalctl", "-u", "kaspersky-vm-worker.service", "-n", "5", "-f", "--no-pager",
                                    "-o", "short-iso", "-q"])
        self.assertIn(b"worker[1]: started", body)
        self.assertNotIn(b"Logs begin", body)
        self.assertIn(b'"path":"journalctl -u kaspersky-vm-worker.service"', body)

    def test_errors(self):
        for path, status, code in (("/api/logs/live/file/nope", 404, "unknown_log"),
                                   ("/api/logs/live/file/missing", 404, "file_not_found"),
                                   ("/api/logs/live/journal/nope", 404, "unknown_service")):
            c = self.conn()
            c.request("GET", path)
            resp = c.getresponse()
            self.assertEqual((resp.status, json.loads(resp.read().decode())["error"]), (status, code), path)
            c.close()

    def test_too_many_streams(self):
        for _ in range(kvm.LIVE_MAX_STREAMS):
            self.srv.app.live_slots.acquire()
        try:
            c = self.conn()
            c.request("GET", "/api/logs/live/file/scanner")
            resp = c.getresponse()
            payload = json.loads(resp.read().decode())
            self.assertEqual((resp.status, payload["error"], payload["limit"]), (429, "too_many_streams", kvm.LIVE_MAX_STREAMS))
        finally:
            for _ in range(kvm.LIVE_MAX_STREAMS):
                self.srv.app.live_slots.release()

    def test_head_does_not_stream(self):
        c = self.conn()
        c.request("HEAD", "/api/logs/live/file/scanner")
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        resp.read()
        c.close()
        deadline = time.time() + 3
        while self.srv.app.live_slots._value != kvm.LIVE_MAX_STREAMS and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.srv.app.live_slots._value, kvm.LIVE_MAX_STREAMS)

    def test_server_stop_ends_streams(self):
        c = self.conn()
        c.request("GET", "/api/logs/live/file/scanner?lines=0")
        resp = c.getresponse()
        self.read_until(resp, b"event: meta")
        self.srv.app.stopping.set()
        body = self.read_until(resp, b"event: end")
        self.assertIn(b'"reason":"server_stopping"', body)
        resp.close()
        c.close()


class LiveHttpsTest(LiveHttpTest):
    TLS = True

    def setUp(self):
        if os.system("command -v openssl >/dev/null 2>&1") != 0:
            raise unittest.SkipTest("openssl unavailable")  # pragma: no cover
        LiveHttpTest.setUp(self)

    def test_client_close_detected_over_tls(self):
        c = self.conn()
        c.request("GET", "/api/logs/live/file/scanner?lines=0")
        resp = c.getresponse()
        self.read_until(resp, b"event: meta")
        c.close()
        resp.close()
        deadline = time.time() + 3
        while self.srv.app.live_slots._value != kvm.LIVE_MAX_STREAMS and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.srv.app.live_slots._value, kvm.LIVE_MAX_STREAMS)


class BrandTest(unittest.TestCase):
    def test_builtin_brand_png(self):
        brand = kvm.builtin_brand()
        self.assertEqual(brand["type"], "image/png")
        self.assertTrue(brand["data"].startswith(b"\x89PNG\r\n\x1a\n"))
        with open(os.path.join(os.path.dirname(kvm.__file__), "web", "brand.png"), "rb") as fh:
            self.assertEqual(fh.read(), brand["data"], "встроенный логотип = web/brand.png")

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_default_and_override(self):
        with TempDir() as d:
            with mock.patch.object(kvm, "ASSET_DIRS", (d,)):
                app = kvm.App(log_files=[], log_dir=d, settings_path=os.path.join(d, "s.json"))
                self.assertEqual(sorted(app.brand), ["favicon", "logo"])
                self.assertEqual(app.brand["logo"]["data"], kvm.builtin_brand()["data"])
                with open(os.path.join(d, "logo-dark.svg"), "w") as fh:
                    fh.write("<svg/>")
                app = kvm.App(log_files=[], log_dir=d, settings_path=os.path.join(d, "s.json"))
                self.assertEqual(sorted(app.brand), ["favicon", "logo-dark"], "свой логотип заменяет встроенный")
                html = kvm.render_index(app.assets, "ru", "dark", "h", app.brand).decode()
                self.assertIn('<meta name="static-favicon" content="1">', html)
                self.assertIn('href="/brand/favicon"', html)


if __name__ == "__main__":
    unittest.main()
