# -*- coding: utf-8 -*-
"""Общие помощники тестов: загрузка модуля сервиса и имитация systemd/ss/journalctl."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "kaspersky-vm-metrics.py")


def load_module():
    """Импортирует kaspersky-vm-metrics.py (имя с дефисами) как модуль kvm."""
    if "kvm_metrics" in sys.modules:
        return sys.modules["kvm_metrics"]
    spec = importlib.util.spec_from_file_location("kvm_metrics", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["kvm_metrics"] = module
    spec.loader.exec_module(module)
    return module


kvm = load_module()
if not os.environ.get("KVM_TEST_VERBOSE"):
    kvm.real_log = kvm.log
    kvm.log = lambda *args, **kwargs: None  # тишина в выводе тестов (аудит проверяется отдельно)


def MONO():
    """Монотонные часы со сдвигом: в свежем контейнере time.monotonic() может быть мал."""
    return time.monotonic() + 100000.0

SS_LISTEN = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=601,fd=13))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*     users:(("postgres",pid=1006,fd=6))
tcp   LISTEN 0      511          0.0.0.0:8999       0.0.0.0:*     users:(("python3",pid=1300,fd=3))
tcp   LISTEN 0      4096               *:8443             *:*     users:(("kvm-privateapi",pid=1102,fd=9),("kvm-privateapi",pid=1102,fd=10))
tcp   LISTEN 0      4096               *:8081             *:*     users:(("kvm-publicapi",pid=1103,fd=9))
tcp   LISTEN 0      128             [::]:22            [::]:*     users:(("sshd",pid=812,fd=4))
"""

SS_TAN = """State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
LISTEN     0      244        127.0.0.1:5432        0.0.0.0:*
ESTAB      0      0          127.0.0.1:5432      127.0.0.1:41000
ESTAB      0      0          127.0.0.1:41000     127.0.0.1:5432
ESTAB      0      0          127.0.0.1:5432      127.0.0.1:41002
ESTAB      0      0          127.0.0.1:41002     127.0.0.1:5432
ESTAB      0      0         10.0.0.5:5432        10.0.0.9:51000
ESTAB      0      0         10.0.0.5:22          10.0.0.9:52000
TIME-WAIT  0      0          127.0.0.1:5432      127.0.0.1:41010
"""


class FakeSystem(object):
    """Имитация systemctl/ss/journalctl; подставляется в App как runner."""

    def __init__(self, services=None, clock=MONO, restart_delay=0.6):
        self.clock = clock
        self.restart_delay = restart_delay
        self.lock = threading.Lock()
        self.calls = []
        self.fail_restart = set()       # systemctl restart вернёт ошибку
        self.crash_on_start = set()     # после перезапуска служба уйдёт в failed
        self.ss_listen = SS_LISTEN
        self.ss_tan = SS_TAN
        self.journal = {}
        self.broken = False
        pid = 1100
        self.units = {}
        for svc in services or kvm.SERVICES:
            pid += 1
            self.units[svc["unit"]] = {
                "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                "MainPID": pid if svc["key"] != "postgresql" else 1006,
                "MemoryCurrent": 300 * 1024 * 1024 + pid * 1024 * 1024,
                "TasksCurrent": 20, "NRestarts": 0, "since": self.clock() - 3 * 3600 - 120,
                "ControlGroup": "/system.slice/" + svc["unit"], "Result": "success", "restart_at": None,
            }

    # -- управление состоянием из тестов ---------------------------------------
    def set(self, unit, **props):
        with self.lock:
            self.units[unit].update(props)

    def stop(self, unit, failed=False):
        self.set(unit, ActiveState="failed" if failed else "inactive",
                 SubState="failed" if failed else "dead", MainPID=0, MemoryCurrent="[not set]",
                 TasksCurrent="[not set]", Result="exit-code" if failed else "success")

    def _advance(self, unit, u):
        if u["restart_at"] is None:
            return
        elapsed = self.clock() - u["restart_at"]
        if elapsed < self.restart_delay:
            u.update(ActiveState="activating", SubState="start", MainPID=0, MemoryCurrent="[not set]")
            return
        u["restart_at"] = None
        if unit in self.crash_on_start:
            u.update(ActiveState="failed", SubState="failed", MainPID=0, MemoryCurrent="[not set]",
                     Result="exit-code")
        else:
            u.update(ActiveState="active", SubState="running", MainPID=u.get("next_pid", 4242),
                     MemoryCurrent=123 * 1024 * 1024, since=self.clock(), Result="success")

    # -- runner ----------------------------------------------------------------
    def __call__(self, args, timeout=5, c_locale=True):
        with self.lock:
            self.calls.append(list(args))
            if self.broken:
                raise RuntimeError("runner exploded")
            cmd = args[0]
            if cmd == "systemctl" and args[1] in ("list-units", "list-unit-files"):
                import fnmatch
                patterns = [x for x in args[2:] if not x.startswith("--")]
                rows = []
                for name in sorted(self.units):
                    if patterns and not any(fnmatch.fnmatch(name, pat) for pat in patterns):
                        continue
                    u = self.units[name]
                    if args[1] == "list-units":
                        bullet = "\u25cf " if u.get("ActiveState") == "failed" else ""
                        rows.append("%s%s %s %s %s desc" % (bullet, name, u.get("LoadState", "loaded"),
                                                           u.get("ActiveState"), u.get("SubState")))
                    else:
                        rows.append("%s enabled enabled" % name)
                return kvm.CmdResult(0, "\n".join(rows) + ("\n" if rows else ""), "")
            if cmd == "systemctl" and args[1] == "show":
                return self._show(args[2:])
            if cmd == "systemctl" and args[1] == "restart":
                unit = args[-1]
                if unit in self.fail_restart:
                    return kvm.CmdResult(1, "", "Failed to restart %s: Access denied" % unit)
                self.units[unit]["restart_at"] = self.clock()
                self._advance(unit, self.units[unit])
                return kvm.CmdResult(0, "", "")
            if cmd == "ss" and args[1] == "-tulnp":
                return kvm.CmdResult(0, self.ss_listen, "")
            if cmd == "ss" and args[1] == "-tan":
                return kvm.CmdResult(0, self.ss_tan, "")
            if cmd == "sudo" and args[1:2] == ["-n"]:
                args, cmd = args[2:], args[2]
            if cmd == "tail":
                return kvm.run_cmd(args, timeout)  # настоящий tail по реальному файлу
            if cmd == "journalctl":
                unit = args[args.index("-u") + 1]
                count = int(args[args.index("-n") + 1])
                lines = self.journal.get(unit)
                if lines is None:
                    lines = ["2026-10-28T10:%02d:00+0300 host %s[1]: line %d%s" % (
                        i % 60, unit, i, " ERROR failed to connect" if i % 17 == 0 else "")
                        for i in range(1, 121)]
                return kvm.CmdResult(0, "\n".join(lines[-count:]) + "\n", "")
            return kvm.CmdResult(127, "", "unknown command")

    def _show(self, rest):
        units = [a for a in rest if not a.startswith("--")]
        props = [a for a in rest if a.startswith("--property=")][0].split("=", 1)[1].split(",")
        blocks = []
        now = self.clock()
        for unit in units:
            u = self.units.get(unit)
            if u is None:
                u = {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "MainPID": 0,
                     "MemoryCurrent": "[not set]", "TasksCurrent": "[not set]", "since": 0, "restart_at": None}
            self._advance(unit, u)
            values = dict(u)
            values["Id"] = unit
            values["ActiveEnterTimestampMonotonic"] = int(u["since"] * 1e6) if u["since"] and \
                u["ActiveState"] == "active" else 0
            lines = []
            for prop in props:
                if prop in values:
                    lines.append("%s=%s" % (prop, values[prop]))
            blocks.append("\n".join(lines))
        _ = now
        return kvm.CmdResult(0, "\n\n".join(blocks) + "\n", "")


class FakeClock(object):
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TempDir(object):
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="kvm-test-")
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


def make_shadow(directory, password="S3cret!pass", hash_override=None, user="root"):
    """Создаёт shadow-файл с хешем SHA-512 пароля (через системный crypt(3))."""
    pw_hash = hash_override
    if pw_hash is None:
        pw_hash = kvm.system_crypt(password, "$6$kvmtestsalt$")
        assert pw_hash and pw_hash.startswith("$6$"), "crypt(3) unavailable"
    path = os.path.join(directory, "shadow")
    with open(path, "w") as fh:
        fh.write("daemon:*:19000:0:99999:7:::\n")
        fh.write("%s:%s:19000:0:99999:7:::\n" % (user, pw_hash))
        fh.write("bin:*:19000:0:99999:7:::\n")
    return path


def json_body(response):
    return json.loads(response.read().decode("utf-8"))


class ServerFixture(object):
    """Поднимает настоящий HTTP(S)-сервер сервиса на 127.0.0.1:<случайный порт> с FakeSystem."""

    PASSWORD = "S3cret!pass"

    def __init__(self, tls=False, log_files=None, shadow_hash=None, restart_delay=0.6, settle=0.3,
                 throttle=None, reports=True):
        self.tls = tls
        self.tmp = tempfile.mkdtemp(prefix="kvm-srv-")
        self.fake = FakeSystem(restart_delay=restart_delay)
        self.collector = kvm.StatusCollector(kvm.SERVICES, runner=self.fake, clock=MONO, ttl=0.2)
        self.collector.fqdn = "kvm-test.local"
        self.restarts = kvm.RestartManager(runner=self.fake, clock=MONO, settle=settle, timeout=30)
        shadow = make_shadow(self.tmp, password=self.PASSWORD, hash_override=shadow_hash)
        self.auth = kvm.RootAuthenticator(shadow_paths=(shadow,))
        self.log_path = os.path.join(self.tmp, "scanner.log")
        with open(self.log_path, "w") as fh:
            for i in range(1, 301):
                level = "ERROR" if i % 50 == 0 else ("WARN" if i % 30 == 0 else "INFO")
                fh.write("2026-10-28 12:%02d:%02d %s scanner: task %d processed <b>&amp;\n" % (i // 60, i % 60, level, i))
        if log_files is None:
            log_files = [
                {"key": "scanner", "title_ru": "Модуль сканирования", "title_en": "Scanner", "path": self.log_path,
                 "service": "scanner"},
                {"key": "missing", "title_ru": "Нет файла", "title_en": "Missing", "path": os.path.join(self.tmp, "nope.log")},
            ]
        if reports:
            for day in ("26_10_2026", "27_10_2026", "28_10_2026"):
                with open(os.path.join(self.tmp, kvm.REPORT_PREFIX + day + ".json"), "w") as fh:
                    fh.write('{"report": "kaspersky-vm-services-state", "date": "%s"}\n' % day)
        self.throttle = throttle or kvm.LoginThrottle(max_fails=3, window=600, lock=300)
        self.app = kvm.App(services=kvm.SERVICES, log_files=log_files, collector=self.collector,
                           restarts=self.restarts, auth=self.auth, throttle=self.throttle,
                           runner=self.fake, log_dir=self.tmp, fail_delay=0,
                           settings_path=os.path.join(self.tmp, "settings.json"))
        self.context = None
        if tls:
            cert = os.path.join(self.tmp, "cert.pem")
            key = os.path.join(self.tmp, "key.pem")
            assert kvm.generate_certificate("localhost", cert, key, force=True)
            self.context = kvm.make_ssl_context(cert, key)
        self.server = kvm.create_server(self.app, "127.0.0.1", 0, self.context)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        self.thread.daemon = True
        self.thread.start()

    @property
    def base(self):
        return "%s://127.0.0.1:%d" % ("https" if self.tls else "http", self.port)

    def close(self):
        self.app.stopping.set()  # потоки Real-time завершают свои tail -F
        time.sleep(0.05)
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)
