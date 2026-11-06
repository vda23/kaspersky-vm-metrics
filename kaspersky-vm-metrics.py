#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kaspersky Vulnerability Management. Monitoring of solution components
Сервис мониторинга служб Kaspersky Vulnerability Management

Порт: 8999 (HTTPS) по умолчанию; другой задаётся параметром --port (установщик: install.sh --port N)

Требования: Python 3.5+ (только стандартная библиотека), systemd, iproute2 (ss),
openssl. Совместимость (64-разрядные ОС, x86_64 и ARM64): Альт Рабочая станция 11.2,
Альт Сервер 11.0, Альт СП Рабочая станция 10, Альт СП Сервер 10, РЕД ОС 8.0 (в том числе
сертифицированная редакция), Astra Linux CE 2.12, Astra Linux SE 1.8.5 (в том числе в режиме
замкнутой программной среды), Debian 13.0, Platform V SberLinux OS Server 9.6,
Ubuntu Server 24.04 LTS и 26.04 LTS.

Код намеренно не использует f-строки, subprocess.run(capture_output=...)
и другие возможности новее Python 3.5: на Astra Linux CE 2.12 штатный
интерпретатор - 3.5, на SberLinux 8 - 3.6.

HTTP API
  GET  /                                  - веб-интерфейс
  GET  /api/status                        - состояние служб, системы и портов (JSON)
  GET  /api/logs                          - список лог-файлов, журналов и отчётов
  GET  /api/logs/file/<key>?lines=50      - последние строки лог-файла (tail -n 50 -- <path>)
  GET  /api/logs/journal/<key>?lines=50   - последние строки журнала systemd службы
  GET  /api/logs/live/file/<key>          - Real-time: поток новых строк лог-файла (text/event-stream)
  GET  /api/logs/live/journal/<key>       - Real-time: поток журнала systemd службы
  POST /api/services/<key>/restart        - перезапуск службы (нужен пароль root)
  GET  /logs-today                        - архив логов компонентов за сегодня (zip)
  GET  /logs-day?date=ГГГГ-ММ-ДД          - архив логов компонентов за выбранный день (zip)
  GET  /api/report-now                    - отчёт о состоянии прямо сейчас (JSON-файл)
  GET  /log?file=<name>                   - скачать ежедневный отчёт
  GET  /logs-archive?files=["a","b"]      - скачать несколько отчётов (zip)
  GET  /api/siem                          - настройки и состояние отправки событий в SIEM, 5 последних событий
  GET  /api/siem/events?lines=200         - последние события строками syslog/CEF (как уходят в SIEM)
  POST /api/siem                          - сохранить настройки SIEM (нужен пароль root)
  POST /api/siem/test                     - отправить тестовое событие (нужен пароль root)
  GET  /healthz                           - проверка работоспособности
"""

import argparse
import base64
import glob
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from collections import deque, namedtuple
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlsplit

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

PORT = 8999
BIND_ADDRESS = "0.0.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = SCRIPT_DIR
CERT_FILE = os.path.join(SCRIPT_DIR, "cert.pem")
KEY_FILE = os.path.join(SCRIPT_DIR, "key.pem")
FONT_NAME = "KasperskySans-Regular"

REPORT_PREFIX = "kaspersky-vm-services-state_"
REPORT_RE = re.compile(r"^kaspersky-vm-services-state_\d{2}_\d{2}_\d{4}\.json$")
REPORT_HOUR = 19            # ежедневный отчёт в 19:00
REPORT_KEEP_DAYS = 7        # хранить отчёты 7 дней
REPORT_SCHEMA = 1
REPORT_SCAN_MAX = 32 * 1024 * 1024  # сколько байт сегодняшнего лога просматривать при подсчёте ошибок
REPORT_LAST_ERRORS = 5      # последних ошибок каждого компонента в отчёте
REPORT_DISK_PATHS = ("/", "/var", "/var/log", "/var/log/kaspersky", "/var/lib/pgsql",
                     "/var/lib/postgresql", "/opt")
SETTINGS_FILE = os.path.join(SCRIPT_DIR, "settings.json")

# Отправка событий в SIEM: syslog (RFC 3164) с сообщением в формате CEF.
# Рекомендуется TCP: доставка подтверждается на транспортном уровне, длинные события
# не обрезаются. Порт 5144 часто используют для коллекторов KUMA: порты ниже 1024 (в том
# числе стандартный 514) требуют на коллекторе дополнительных прав. Указывается порт,
# который слушает коллектор SIEM, принимающий CEF по syslog.
SIEM_RECOMMENDED_PROTOCOL = "tcp"
SIEM_RECOMMENDED_PORT = 5144
SIEM_QUEUE_MAX = 2000       # событий в очереди, пока SIEM недоступна
SIEM_UDP_MAX = 2048         # байт в датаграмме UDP (RFC 5426: безопасный размер)
SIEM_TCP_MAX = 16384        # байт в одном событии по TCP
SIEM_CONNECT_TIMEOUT = 5
SIEM_FACILITY = 16          # local0

MONITOR_INTERVAL = 15       # с; проверка смены состояний для событий
LOG_SCAN_INTERVAL = 60      # с; поиск новых ошибок в логах компонентов
LOG_SCAN_MAX = 4 * 1024 * 1024
MEM_ALERT_PERCENT = 90
DISK_ALERT_PERCENT = 90
ALERT_CLEAR_MARGIN = 5      # гистерезис: «норма» — на 5 п.п. ниже порога
CERT_DAYS = 365
CERT_RENEW_BEFORE = 30 * 86400

STATUS_CACHE_TTL = 1.0      # с; защищает systemctl/ss от «шторма» запросов
CMD_TIMEOUT = 5             # с; таймаут внешних команд
REQUEST_TIMEOUT = 30        # с; таймаут сокета клиента
MAX_CONCURRENT_REQUESTS = 64
MAX_BODY = 4096

TAIL_DEFAULT = 50
TAIL_MAX = 1000
SIEM_RECENT_SHOWN = 5      # событий в панели SIEM; остальные — в окне «Все события»
TAIL_MAX_LINE = 8000

# Real-time: лог передаётся браузеру потоком (Server-Sent Events) из tail -F / journalctl -f
LIVE_MAX_STREAMS = 8        # одновременных потоков на сервер
LIVE_MAX_SECONDS = 3600     # поток закрывается через час (кнопкой «Продолжить» — заново)
LIVE_HEARTBEAT = 10         # с; пустое событие: держит соединение и замечает закрытую вкладку
LIVE_FLUSH = 0.25           # с; строки отправляются пачками не чаще раза в 250 мс
LIVE_CHECK_FILE = 5         # с; проверка, не появился ли новый файл по маске (vms_<дата>.log)

RESTART_TIMEOUT = 180       # с; сколько ждать завершения перезапуска
RESTART_SETTLE = 2.0        # с; минимальное время до признания перезапуска завершённым

AUTH_MAX_FAILS = 5          # неудачных попыток ввода пароля root...
AUTH_WINDOW = 600           # ...за 10 минут
AUTH_LOCK = 300             # блокируют IP на 5 минут
AUTH_FAIL_DELAY = 1.0       # задержка ответа при неверном пароле

PG_PORT = 5432

SERVICES = [
    {
        "key": "scanner",
        "unit": "kaspersky-vm-scanner.service",
        "desc_ru": "Служба модуля сканирования уязвимостей",
        "desc_en": "Vulnerability scanning module service",
    },
    {
        "key": "vms",
        "unit": "kaspersky-vm-vms.service",
        "desc_ru": "Служба модуля обнаружения уязвимостей",
        "desc_en": "Vulnerability detection module service",
    },
    {
        "key": "worker",
        "unit": "kaspersky-vm-worker.service",
        "desc_ru": "Служба фоновых задач, созданных для Kaspersky Vulnerability Management "
                   "в Kaspersky Security Center",
        "desc_en": "Background tasks service created for Kaspersky Vulnerability Management "
                   "in Kaspersky Security Center",
    },
    {
        "key": "privateapi",
        "unit": "kaspersky-vm-privateapi.service",
        "desc_ru": "Веб-служба для взаимодействия с веб-плагином управления решением через "
                   "Kaspersky Security Center Web Console, Сетевым сканером и Службой фоновых задач",
        "desc_en": "Web service for interacting with the solution's management web plug-in for "
                   "the Kaspersky Security Center Web Console, Network Scanner, and Worker",
    },
    {
        "key": "publicapi",
        "unit": "kaspersky-vm-publicapi.service",
        "desc_ru": "Веб-служба для взаимодействия внешних систем с Kaspersky Vulnerability Management",
        "desc_en": "Web service for interaction of external systems with Kaspersky Vulnerability Management",
    },
    {
        "key": "postgresql",
        "unit": "postgresql.service",
        # Имя службы СУБД отличается между ОС и сборками PostgreSQL
        # (postgresql.service, postgresql-15.service, postgresql@15-main.service,
        # postgrespro-std-15.service) — сервис находит его сам.
        "detect": ["postgresql*.service", "postgrespro*.service"],
        "desc_ru": "Системная служба для управления сервером базы данных",
        "desc_en": "System service for database server management",
        "warn_ru": "Все службы Kaspersky Vulnerability Management временно потеряют "
                   "соединение с базой данных.",
        "warn_en": "All Kaspersky Vulnerability Management services will temporarily lose "
                   "their database connection.",
        "db_port": PG_PORT,
    },
]

# Лог-файлы компонентов. Кнопка «Последние 50 строк» выполняет на сервере
#   tail -n 50 -- <path>          (сервис работает от root)
#   sudo -n tail -n 50 -- <path>  (если сервис запущен не от root)
# Команда запускается без оболочки, путь берётся только из этого списка (не из запроса).
# path может содержать маску (*), тогда берётся самый свежий по времени изменения файл.
# service - ключ службы из SERVICES: кнопка «Лог» появится в её карточке.
# Каталог логов одинаков для всех инсталляций KVM, настройка не требуется.
LOG_DIR_KVM = "/var/log/kaspersky/vulnerability-management"
LOG_FILES = [
    {"key": "worker", "service": "worker", "path": LOG_DIR_KVM + "/worker/worker.log",
     "title_ru": "Служба фоновых задач", "title_en": "Worker"},
    {"key": "scanner", "service": "scanner", "path": LOG_DIR_KVM + "/scanner/scanner.log",
     "title_ru": "Модуль сканирования уязвимостей", "title_en": "Vulnerability scanning module"},
    # vms пишет лог с датой запуска в имени: vms_2026-10-29T231005.log -> берём самый свежий
    {"key": "vms", "service": "vms", "path": LOG_DIR_KVM + "/vms/vms*.log",
     "title_ru": "Модуль обнаружения уязвимостей", "title_en": "Vulnerability detection module"},
    {"key": "privateapi", "service": "privateapi", "path": LOG_DIR_KVM + "/privateapi/privateapi.log",
     "title_ru": "Private API", "title_en": "Private API"},
    {"key": "publicapi", "service": "publicapi", "path": LOG_DIR_KVM + "/publicapi/publicapi.log",
     "title_ru": "Public API", "title_en": "Public API"},
]

# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

CmdResult = namedtuple("CmdResult", "rc out err")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
UINT64_MAX = 18446744073709551615


def log(message, *args):
    """Пишет сообщение в stderr (попадает в journald)."""
    if args:
        message = message % args
    try:
        sys.stderr.write("[kvm-metrics] " + message + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):  # pragma: no cover (stderr закрыт)
        pass


def run_cmd(args, timeout=CMD_TIMEOUT, c_locale=True):
    """Запускает команду и возвращает CmdResult. Никогда не бросает исключений."""
    env = dict(os.environ)
    env.update({"SYSTEMD_PAGER": "", "PAGER": "cat", "SYSTEMD_COLORS": "0"})
    if c_locale:
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              stdin=subprocess.DEVNULL, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", "timeout")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return CmdResult(127, "", str(exc))
    return CmdResult(proc.returncode,
                     proc.stdout.decode("utf-8", "replace"),
                     proc.stderr.decode("utf-8", "replace"))


def read_text(path, default=""):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except (OSError, IOError):
        return default


def to_int(value):
    """Преобразует значение свойства systemd в int; '[not set]', '', 'infinity' -> None."""
    if value is None:
        return None
    value = str(value).strip()
    if not value or not re.match(r"^-?\d+$", value):
        return None
    number = int(value)
    if number >= UINT64_MAX or number < 0:
        return None
    return number


def clamp_int(value, default, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def now_iso():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def iso_local(ts=None):
    """Локальное время с часовым поясом: 2026-11-05T19:00:00+03:00 (для отчётов и событий)."""
    ts = time.time() if ts is None else ts
    tm = time.localtime(ts)
    offset = tm.tm_gmtoff if getattr(tm, "tm_gmtoff", None) is not None else -time.timezone
    sign = "+" if offset >= 0 else "-"
    offset = abs(int(offset)) // 60
    return time.strftime("%Y-%m-%dT%H:%M:%S", tm) + "%s%02d:%02d" % (sign, offset // 60, offset % 60)


# ---------------------------------------------------------------------------
# Парсеры (чистые функции, покрыты тестами)
# ---------------------------------------------------------------------------

def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        values[key.strip()] = val
    return values.get("PRETTY_NAME") or values.get("NAME") or "Unknown"


def parse_meminfo(text):
    """Возвращает значения /proc/meminfo в байтах."""
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if not parts:
            continue
        try:
            number = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            number *= 1024
        result[key.strip()] = number
    return result


def memory_summary(meminfo):
    """Разбивка ОЗУ, в которой части всегда складываются в целое:
        total = processes + cache + free,   used = processes + cache = total - free.
    cache — страничный кэш и буферы ядра (Cached + Buffers + SReclaimable), как в `free`;
    processes — всё остальное занятое (память процессов, ядро)."""
    total = meminfo.get("MemTotal", 0)
    free = min(meminfo.get("MemFree", 0), total)
    used = total - free
    cache = min(meminfo.get("Cached", 0) + meminfo.get("Buffers", 0) + meminfo.get("SReclaimable", 0), used)
    if "MemAvailable" in meminfo:
        available = meminfo["MemAvailable"]
    else:  # ядра < 3.14
        available = free + cache
    return {
        "total": total,
        "used": used,
        "processes": used - cache,
        "cache": cache,
        "free": free,
        "available": min(available, total),
    }


def parse_cpu_times(text):
    """(busy, total) в тиках из первой строки /proc/stat или None."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "cpu":
            try:
                values = [int(x) for x in parts[1:9]]
            except ValueError:
                return None
            if len(values) < 4:
                return None
            idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
            total = sum(values)
            return total - idle, total
    return None


def cpu_percent(previous, current):
    """Загрузка ЦП в процентах между двумя замерами parse_cpu_times."""
    if not previous or not current:
        return None
    busy = current[0] - previous[0]
    total = current[1] - previous[1]
    if total <= 0:
        return None
    return round(max(0.0, min(100.0, busy * 100.0 / total)), 1)


def parse_uptime(text):
    try:
        return int(float(text.split()[0]))
    except (IndexError, ValueError):
        return None


def parse_systemctl_show(text):
    """Разбирает вывод `systemctl show unit1 unit2 ...` (блоки через пустую строку)."""
    blocks = []
    current = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            current[key] = val
    if current:
        blocks.append(current)
    return blocks


def service_state(props):
    if not props:
        return "unknown"
    if props.get("LoadState") in ("not-found", "masked") and props.get("ActiveState") != "active":
        return "not-found" if props.get("LoadState") == "not-found" else "masked"
    return props.get("ActiveState") or "unknown"


SS_USER_RE = re.compile(r'\("([^"]*)",pid=(\d+)')


def parse_ss_users(field):
    """users:(("sshd",pid=812,fd=3),("sshd",pid=813,fd=3)) -> [("sshd", 812), ...]"""
    return [(name, int(pid)) for name, pid in SS_USER_RE.findall(field or "")]


def split_port(address):
    """'0.0.0.0:22' -> 22, '[::]:5432' -> 5432, '*:8999' -> 8999."""
    if ":" not in address:
        return None
    tail = address.rsplit(":", 1)[1]
    return int(tail) if tail.isdigit() else None


def parse_ss_listen(text):
    """Разбирает вывод `ss -tulnp`."""
    ports = []
    for line in text.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 6 or parts[0] == "Netid":
            continue
        process = parts[6].strip() if len(parts) > 6 else ""
        users = parse_ss_users(process)
        ports.append({
            "netid": parts[0],
            "state": parts[1],
            "local": parts[4],
            "port": split_port(parts[4]),
            "process": ", ".join(sorted(set(u[0] for u in users))) if users else process,
            "pids": sorted(set(u[1] for u in users)),
        })

    def sort_key(item):
        proto = 0 if item["netid"].startswith("tcp") else 1
        state = {"LISTEN": 0, "UNCONN": 1}.get(item["state"], 2)
        return (proto, state, item["port"] if item["port"] is not None else 65536, item["local"])

    ports.sort(key=sort_key)
    return ports


def count_established(text, port):
    """Считает входящие (local port == port) установленные TCP-соединения в выводе `ss -tan`."""
    count = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ("State", "Netid"):
            continue
        if parts[0].upper().startswith("ESTAB") and split_port(parts[3]) == port:
            count += 1
    return count


def strip_ansi(line):
    return ANSI_RE.sub("", line)


# ---------------------------------------------------------------------------
# Сбор состояния
# ---------------------------------------------------------------------------

def parse_unit_list(text):
    """Имена служб из вывода `systemctl list-units/list-unit-files --plain --no-legend`."""
    units = []
    for line in text.splitlines():
        parts = line.replace("\u25cf", " ").split()  # «●» перед упавшими службами
        if parts and parts[0].endswith(".service") and not parts[0].endswith("@.service"):
            units.append(parts[0])
    return units


def detect_unit(runner, patterns, default):
    """Находит реальное имя службы по маскам. Предпочтение: работающая служба с процессом,
    затем активная (Debian: обёртка postgresql.service в состоянии exited), затем установленная."""
    listed = runner(["systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend",
                     "--no-pager"] + list(patterns))
    files = runner(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]
                   + list(patterns))
    candidates = []
    for name in parse_unit_list(listed.out if listed.rc == 0 else "") + \
            parse_unit_list(files.out if files.rc == 0 else ""):
        if name not in candidates:
            candidates.append(name)
    if not candidates:
        return default
    res = runner(["systemctl", "show"] + candidates + ["--property=Id,LoadState,ActiveState,SubState,MainPID"])
    blocks = parse_systemctl_show(res.out) if res.rc == 0 else []

    def score(item):
        index, (name, props) = item
        value = 0
        if props.get("LoadState") == "loaded":
            value += 1
        if props.get("ActiveState") == "active":
            value += 4
        if props.get("SubState") == "running" and (to_int(props.get("MainPID")) or 0) > 0:
            value += 2
        if name == default:
            value += 0.5
        return (value, -index)
    ranked = sorted(enumerate(zip(candidates, blocks)), key=score, reverse=True)
    return ranked[0][1][0] if ranked else default


SHOW_PROPS = ("Id,LoadState,ActiveState,SubState,MemoryCurrent,TasksCurrent,MainPID,"
              "ActiveEnterTimestampMonotonic,NRestarts,ControlGroup,Result")
CGROUP_ROOTS = ("/sys/fs/cgroup", "/sys/fs/cgroup/systemd", "/sys/fs/cgroup/unified")


class StatusCollector(object):
    """Собирает состояние служб, системы и портов; кэширует результат на STATUS_CACHE_TTL."""

    def __init__(self, services, runner=None, proc_root="/proc", ttl=STATUS_CACHE_TTL,
                 clock=time.monotonic, cgroup_roots=CGROUP_ROOTS):
        self.services = services
        self.runner = runner or run_cmd
        self.proc_root = proc_root
        self.ttl = ttl
        self.clock = clock
        self.cgroup_roots = cgroup_roots
        self.restarts = None  # RestartManager, назначается приложением
        self.fqdn = socket.getfqdn()
        self.detect_interval = 300
        self._detected_at = None
        self._cpu_sample = None
        self._lock = threading.Lock()
        self._cache = None
        self._cache_time = 0.0

    # -- системная информация ------------------------------------------------
    def cpu_usage(self):
        """Загрузка ЦП (%) с прошлого опроса; при первом опросе — за 0,25 с."""
        stat_path = os.path.join(self.proc_root, "stat")
        current = parse_cpu_times(read_text(stat_path))
        previous = self._cpu_sample
        if current and previous is None:
            time.sleep(0.25)
            previous, current = current, parse_cpu_times(read_text(stat_path))
        self._cpu_sample = current
        return cpu_percent(previous, current)

    def system_info(self):
        osr = read_text("/etc/os-release") or read_text("/usr/lib/os-release")
        return {
            "os_name": parse_os_release(osr),
            "cpu_threads": os.cpu_count() or 0,
            "cpu_percent": self.cpu_usage(),
            "memory": memory_summary(parse_meminfo(read_text(os.path.join(self.proc_root, "meminfo")))),
            "uptime_sec": parse_uptime(read_text(os.path.join(self.proc_root, "uptime"))),
        }

    # -- службы ---------------------------------------------------------------
    def query_units(self, units):
        res = self.runner(["systemctl", "show"] + list(units) + ["--property=" + SHOW_PROPS])
        by_id = {}
        blocks = parse_systemctl_show(res.out) if res.rc == 0 or res.out else []
        for unit, block in zip(units, blocks):
            # systemctl выводит блоки в порядке аргументов; Id может отличаться (алиасы)
            by_id[unit] = block
        return by_id

    def cgroup_rss(self, cgroup):
        """Резервная оценка памяти: сумма VmRSS процессов cgroup (если MemoryAccounting выключен)."""
        if not cgroup:
            return None
        for root in self.cgroup_roots:
            procs = read_text(os.path.join(root, cgroup.lstrip("/"), "cgroup.procs"), None)
            if procs is None:
                continue
            total = 0
            for pid in procs.split():
                status = read_text(os.path.join(self.proc_root, pid, "status"))
                match = re.search(r"^VmRSS:\s+(\d+)\s+kB", status, re.M)
                if match:
                    total += int(match.group(1)) * 1024
            return total
        return None

    def service_info(self, svc, props, now_mono, connections):
        state = service_state(props)
        pid = to_int(props.get("MainPID")) or 0
        memory = to_int(props.get("MemoryCurrent"))
        memory_source = "cgroup"
        if memory is None and state == "active":
            memory = self.cgroup_rss(props.get("ControlGroup"))
            memory_source = "rss" if memory is not None else None
        uptime = None
        since = to_int(props.get("ActiveEnterTimestampMonotonic")) or 0
        if state == "active" and since > 0:
            uptime = max(int(now_mono - since / 1e6), 0)
        info = {
            "key": svc["key"],
            "unit": svc["unit"],
            "desc_ru": svc.get("desc_ru", ""),
            "desc_en": svc.get("desc_en", ""),
            "warn_ru": svc.get("warn_ru", ""),
            "warn_en": svc.get("warn_en", ""),
            "state": state,
            "sub_state": props.get("SubState", ""),
            "result": props.get("Result", ""),
            "pid": pid,
            "memory_bytes": memory or 0,
            "memory_source": memory_source if memory is not None else None,
            "tasks": to_int(props.get("TasksCurrent")),
            "restarts": to_int(props.get("NRestarts")),
            "uptime_sec": uptime,
            "since_mono": since,
            "restart": None,
        }
        if svc.get("db_port"):
            info["db_connections"] = connections
        return info

    # -- сеть -------------------------------------------------------------------
    def ports(self):
        res = self.runner(["ss", "-tulnp"])
        return parse_ss_listen(res.out) if res.rc == 0 else []

    def db_connections(self, port=PG_PORT):
        res = self.runner(["ss", "-tan"])
        return count_established(res.out, port) if res.rc == 0 else 0

    # -- итог -------------------------------------------------------------------
    def detect_units(self, force=False):
        """Уточняет имена служб с масками detect (раз в 5 минут: СУБД могли переустановить)."""
        now = self.clock()
        if not force and self._detected_at is not None and now - self._detected_at < self.detect_interval:
            return
        self._detected_at = now
        for svc in self.services:
            if svc.get("detect"):
                found = detect_unit(self.runner, svc["detect"], svc.get("default_unit", svc["unit"]))
                svc.setdefault("default_unit", svc["unit"])
                if found != svc["unit"]:
                    log("service %s: using unit %s", svc["key"], found)
                    svc["unit"] = found

    def collect(self):
        self.detect_units()
        units = [s["unit"] for s in self.services]
        props = self.query_units(units)
        now_mono = self.clock()
        need_db = any(s.get("db_port") for s in self.services)
        connections = self.db_connections() if need_db else 0
        services = [self.service_info(s, props.get(s["unit"], {}), now_mono, connections)
                    for s in self.services]
        if self.restarts is not None:
            self.restarts.annotate(services)

        ports = self.ports()
        pid_to_key = dict((s["pid"], s["key"]) for s in services if s["pid"])
        for port in ports:
            port["service"] = next((pid_to_key[p] for p in port["pids"] if p in pid_to_key), None)

        running = sum(1 for s in services if s["state"] == "active")
        return {
            "version": __version__,
            "host": self.fqdn,
            "time": now_iso(),
            "system": self.system_info(),
            "services": services,
            "summary": {
                "total": len(services),
                "running": running,
                "all_up": running == len(services),
                "services_memory_bytes": sum(s["memory_bytes"] for s in services),
            },
            "ports": ports,
        }

    def get(self, force=False):
        with self._lock:
            if not force and self._cache is not None and self.clock() - self._cache_time < self.ttl:
                return self._cache
            self._cache = self.collect()
            self._cache_time = self.clock()
            return self._cache

    def invalidate(self):
        with self._lock:
            self._cache = None


# ---------------------------------------------------------------------------
# Перезапуск служб
# ---------------------------------------------------------------------------

class RestartManager(object):
    """Запускает `systemctl restart --no-block` и отслеживает завершение перезапуска."""

    TRANSITIONAL = ("activating", "deactivating", "reloading")

    def __init__(self, runner=None, clock=time.monotonic, timeout=RESTART_TIMEOUT,
                 settle=RESTART_SETTLE):
        self.runner = runner or run_cmd
        self.clock = clock
        self.timeout = timeout
        self.settle = settle
        self._lock = threading.Lock()
        self.jobs = {}      # key -> активный перезапуск
        self.results = {}   # key -> результат последнего перезапуска
        self.events = None  # EventBus, назначается приложением

    def emit(self, name, message, **fields):
        if self.events is not None:
            self.events.emit(name, message, **fields)

    def in_progress(self, key):
        with self._lock:
            return key in self.jobs

    def start(self, svc, since_mono, client):
        """Возвращает (ok, error_code, message)."""
        with self._lock:
            if svc["key"] in self.jobs:
                return False, "in_progress", ""
            self.jobs[svc["key"]] = {"started": self.clock(), "since": since_mono,
                                     "client": client, "wall": time.time()}
            self.results.pop(svc["key"], None)
        res = self.runner(["systemctl", "restart", "--no-block", svc["unit"]], timeout=15)
        if res.rc != 0:
            with self._lock:
                self.jobs.pop(svc["key"], None)
            message = (res.err or res.out or "").strip()[:500]
            log("AUDIT restart unit=%s client=%s result=error rc=%s msg=%s",
                svc["unit"], client, res.rc, message)
            self.emit("restart_failed", "Restart of %s failed: %s" % (svc["unit"], message or "rc=%s" % res.rc),
                      key=svc["key"], unit=svc["unit"], client=client, user="root", action="restart",
                      outcome="failure")
            return False, "systemctl_failed", message
        log("AUDIT restart unit=%s client=%s result=queued", svc["unit"], client)
        self.emit("restart_requested", "Restart of %s requested" % svc["unit"], key=svc["key"],
                  unit=svc["unit"], client=client, user="root", action="restart", outcome="success")
        return True, None, ""

    def annotate(self, services):
        """Отмечает службы с идущим перезапуском и фиксирует завершённые."""
        finished = []
        try:
            self._annotate(services, finished)
        finally:
            for name, message, fields in finished:  # события — вне блокировки
                self.emit(name, message, **fields)

    def _annotate(self, services, finished):
        now = self.clock()
        with self._lock:
            for svc in services:
                key = svc["key"]
                job = self.jobs.get(key)
                if job is not None:
                    elapsed = now - job["started"]
                    state = svc["state"]
                    done = None
                    if elapsed >= self.timeout:
                        done = "timeout"
                    elif elapsed >= self.settle and state not in self.TRANSITIONAL:
                        if state == "active" and svc["since_mono"] != job["since"]:
                            done = "ok"
                        elif state in ("failed", "inactive", "not-found", "masked"):
                            done = "failed"
                    if done:
                        self.jobs.pop(key, None)
                        self.results[key] = {"result": done, "finished": time.time(),
                                             "started": job["wall"]}
                        log("AUDIT restart unit=%s client=%s result=%s elapsed=%.1fs",
                            svc["unit"], job["client"], done, elapsed)
                        finished.append(("restart_" + done, "Restart of %s: %s after %.0f s" % (
                            svc["unit"], {"ok": "completed", "failed": "service failed to start",
                                          "timeout": "not finished"}[done], elapsed),
                            {"key": key, "unit": svc["unit"], "client": job["client"], "user": "root",
                             "action": "restart", "state": svc["state"],
                             "outcome": "success" if done == "ok" else "failure"}))
                    else:
                        svc["restart"] = {"in_progress": True, "elapsed": round(elapsed, 1),
                                          "started": job["wall"]}
                        continue
                result = self.results.get(key)
                if result is not None:
                    svc["restart"] = dict(result, in_progress=False)


# ---------------------------------------------------------------------------
# Проверка пароля root
# ---------------------------------------------------------------------------

_crypt_lock = threading.Lock()
_crypt_impl = None


def _load_crypt():
    """crypt(3) из модуля crypt (Python <= 3.12) или через ctypes (Python 3.13+)."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import crypt as crypt_module  # noqa: удалён в Python 3.13
        return crypt_module.crypt  # pragma: no cover (Python <= 3.12; ветка ctypes — 3.13+)
    except ImportError:
        pass
    import ctypes
    import ctypes.util
    names = [ctypes.util.find_library("crypt"), "libcrypt.so.2", "libcrypt.so.1", "libcrypt.so"]
    for name in names:
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        func = lib.crypt
        func.restype = ctypes.c_char_p
        func.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

        def _crypt(word, salt, _func=func):
            out = _func(word.encode("utf-8"), salt.encode("utf-8"))
            return out.decode("utf-8", "replace") if out else None
        return _crypt
    return None


def system_crypt(word, salt):
    global _crypt_impl
    with _crypt_lock:
        if _crypt_impl is None:
            _crypt_impl = _load_crypt() or False
        if not _crypt_impl:
            return None
        try:
            return _crypt_impl(word, salt)
        except (OSError, ValueError):
            return None


class RootAuthenticator(object):
    """Проверяет пароль root по /etc/shadow (или /etc/tcb/root/shadow на Альт)."""

    SHADOW_PATHS = ("/etc/tcb/root/shadow", "/etc/shadow")

    def __init__(self, shadow_paths=None, crypt_func=None, user="root"):
        self.shadow_paths = shadow_paths or self.SHADOW_PATHS
        self.crypt = crypt_func or system_crypt
        self.user = user

    def password_hash(self):
        for path in self.shadow_paths:
            text = read_text(path, None)
            if text is None:
                continue
            for line in text.splitlines():
                fields = line.split(":")
                if len(fields) >= 2 and fields[0] == self.user:
                    return fields[1]
        return None

    def status(self):
        """'ok' | 'locked' (пароль не задан / учётная запись заблокирована) | 'unavailable'."""
        pw_hash = self.password_hash()
        if pw_hash is None:
            return "unavailable"
        if not pw_hash or pw_hash[0] in "!*" or not pw_hash.startswith("$") and len(pw_hash) != 13:
            return "locked"
        return "ok"

    def verify(self, password):
        if not password or len(password) > 1024 or "\x00" in password:
            return False
        if self.status() != "ok":
            return False
        pw_hash = self.password_hash()
        result = self.crypt(password, pw_hash)
        if not result:
            return False
        return hmac.compare_digest(result.encode("utf-8"), pw_hash.encode("utf-8"))


class LoginThrottle(object):
    """Ограничение числа неудачных попыток ввода пароля по IP."""

    def __init__(self, max_fails=AUTH_MAX_FAILS, window=AUTH_WINDOW, lock=AUTH_LOCK,
                 clock=time.monotonic):
        self.max_fails = max_fails
        self.window = window
        self.lock_time = lock
        self.clock = clock
        self._lock = threading.Lock()
        self._fails = {}
        self._locked = {}

    def retry_after(self, client):
        with self._lock:
            until = self._locked.get(client)
            if until is None:
                return 0
            left = until - self.clock()
            if left <= 0:
                self._locked.pop(client, None)
                self._fails.pop(client, None)
                return 0
            return int(left) + 1

    def fail(self, client):
        """Фиксирует неудачу; возвращает число оставшихся попыток (0 - IP заблокирован)."""
        now = self.clock()
        with self._lock:
            fails = [t for t in self._fails.get(client, []) if now - t < self.window]
            fails.append(now)
            self._fails[client] = fails
            if len(fails) >= self.max_fails:
                self._locked[client] = now + self.lock_time
                return 0
            return self.max_fails - len(fails)

    def success(self, client):
        with self._lock:
            self._fails.pop(client, None)
            self._locked.pop(client, None)


# ---------------------------------------------------------------------------
# Логи
# ---------------------------------------------------------------------------

def tail_command(path, count, euid=None, follow=False):
    """Команда чтения последних строк: tail -n N -- path (через sudo -n, если не root).

    follow=True — режим Real-time: tail -n N -F -- path (следит за файлом и после ротации).
    """
    euid = os.geteuid() if euid is None else euid
    args = ["tail", "-n", str(int(count))] + (["-F"] if follow else []) + ["--", path]
    return args if euid == 0 else ["sudo", "-n"] + args


def classify_tail_error(res):
    """Код ошибки и HTTP-статус по результату tail/sudo."""
    text = (res.err or "").lower()
    if res.rc == 124:
        return "timeout", 504
    if "no such file" in text:
        return "file_not_found", 404
    if "permission denied" in text or "password is required" in text or "sudo:" in text \
            or "not allowed" in text:
        return "permission_denied", 403
    return "read_error", 500


def read_log_tail(runner, path, count, euid=None):
    """Выполняет tail; возвращает (lines, error_code, http_status, command, stderr)."""
    args = tail_command(path, count, euid)
    command = " ".join(args)
    res = runner(args, timeout=10)
    if res.rc != 0:
        code, status = classify_tail_error(res)
        return None, code, status, command, res.err.strip()[:300]
    lines = []
    for raw in res.out.splitlines():
        line = strip_ansi(raw.rstrip("\r"))
        if len(line) > TAIL_MAX_LINE:
            line = line[:TAIL_MAX_LINE] + " …"
        lines.append(line)
    return lines[-count:], None, 200, command, ""


def spawn_process(args):
    """Запускает долгоживущую команду (tail -F, journalctl -f) без оболочки; stderr — в общий поток."""
    env = dict(os.environ)
    env.update({"SYSTEMD_PAGER": "", "PAGER": "cat", "SYSTEMD_COLORS": "0"})
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, env=env)


def stop_process(proc, timeout=2.0):
    """Завершает процесс и закрывает его канал вывода (иначе каждый сеанс Real-time оставлял бы дескриптор)."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout)
    except subprocess.TimeoutExpired:  # pragma: no cover (tail завершается по SIGTERM сразу)
        proc.kill()
        proc.wait()
    except OSError:  # pragma: no cover
        pass
    if proc.stdout is not None:
        proc.stdout.close()


class LineSplitter(object):
    """Собирает строки из кусков вывода; слишком длинная строка обрезается (TAIL_MAX_LINE)."""

    def __init__(self, journal=False):
        self.buf = b""
        self.journal = journal

    def _clean(self, raw):
        line = strip_ansi(raw.decode("utf-8", "replace").rstrip("\r"))
        if len(line) > TAIL_MAX_LINE:
            line = line[:TAIL_MAX_LINE] + " …"
        return line

    def feed(self, chunk):
        self.buf += chunk
        parts = self.buf.split(b"\n")
        self.buf = parts.pop()
        if len(self.buf) > TAIL_MAX_LINE * 4:  # строка без перевода — отдаём кусками
            parts.append(self.buf)
            self.buf = b""
        lines = [self._clean(p) for p in parts]
        if self.journal:
            lines = [line for line in lines if not line.startswith("-- ")]
        return lines

    def flush(self):
        rest, self.buf = self.buf, b""
        return [self._clean(rest)] if rest else []


def client_closed(sock):
    """True, если клиент закрыл соединение (вызывается, когда сокет стал читаемым).
    Браузер в потоке SSE ничего не отправляет, поэтому прочитанные байты можно отбросить."""
    old = sock.gettimeout()
    try:
        sock.settimeout(0)
        return sock.recv(1) == b""
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, socket.timeout):
        return False
    except (OSError, ValueError):
        return True
    finally:
        try:
            sock.settimeout(old)
        except (OSError, ValueError):  # pragma: no cover (сокет уже закрыт)
            pass


def sse_event(name, data):
    return ("event: %s\ndata: %s\n\n" % (name, json.dumps(data, ensure_ascii=False, separators=(",", ":")))).encode("utf-8")


def live_stream(write, spawn, command_for, resolve=None, stop=None, clock=time.monotonic,
                max_seconds=LIVE_MAX_SECONDS, heartbeat=LIVE_HEARTBEAT, flush_every=LIVE_FLUSH,
                check_every=LIVE_CHECK_FILE, journal=False, poll=0.2, conn=None):
    """Передаёт вывод команды событиями SSE, пока клиент не отключится.

    write(bytes) отправляет данные клиенту (исключение — клиент закрыл вкладку или нажал «Стоп»);
    command_for(target, switched) — команда для цели (switched=True — новый файл после ротации);
    resolve() — актуальный файл по маске (vms_<дата>.log):
    если он сменился, поток переключается на новый файл; conn — сокет клиента: его закрытие
    (вкладка закрыта, нажата «Стоп») замечается сразу, процесс tail завершается. Возвращает причину."""
    target = resolve() if resolve else None
    proc = spawn(command_for(target, False))
    started = last_write = last_check = clock()
    splitter = LineSplitter(journal)
    pending = []
    reason = "client_closed"
    try:
        write(b"retry: 3000\n\n")
        while True:
            now = clock()
            if stop is not None and stop.is_set():
                reason = "server_stopping"
                break
            if now - started >= max_seconds:
                reason = "time_limit"
                break
            watch = [proc.stdout] + ([conn] if conn is not None else [])
            readable, _, _ = select.select(watch, [], [], poll)
            if conn is not None and conn in readable and client_closed(conn):
                reason = "client_closed"
                break
            if proc.stdout in readable:
                chunk = os.read(proc.stdout.fileno(), 65536)
                if not chunk:
                    pending.extend(splitter.flush())
                    if pending:
                        write(sse_event("lines", pending))
                    reason = "exited"
                    break
                pending.extend(splitter.feed(chunk))
            if pending and (clock() - last_write >= flush_every or len(pending) >= 500):
                for i in range(0, len(pending), 500):  # событие — не больше 500 строк
                    write(sse_event("lines", pending[i:i + 500]))
                pending = []
                last_write = clock()
            elif clock() - last_write >= heartbeat:
                write(b": ping\n\n")
                last_write = clock()
            if resolve and clock() - last_check >= check_every:
                last_check = clock()
                fresh = resolve()
                if fresh and fresh != target:
                    stop_process(proc)
                    target = fresh
                    splitter = LineSplitter(journal)
                    proc = spawn(command_for(target, True))
                    write(sse_event("switch", {"path": target}))
        if reason != "client_closed":
            write(sse_event("end", {"reason": reason, "rc": proc.poll()}))
    except (OSError, ValueError, socket.error):
        reason = "client_closed"
    finally:
        stop_process(proc)
    return reason


def resolve_log_path(pattern):
    """Для маски возвращает самый свежий подходящий файл, иначе сам путь."""
    if any(ch in pattern for ch in "*?["):
        candidates = [p for p in glob.glob(pattern) if os.path.isfile(p)]
        if not candidates:
            return None
        return max(candidates, key=lambda p: (os.path.getmtime(p), p))
    return pattern


LOG_DATE_RES = (
    (re.compile(rb"^\[?(\d{4})-(\d{2})-(\d{2})[ T]"), (0, 1, 2)),   # 2026-11-03 17:02:17 / 2026-11-03T17:02
    (re.compile(rb"^\[?(\d{2})\.(\d{2})\.(\d{4})[ T,]"), (2, 1, 0)),  # 03.11.2026 17:02:17
    (re.compile(rb"^\[?(\d{4})/(\d{2})/(\d{2})[ T]"), (0, 1, 2)),   # 2026/11/03 17:02:17
)


# Компоненты KVM пишут логи строками JSON:
# {"level":"info","timestamp":"2026-11-05T12:26:44.782+0300","logger":"...","message":"..."}
JSON_DATE_RE = re.compile(rb'"(?:timestamp|@timestamp|time|ts|date)"\s*:\s*"(\d{4})-(\d{2})-(\d{2})')


def line_date(line):
    """Дата записи лога (date) или None — для строк продолжения (стек и т.п.).
    Текстовые логи: дата в начале строки; JSON-логи: поле timestamp."""
    if line[:1] == b"{" or line.lstrip()[:1] == b"{":
        match = JSON_DATE_RE.search(line, 0, 4096)
        regex_order = [(match, (0, 1, 2))] if match else []
    else:
        regex_order = [(regex.match(line), order) for regex, order in LOG_DATE_RES]
    for match, order in regex_order:
        if match:
            groups = match.groups()
            try:
                return datetime(int(groups[order[0]]), int(groups[order[1]]), int(groups[order[2]])).date()
            except ValueError:
                return None
    return None


JSON_LEVEL_RE = re.compile(rb'"(?:level|lvl|severity)"\s*:\s*"([A-Za-z]+)"')
TEXT_LEVEL_RE = re.compile(rb"\b(ERROR|ERR|FATAL|CRITICAL|CRIT|PANIC|EMERG|ALERT|SEVERE|WARNING|WARN)\b"
                           rb"|\blevel=([A-Za-z]+)")
LEVEL_WORDS = {
    b"error": "error", b"err": "error", b"fatal": "error", b"panic": "error", b"critical": "error",
    b"crit": "error", b"alert": "error", b"emerg": "error", b"severe": "error",
    b"warn": "warn", b"warning": "warn",
}


def line_level(line):
    """Уровень записи лога: 'error', 'warn' или None. Совпадает с подсветкой в веб-интерфейсе."""
    if line.lstrip()[:1] == b"{":
        match = JSON_LEVEL_RE.search(line, 0, 4096)
        return LEVEL_WORDS.get(match.group(1).lower()) if match else None
    match = TEXT_LEVEL_RE.search(line, 0, 400)
    if not match:
        return None
    return LEVEL_WORDS.get((match.group(1) or match.group(2)).lower())


def summarize_log_line(line, limit=500):
    """Краткое описание записи лога для отчёта и события: {"time", "message"}."""
    text = line.decode("utf-8", "replace").strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            message = str(obj.get("message") or obj.get("msg") or "")
            error = obj.get("error") or obj.get("err")
            if error and str(error) not in message:
                message = "%s: %s" % (message, error) if message else str(error)
            source = obj.get("logger") or obj.get("component") or ""
            return {"time": str(obj.get("timestamp") or obj.get("time") or obj.get("ts") or ""),
                    "source": str(source)[:120], "message": (message or text)[:limit]}
    return {"time": "", "source": "", "message": text[:limit]}


def scan_log_levels(path, start=0, max_bytes=REPORT_SCAN_MAX, keep=REPORT_LAST_ERRORS, end=None):
    """Считает записи уровней error/warn в файле начиная с позиции start.

    Просматривается не больше max_bytes с конца диапазона (truncated=True, если часть
    пропущена). Незавершённая последняя строка не учитывается: next_offset указывает
    на её начало, чтобы следующий проход прочитал её целиком."""
    size = os.path.getsize(path) if end is None else end
    begin = max(start, size - max_bytes)
    result = {"lines": 0, "errors": 0, "warnings": 0, "scanned_bytes": 0,
              "truncated": begin > start, "last_errors": [], "next_offset": begin}
    last = deque(maxlen=max(keep, 1))
    with open(path, "rb") as fh:
        fh.seek(begin)
        pos = begin
        if begin > start and begin > 0:
            fh.seek(begin - 1)
            if fh.read(1) != b"\n":
                pos += len(fh.readline())  # попали в середину строки
        while pos < size:
            line = fh.readline()
            if not line or not line.endswith(b"\n"):
                break
            pos += len(line)
            result["lines"] += 1
            level = line_level(line)
            if level == "error":
                result["errors"] += 1
                last.append(line)
            elif level == "warn":
                result["warnings"] += 1
        result["next_offset"] = pos
        result["scanned_bytes"] = pos - begin
    if keep:
        result["last_errors"] = [summarize_log_line(line) for line in last]
    return result


def _dated_line_at(fh, offset, size, scan_limit=1024 * 1024):
    """Первая строка с датой, начинающаяся не раньше offset: (позиция, дата) или (None, None)."""
    fh.seek(offset)
    if offset > 0:
        fh.readline()  # дочитываем строку, в середину которой попали
    scanned = 0
    while scanned < scan_limit:
        pos = fh.tell()
        if pos >= size:
            return None, None
        line = fh.readline()
        if not line:
            return None, None
        scanned += len(line)
        day = line_date(line)
        if day is not None:
            return pos, day
    return None, None


def today_offset(path, day):
    """Смещение первой строки за день `day` (логи пишутся по порядку времени — двоичный поиск).
    None — в файле нет строк с датой (формат не распознан); size — строк за этот день нет."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        first_pos, first_day = _dated_line_at(fh, 0, size)
        if first_pos is None:
            return None
        if first_day >= day:
            return 0
        lo, hi = 0, size  # инвариант: строка на lo — раньше day
        while hi - lo > 4096:
            mid = (lo + hi) // 2
            pos, found = _dated_line_at(fh, mid, size)
            if pos is None or found >= day:
                hi = mid
            else:
                lo = mid
        pos = lo
        while True:  # последние ≤4 КБ + строки продолжения: читаем без ограничения
            pos, found = _dated_line_at(fh, pos, size, scan_limit=size + 1)
            if pos is None:
                return size
            if found >= day:
                return pos
            pos += 1


def copy_range(src_path, start, dst, end=None):
    with open(src_path, "rb") as src:
        src.seek(start)
        left = None if end is None else end - start
        while left is None or left > 0:
            chunk = src.read(1024 * 1024 if left is None else min(1024 * 1024, left))
            if not chunk:
                break
            dst.write(chunk)
            if left is not None:
                left -= len(chunk)


def parse_day(value):
    """'ГГГГ-ММ-ДД' -> date, если день не в будущем; иначе None."""
    try:
        day = datetime.strptime(str(value or ""), "%Y-%m-%d").date()
    except ValueError:
        return None
    return day if date(1970, 1, 2) <= day <= date.today() else None


def log_candidates(pattern):
    """Файл лога и его ротированные копии рядом: worker.log, worker.log.1, worker.log-20261105.gz…"""
    found = set()
    for pat in (pattern, pattern + ".*", pattern + "-*"):
        if pat == pattern and not any(ch in pattern for ch in "*?["):
            found.add(pattern)
        else:
            found.update(glob.glob(pat))
    return sorted(p for p in found if os.path.isfile(p))


def gzip_day_lines(path, day, dst):
    """Строки за день из сжатого лога (.gz): читается последовательно, строки продолжения
    (без даты) идут вместе с предыдущей строкой. Возвращает (байт записано, найдены ли даты)."""
    written, dated, inside = 0, False, False
    with gzip.open(path, "rb") as fh:
        for line in fh:
            found = line_date(line)
            if found is not None:
                dated = True
                if found > day:
                    break
                inside = found == day
            if inside:
                dst.write(line)
                written += len(line)
    return written, dated


def build_today_logs_zip(log_files, out_fh, now=None, host="", day=None):
    """Архив логов компонентов за день (по умолчанию — сегодня). Пишет zip в out_fh,
    возвращает список включённых файлов.

    Берутся файл лога и его ротированные копии (в том числе .gz), изменённые в этот день или
    позже. Из каждого — строки этого дня (строки продолжения — стеки исключений — сохраняются;
    логи пишутся по порядку времени, начало и конец дня ищутся двоичным поиском). Если даты
    в строках не распознаны, файл включается целиком, когда он изменён в этот день."""
    now = now or datetime.now()
    day = day or now.date()
    next_day = day + timedelta(days=1)
    day_start = datetime(day.year, day.month, day.day).timestamp()
    day_end = datetime(next_day.year, next_day.month, next_day.day).timestamp()
    is_today = day == now.date()
    included = []
    with zipfile.ZipFile(out_fh, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for item in log_files:
            for path in log_candidates(item["path"]):
                try:
                    mtime = os.path.getmtime(path)
                    if mtime < day_start:
                        continue
                    name = os.path.basename(path)
                    fd, tmp_name = tempfile.mkstemp(prefix=".kvm-logs-")
                    try:
                        with os.fdopen(fd, "wb") as tmp:
                            if path.endswith(".gz"):
                                name = name[:-3]
                                size, dated = gzip_day_lines(path, day, tmp)
                                mode = "day" if dated else "skipped: no dates"
                            else:
                                start = today_offset(path, day)
                                mode = "today" if is_today else "day"
                                end = None
                                if start is None:
                                    if mtime >= day_end:
                                        continue
                                    start, mode = 0, "whole-file"
                                elif mtime >= day_end:
                                    end = today_offset(path, next_day)
                                size = (os.path.getsize(path) if end is None else end) - start
                                if size > 0:
                                    copy_range(path, start, tmp, end)
                        if size > 0:
                            zf.write(tmp_name, "%s/%s" % (item["key"], name))
                    finally:
                        os.unlink(tmp_name)
                    if size > 0:
                        included.append({"key": item["key"], "file": path, "bytes": size, "mode": mode})
                except (OSError, IOError, EOFError) as exc:
                    included.append({"key": item["key"], "file": path, "bytes": 0, "mode": "error: %s" % exc})
        lines = ["Kaspersky VM Metrics %s" % __version__,
                 "Host: %s" % host,
                 "Logs for: %s (created %s)" % (day.strftime("%d.%m.%Y"), now.strftime("%d.%m.%Y %H:%M:%S")),
                 ""]
        if not included:
            lines.append("No component log entries for today." if is_today
                         else "No component log entries for %s." % day.strftime("%d.%m.%Y"))
        for entry in included:
            lines.append("%-11s %s  %d bytes  (%s)" % (entry["key"], entry["file"], entry["bytes"], entry["mode"]))
        zf.writestr("README.txt", "\n".join(lines) + "\n")
    return included


def file_meta(path):
    try:
        st = os.stat(path)
    except OSError:
        return {"exists": False, "size": None, "mtime": None, "readable": False}
    # не root: файл всё равно может быть прочитан через sudo -n tail
    return {"exists": True, "size": st.st_size, "mtime": int(st.st_mtime),
            "readable": os.access(path, os.R_OK) or os.geteuid() != 0}


def report_date(name):
    """Дата из имени отчёта kaspersky-vm-services-state_ДД_ММ_ГГГГ.json или datetime.min."""
    try:
        return datetime.strptime(os.path.splitext(name)[0][len(REPORT_PREFIX):], "%d_%m_%Y")
    except ValueError:
        return datetime.min


def list_reports(log_dir=None):
    log_dir = log_dir or LOG_DIR
    reports = []
    try:
        names = os.listdir(log_dir)
    except OSError:
        return reports
    for name in names:
        if REPORT_RE.match(name):
            meta = file_meta(os.path.join(log_dir, name))
            reports.append({"name": name, "size": meta["size"], "mtime": meta["mtime"]})
    reports.sort(key=lambda item: report_date(item["name"]), reverse=True)  # новые сверху
    return reports


def report_path(name, log_dir=None):
    """Безопасный путь к отчёту или None (защита от обхода каталогов)."""
    if not isinstance(name, str) or not REPORT_RE.match(name):
        return None
    path = os.path.join(log_dir or LOG_DIR, name)
    return path if os.path.isfile(path) else None


def build_reports_zip(names, log_dir=None):
    buf = io.BytesIO()
    added = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in names:
            path = report_path(name, log_dir)
            if path:
                zf.write(path, name)
                added += 1
    return buf.getvalue(), added


def disk_usage(paths=REPORT_DISK_PATHS):
    """Заполнение файловых систем, на которых лежат ОС, логи, СУБД и сервис (без повторов)."""
    seen = set()
    result = []
    for path in paths:
        try:
            st = os.statvfs(path)
            dev = os.stat(path).st_dev
        except OSError:
            continue
        if dev in seen:
            continue
        seen.add(dev)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        result.append({"path": path, "total_bytes": total, "used_bytes": used, "free_bytes": free,
                       "percent": round(used * 100.0 / (used + free), 1) if used + free else 0.0})
    return result


def certificate_info(cert_file=None, runner=None, now=None):
    """Срок действия сертификата веб-интерфейса: {"not_after", "days_left"} или None."""
    cert_file = cert_file or CERT_FILE
    if not os.path.exists(cert_file):
        return None
    res = (runner or run_cmd)(["openssl", "x509", "-enddate", "-noout", "-in", cert_file])
    match = re.search(r"notAfter=(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})", res.out or "")
    if res.rc != 0 or not match:
        return None
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    if match.group(1) not in months:
        return None
    end = datetime(int(match.group(6)), months.index(match.group(1)) + 1, int(match.group(2)),
                   int(match.group(3)), int(match.group(4)), int(match.group(5)))
    left = end - (now or datetime(*time.gmtime()[:6]))
    return {"not_after": end.strftime("%Y-%m-%dT%H:%M:%SZ"), "days_left": left.days}


def log_today_summary(item, now=None):
    """Сводка лога компонента за сегодня: размер, число ошибок и предупреждений, последние ошибки."""
    now = now or datetime.now()
    resolved = resolve_log_path(item["path"])
    entry = {"key": item["key"], "title": item["title_ru"], "path": item["path"], "file": resolved,
             "exists": False, "size_bytes": None, "modified": None, "today": None}
    if not resolved or not os.path.isfile(resolved):
        return entry
    try:
        st = os.stat(resolved)
        entry.update({"exists": True, "size_bytes": st.st_size, "modified": iso_local(st.st_mtime)})
        midnight = datetime(now.year, now.month, now.day).timestamp()
        if st.st_mtime < midnight:
            entry["today"] = {"errors": 0, "warnings": 0, "lines": 0, "scanned_bytes": 0,
                              "truncated": False, "last_errors": [], "date_format": "n/a"}
            return entry
        start = today_offset(resolved, now.date())
        detected = start is not None
        scan = scan_log_levels(resolved, start if detected else 0, end=st.st_size)
        scan.pop("next_offset", None)
        scan["date_format"] = "detected" if detected else "unknown (whole file)"
        entry["today"] = scan
    except (OSError, IOError) as exc:
        entry["error"] = str(exc)
    return entry


def build_state_report(app, kind="on-demand", now=None):
    """Отчёт о состоянии (dict): службы, система, диски, ошибки в логах, события, SIEM."""
    now = now or datetime.now()
    data = app.collector.get(force=True)
    stamp = now.timestamp()
    problems = []
    services = []
    for svc in data["services"]:
        item = dict((k, svc.get(k)) for k in ("key", "unit", "state", "sub_state", "result", "pid",
                                               "memory_bytes", "memory_source", "tasks", "restarts",
                                               "uptime_sec"))
        item["description"] = svc.get("desc_ru", "")
        item["active_since"] = iso_local(stamp - svc["uptime_sec"]) if svc.get("uptime_sec") is not None else None
        if "db_connections" in svc:
            item["db_connections"] = svc["db_connections"]
        last = app.restarts.results.get(svc["key"])
        if last:
            item["last_restart_from_dashboard"] = {"result": last["result"], "started": iso_local(last["started"]),
                                                   "finished": iso_local(last["finished"])}
        services.append(item)
        if svc["state"] != "active":
            problems.append({"severity": "critical", "code": "service_not_running", "key": svc["key"],
                             "message": "Служба %s не работает (состояние: %s)" % (svc["unit"], svc["state"])})

    system = dict(data["system"])
    try:
        system["kernel"] = os.uname()[2]
        system["load_average"] = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):  # pragma: no cover (не Linux)
        pass
    mem = system.get("memory") or {}
    if mem.get("total"):
        used_pct = round((mem["total"] - mem.get("available", 0)) * 100.0 / mem["total"], 1)
        system["memory"] = dict(mem, used_percent=used_pct)
        if used_pct >= MEM_ALERT_PERCENT:
            problems.append({"severity": "warning", "code": "memory_high",
                             "message": "Занято %.1f%% оперативной памяти" % used_pct})
    system["disks"] = disk_usage()
    for disk in system["disks"]:
        if disk["percent"] >= DISK_ALERT_PERCENT:
            problems.append({"severity": "warning", "code": "disk_high", "path": disk["path"],
                             "message": "Файловая система %s заполнена на %.1f%%" % (disk["path"], disk["percent"])})

    logs = [log_today_summary(item, now) for item in app.log_files]
    errors = sum((entry["today"] or {}).get("errors", 0) for entry in logs)
    warnings = sum((entry["today"] or {}).get("warnings", 0) for entry in logs)
    for entry in logs:
        today = entry["today"] or {}
        if today.get("errors"):
            problems.append({"severity": "warning", "code": "log_errors", "key": entry["key"],
                             "message": "%s: записей с ошибками за сегодня — %d" % (entry["title"], today["errors"])})

    certificate = certificate_info()
    if certificate and certificate["days_left"] < 30:
        problems.append({"severity": "warning", "code": "certificate_expiring",
                         "message": "Сертификат веб-интерфейса истекает через %d дн." % certificate["days_left"]})

    events = app.events.recent(since=stamp - 86400)
    running = data["summary"]["running"]
    status = "ok"
    if any(p["severity"] == "critical" for p in problems):
        status = "critical"
    elif problems:
        status = "warning"
    return {
        "report": "kaspersky-vm-services-state",
        "schema": REPORT_SCHEMA,
        "kind": kind,
        "generated": iso_local(stamp),
        "host": data["host"],
        "monitor_version": __version__,
        "summary": {
            "status": status,
            "services_total": len(services),
            "services_running": running,
            "services_not_running": [s["key"] for s in services if s["state"] != "active"],
            "services_memory_bytes": data["summary"]["services_memory_bytes"],
            "log_errors_today": errors,
            "log_warnings_today": warnings,
            "events_24h": len(events),
            "problems": problems,
        },
        "system": system,
        "services": services,
        "logs": logs,
        "ports": data["ports"],
        "events_24h": events,
        "siem": app.siem.status(),
        "certificate": certificate,
    }


def report_json_bytes(report):
    return (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")


def write_daily_report(app, log_dir=None, today=None):
    """Пишет ежедневный отчёт о состоянии в JSON и чистит старые отчёты."""
    log_dir = log_dir or LOG_DIR
    today = today or datetime.now()
    filename = REPORT_PREFIX + today.strftime("%d_%m_%Y") + ".json"
    filepath = os.path.join(log_dir, filename)
    report = build_state_report(app, "daily", today)
    content = report_json_bytes(report)
    fd, tmp = tempfile.mkstemp(prefix=".report-", dir=log_dir)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.chmod(tmp, 0o644)
        os.rename(tmp, filepath)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    cleanup_old_reports(log_dir)
    summary = report["summary"]
    app.events.emit("report_created", "Daily state report: %s, services running %d of %d, log errors today %d" % (
        summary["status"], summary["services_running"], summary["services_total"], summary["log_errors_today"]),
        file=filepath, outcome=summary["status"])
    return filepath


def cleanup_old_reports(log_dir=None, keep_days=REPORT_KEEP_DAYS, now=None):
    log_dir = log_dir or LOG_DIR
    limit = ((now or datetime.now()) - timedelta(days=keep_days)).timestamp()
    removed = 0
    try:
        names = os.listdir(log_dir)
    except OSError:
        return 0
    for name in names:
        if REPORT_RE.match(name):
            path = os.path.join(log_dir, name)
            try:
                if os.path.getmtime(path) < limit:
                    os.remove(path)
                    removed += 1
            except OSError:
                pass
    return removed


def report_due(now, last_date, log_dir=None, hour=REPORT_HOUR):
    """Отчёт нужен, если наступил час отчёта, сегодня он ещё не писался и файла нет."""
    if now.hour < hour or last_date == now.date():
        return False
    name = REPORT_PREFIX + now.strftime("%d_%m_%Y") + ".json"
    return not os.path.exists(os.path.join(log_dir or LOG_DIR, name))


# ---------------------------------------------------------------------------
# TLS-сертификат
# ---------------------------------------------------------------------------

OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = {cn}
[v3]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = {san}
"""


def certificate_needs_renewal(cert_file=None, runner=None):
    cert_file = cert_file or CERT_FILE
    runner = runner or run_cmd
    if not os.path.exists(cert_file):
        return True
    res = runner(["openssl", "x509", "-checkend", str(CERT_RENEW_BEFORE), "-noout", "-in", cert_file])
    return res.rc == 1  # 1 = истекает; прочие ошибки не повод перезаписывать сертификат


def build_san(fqdn):
    names = ["DNS:" + fqdn]
    short = fqdn.split(".")[0]
    if short and short != fqdn:
        names.append("DNS:" + short)
    names.extend(["DNS:localhost", "IP:127.0.0.1"])
    unique = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return ",".join(unique)


def generate_certificate(fqdn, cert_file=None, key_file=None, runner=None, force=False):
    """Создаёт самоподписанный сертификат (с SAN) или обновляет истекающий."""
    cert_file = cert_file or CERT_FILE
    key_file = key_file or KEY_FILE
    runner = runner or run_cmd
    if not force and os.path.exists(cert_file) and os.path.exists(key_file) \
            and not certificate_needs_renewal(cert_file, runner):
        return True
    cn = re.sub(r"[^A-Za-z0-9.-]", "", fqdn)[:64] or "localhost"
    fd, cnf = tempfile.mkstemp(prefix="kvm-openssl-", suffix=".cnf")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(OPENSSL_CNF.format(cn=cn, san=build_san(cn)))
        tmp_key, tmp_cert = key_file + ".new", cert_file + ".new"
        res = runner(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                      "-keyout", tmp_key, "-out", tmp_cert, "-days", str(CERT_DAYS),
                      "-nodes", "-config", cnf], timeout=60)
        if res.rc != 0 or not os.path.exists(tmp_cert):
            log("certificate generation failed: %s", res.err.strip()[:300])
            for path in (tmp_key, tmp_cert):
                if os.path.exists(path):
                    os.unlink(path)
            return os.path.exists(cert_file) and os.path.exists(key_file)
        os.chmod(tmp_key, 0o600)
        os.chmod(tmp_cert, 0o644)
        os.rename(tmp_key, key_file)
        os.rename(tmp_cert, cert_file)
        log("certificate generated for %s", cn)
        return True
    finally:
        try:
            os.unlink(cnf)
        except OSError:
            pass


def make_ssl_context(cert_file=None, key_file=None):
    proto = getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_SSLv23)
    context = ssl.SSLContext(proto)
    if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):  # Python 3.7+
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # novermin (защищено hasattr)
    else:  # pragma: no cover (Python 3.5/3.6: Astra Linux CE 2.12, SberLinux 8)
        for name in ("OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            context.options |= getattr(ssl, name, 0)
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.options |= getattr(ssl, "OP_CIPHER_SERVER_PREFERENCE", 0)
    try:
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS")
    except ssl.SSLError:  # pragma: no cover (OpenSSL без этих наборов шифров)
        pass
    context.load_cert_chain(cert_file or CERT_FILE, key_file or KEY_FILE)
    return context


# ---------------------------------------------------------------------------
# systemd notify / watchdog (WatchdogSec= в unit-файле)
# ---------------------------------------------------------------------------

def sd_notify(message, environ=None):
    environ = os.environ if environ is None else environ
    address = environ.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(address)
        sock.sendall(message.encode("utf-8"))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def watchdog_interval(environ=None):
    """Интервал пинга watchdog в секундах (треть WatchdogSec) или None."""
    environ = os.environ if environ is None else environ
    usec = to_int(environ.get("WATCHDOG_USEC"))
    if not usec:
        return None
    wd_pid = to_int(environ.get("WATCHDOG_PID"))
    if wd_pid and wd_pid != os.getpid():
        return None
    return usec / 1e6 / 3.0


def watchdog_loop(server, stop, interval):
    """Пингует systemd, только пока цикл HTTP-сервера жив (heartbeat свежий)."""
    while not stop.wait(interval):
        if time.monotonic() - server.heartbeat < interval * 1.5:
            sd_notify("WATCHDOG=1")


# ---------------------------------------------------------------------------
# События и отправка в SIEM (syslog + CEF)
# ---------------------------------------------------------------------------

# Важность (Severity в CEF) — шкала 1–5: 1 информация, 2 низкая, 3 средняя, 4 высокая, 5 критическая.
# name: (Signature ID, важность 1–5, категория, Name в CEF)
EVENT_TYPES = {
    "monitor_started": (100, 1, "monitor", "Monitoring service started"),
    "monitor_stopped": (101, 2, "monitor", "Monitoring service stopped"),
    "service_up": (200, 1, "service", "Service is running"),
    "service_down": (201, 4, "service", "Service stopped"),
    "service_failed": (202, 5, "service", "Service failed"),
    "service_auto_restart": (203, 3, "service", "Service restarted by systemd"),
    "restart_requested": (210, 2, "service", "Service restart requested"),
    "restart_ok": (211, 1, "service", "Service restart completed"),
    "restart_failed": (212, 4, "service", "Service restart failed"),
    "restart_timeout": (213, 4, "service", "Service restart timed out"),
    "auth_failed": (300, 3, "auth", "Wrong root password"),
    "auth_locked": (301, 4, "auth", "Client blocked after failed root password attempts"),
    "csrf_rejected": (302, 4, "auth", "Request from foreign origin rejected"),
    "settings_changed": (310, 3, "config", "SIEM forwarding settings changed"),
    "memory_high": (400, 3, "system", "High memory usage"),
    "memory_ok": (401, 1, "system", "Memory usage back to normal"),
    "disk_high": (402, 4, "system", "Low disk space"),
    "disk_ok": (403, 1, "system", "Disk space back to normal"),
    "log_errors": (500, 3, "log", "Errors in component log"),
    "report_created": (600, 1, "report", "Daily state report created"),
    "siem_test": (900, 1, "test", "Test event"),
}

# поля события -> ключи расширения CEF (ArcSight CEF Extension Dictionary)
CEF_FIELDS = (
    ("client", "src", None),
    ("user", "suser", None),
    ("action", "act", None),
    ("outcome", "outcome", None),
    ("file", "filePath", None),
    ("count", "cnt", None),
    ("unit", "cs1", "unit"),
    ("state", "cs2", "state"),
    ("key", "cs3", "component"),
    ("path", "cs4", "path"),
    ("target", "cs5", "target"),
    ("percent", "cfp1", "percent"),
)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
IP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)$")


class EventBus(object):
    """Журнал событий сервиса (последние maxlen) с подписчиками (отправка в SIEM)."""

    def __init__(self, maxlen=500, clock=time.time):
        self.clock = clock
        self._events = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0
        self._listeners = []

    def subscribe(self, listener):
        self._listeners.append(listener)

    def emit(self, name, message, **fields):
        signature, severity, category, title = EVENT_TYPES[name]
        message = one_space(message)
        with self._lock:
            self._seq += 1
            event = {"id": self._seq, "time": self.clock(), "name": name, "title": title,
                     "signature": signature, "severity": severity, "category": category,
                     "message": message, "fields": dict((k, v) for k, v in fields.items() if v is not None)}
            self._events.append(event)
        for listener in list(self._listeners):
            try:
                listener(event)
            except Exception as exc:  # подписчик не должен ломать источник события
                log("event listener failed: %s", exc)
        return event

    def count(self):
        with self._lock:
            return len(self._events)

    def raw_recent(self, limit):
        """Последние limit событий как есть (время — epoch), от старых к новым."""
        with self._lock:
            return [dict(e) for e in self._events][-limit:]

    def recent(self, since=None, limit=200, raw=None):
        """Последние события; raw(event) -> строка, как она уходит в SIEM (для панели в интерфейсе)."""
        with self._lock:
            items = [dict(e) for e in self._events if since is None or e["time"] >= since][-limit:]
        out = []
        for e in items:
            item = dict(e, time=iso_local(e["time"]))
            if "siem_time" in e:
                item["siem_time"] = iso_local(e["siem_time"])
            if raw is not None:
                item["raw"] = raw(e)
            out.append(item)
        return out


def one_space(value):
    """Любые пробельные символы подряд (пробелы, табуляции, переводы строк) -> один пробел."""
    return " ".join(str(value).split())


def cef_header(value):
    return one_space(value).replace("\\", "\\\\").replace("|", "\\|")


def cef_value(value):
    return one_space(value).replace("\\", "\\\\").replace("=", "\\=")


def syslog_severity(level):
    """Важность 1–5 -> severity syslog: 5 crit (2), 4 err (3), 3 warning (4), 2 notice (5), 1 info (6)."""
    return {5: 2, 4: 3, 3: 4, 2: 5}.get(level, 6)


def format_cef(event, host, version=None):
    ext = [("rt", int(event["time"] * 1000)), ("dvchost", host), ("cat", event["category"]),
           ("msg", event["message"])]
    fields = event.get("fields") or {}
    for name, key, label in CEF_FIELDS:
        value = fields.get(name)
        if value is None or value == "":
            continue
        if key == "src" and not IP_RE.match(str(value)):
            continue
        if label:
            ext.append((key + "Label", label))
        ext.append((key, value))
    header = "CEF:0|%s|%s|%s|%s|%s|%d|" % (
        cef_header("Kaspersky"), cef_header("Kaspersky VM Metrics"), cef_header(version or __version__),
        cef_header(event["signature"]), cef_header(event["title"]), event["severity"])
    return header + " ".join("%s=%s" % (k, cef_value(v)) for k, v in ext)


def format_syslog(event, host, version=None):
    """Строка syslog RFC 3164: <PRI>Mmm dd hh:mm:ss host CEF:0|..."""
    tm = time.localtime(event["time"])
    stamp = "%s %d %02d:%02d:%02d" % (MONTHS[tm.tm_mon - 1], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
    pri = SIEM_FACILITY * 8 + syslog_severity(event["severity"])
    hostname = re.sub(r"\s", "", host) or "-"
    return "<%d>%s %s %s" % (pri, stamp, hostname, format_cef(event, host, version))


def encode_syslog(line, protocol):
    data = line.replace("\n", " ").encode("utf-8")
    limit = SIEM_UDP_MAX if protocol == "udp" else SIEM_TCP_MAX
    if len(data) > limit:
        data = data[:limit - 3].decode("utf-8", "ignore").encode("utf-8") + b"..."
    return data if protocol == "udp" else data + b"\n"  # TCP: одно событие — одна строка (LF)


SIEM_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def normalize_siem(raw):
    """Проверяет настройки SIEM из запроса. Возвращает (config, error_code)."""
    if not isinstance(raw, dict):
        return None, "bad_request"
    host = raw.get("host")
    host = host.strip().strip("[]") if isinstance(host, str) else ""
    enabled = bool(raw.get("enabled", True))
    protocol = raw.get("protocol") or SIEM_RECOMMENDED_PROTOCOL
    if protocol not in ("tcp", "udp"):
        return None, "bad_protocol"
    try:
        port = int(raw.get("port") if raw.get("port") not in (None, "") else SIEM_RECOMMENDED_PORT)
    except (TypeError, ValueError):
        return None, "bad_port"
    if not 1 <= port <= 65535:
        return None, "bad_port"
    if host and not SIEM_HOST_RE.match(host):
        return None, "bad_host"
    if enabled and not host:
        return None, "host_required"
    return {"enabled": enabled, "host": host, "port": port, "protocol": protocol}, None


def load_settings(path=None):
    try:
        with open(path or SETTINGS_FILE, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except (OSError, IOError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_settings(data, path=None):
    """Атомарно сохраняет settings.json (права 600: адрес SIEM — служебная информация)."""
    path = path or SETTINGS_FILE
    fd, tmp = tempfile.mkstemp(prefix=".settings-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        os.chmod(tmp, 0o600)
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class SyslogSender(object):
    """Отправляет события в SIEM в отдельном потоке: очередь, переподключение, учёт ошибок.

    TCP — постоянное соединение, события разделяются LF; перед отправкой проверяется,
    не закрыла ли SIEM соединение. UDP — по датаграмме на событие (доставка не гарантируется)."""

    DEFAULT = {"enabled": False, "host": "", "port": SIEM_RECOMMENDED_PORT, "protocol": SIEM_RECOMMENDED_PROTOCOL}

    def __init__(self, hostname, timeout=SIEM_CONNECT_TIMEOUT, queue_max=SIEM_QUEUE_MAX, max_backoff=60.0):
        self.hostname = hostname
        self.timeout = timeout
        self.max_backoff = max_backoff
        self.config = dict(self.DEFAULT)
        self._queue = deque(maxlen=queue_max)
        self._cond = threading.Condition()
        self._io = threading.Lock()
        self._sock = None
        self._thread = None
        self._stopping = False
        self.stats = {"sent": 0, "failed": 0, "dropped": 0, "last_error": "", "last_error_time": None,
                      "last_sent_time": None, "connected": False}

    # -- настройки и состояние ------------------------------------------------------
    def configure(self, config):
        with self._cond:
            changed = (config.get("host"), config.get("port"), config.get("protocol")) != \
                (self.config.get("host"), self.config.get("port"), self.config.get("protocol"))
            self.config = dict(self.DEFAULT, **config)
            if changed:
                self.stats.update({"last_error": "", "last_error_time": None})
            if not self.config["enabled"]:
                for queued in self._queue:
                    queued["siem"] = "dropped"
                self._queue.clear()
            self._cond.notify_all()
        if changed:
            self._close()

    def status(self):
        with self._cond:
            stats = dict(self.stats, queued=len(self._queue))
            config = dict(self.config)
        if not config["enabled"]:
            state = "off"
        elif stats["last_error_time"] and (not stats["last_sent_time"] or
                                           stats["last_error_time"] >= stats["last_sent_time"]):
            state = "error"
        elif stats["last_sent_time"]:
            state = "ok"
        else:
            state = "waiting"
        for name in ("last_error_time", "last_sent_time"):
            if stats[name]:
                stats[name] = iso_local(stats[name])
        return dict(config, state=state, stats=stats)

    def submit(self, event):
        """В очередь на отправку. Состояние доставки пишется в само событие (поле siem):
        queued — ждёт отправки, sent — передано SIEM, dropped — не отправлено (вытеснено из
        переполненной очереди или отправка выключена). Тестовое событие отправляется сразу
        (send_test_event) и в очередь не попадает — иначе SIEM получила бы его дважды."""
        if event.get("name") == "siem_test":
            return False
        with self._cond:
            if not self.config["enabled"] or self._stopping:
                return False
            if len(self._queue) == self._queue.maxlen:
                self.stats["dropped"] += 1
                self._queue.popleft()["siem"] = "dropped"
            event["siem"] = "queued"
            self._queue.append(event)
            self._cond.notify()
            return True

    # -- поток отправки ---------------------------------------------------------------
    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self.run, name="siem-sender", daemon=True)
            self._thread.start()
        return self._thread

    def stop(self, flush_timeout=2.0):
        deadline = time.monotonic() + flush_timeout
        with self._cond:
            while self._queue and self.config["enabled"] and self._thread is not None \
                    and time.monotonic() < deadline:
                self._cond.wait(0.1)
            self._stopping = True
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(flush_timeout)
        self._close()

    def run(self):
        backoff = 1.0
        while True:
            with self._cond:
                while not self._stopping and (not self._queue or not self.config["enabled"]):
                    self._cond.wait(5)
                if self._stopping:
                    return
                event = self._queue[0]
                config = dict(self.config)
            ok = self.send(event, config)
            with self._cond:
                if ok:
                    event["siem"] = "sent"
                    event["siem_time"] = time.time()
                    if self._queue and self._queue[0] is event:
                        self._queue.popleft()
                    backoff = 1.0
                    self._cond.notify_all()
                else:
                    self._cond.wait(backoff)
                    backoff = min(backoff * 2, self.max_backoff)

    def _close(self):
        with self._io:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:  # pragma: no cover
                    pass
            self._sock = None
            self.stats["connected"] = False

    def _tcp_alive(self):
        """Соединение открыто и SIEM его не закрыла (иначе первая отправка «уйдёт в никуда»)."""
        try:
            readable, _, _ = select.select([self._sock], [], [], 0)
            if readable and not self._sock.recv(1024, socket.MSG_PEEK):
                return False
        except (OSError, ValueError):
            return False
        return True

    def send(self, event, config):
        """Отправляет одно событие; True — успешно (для UDP — передано в сеть).
        Сокет защищён отдельной блокировкой: подключение к недоступной SIEM (до timeout секунд)
        не задерживает submit() в обработчиках запросов."""
        payload = encode_syslog(format_syslog(event, self.hostname), config["protocol"])
        try:
            if config["protocol"] == "udp":
                send_udp(config["host"], config["port"], payload, self.timeout)
            else:
                with self._io:
                    if self._sock is not None and not self._tcp_alive():
                        self._sock.close()
                        self._sock = None
                    if self._sock is None:
                        self._sock = socket.create_connection((config["host"], config["port"]), self.timeout)
                    self._sock.sendall(payload)
                    self.stats["connected"] = True
        except (OSError, socket.error) as exc:
            self._close()
            with self._cond:
                self.stats["failed"] += 1
                self.stats["last_error"] = str(exc)[:300] or exc.__class__.__name__
                self.stats["last_error_time"] = time.time()
            return False
        with self._cond:
            self.stats["sent"] += 1
            self.stats["last_sent_time"] = time.time()
        return True


def send_udp(host, port, payload, timeout=SIEM_CONNECT_TIMEOUT):
    family, socktype, proto, _, addr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
    sock = socket.socket(family, socktype, proto)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, addr)
    finally:
        sock.close()


def send_test_event(config, hostname, events=None, client=None):
    """Синхронно отправляет тестовое событие по указанным настройкам. Возвращает (ok, error).
    Событие попадает в журнал событий (с состоянием доставки) ровно в том виде, в каком отправлено."""
    target = "%s:%s/%s" % (config["host"], config["port"], config["protocol"])
    message = "Kaspersky VM Metrics test event"
    if events is not None:
        event = events.emit("siem_test", message, client=client, target=target)
    else:
        event = {"id": 0, "time": time.time(), "name": "siem_test", "title": EVENT_TYPES["siem_test"][3],
                 "signature": EVENT_TYPES["siem_test"][0], "severity": EVENT_TYPES["siem_test"][1],
                 "category": "test", "message": message, "fields": {"client": client, "target": target}}
    payload = encode_syslog(format_syslog(event, hostname), config["protocol"])
    try:
        if config["protocol"] == "udp":
            send_udp(config["host"], config["port"], payload)
        else:
            sock = socket.create_connection((config["host"], config["port"]), SIEM_CONNECT_TIMEOUT)
            try:
                sock.sendall(payload)
            finally:
                sock.close()
    except (OSError, socket.error) as exc:
        event["siem"] = "dropped"
        return False, str(exc)[:300] or exc.__class__.__name__
    event["siem"] = "sent"
    event["siem_time"] = time.time()
    return True, None


class StateMonitor(object):
    """Следит за сменой состояний и порождает события: службы, память, диски, ошибки в логах."""

    STABLE = ("active", "inactive", "failed", "not-found", "masked")

    def __init__(self, app, clock=time.monotonic, log_scan_interval=LOG_SCAN_INTERVAL,
                 disk_paths=REPORT_DISK_PATHS):
        self.app = app
        self.clock = clock
        self.log_scan_interval = log_scan_interval
        self.disk_paths = disk_paths
        self.services = None    # key -> (state, NRestarts)
        self.memory_high = False
        self.disks_high = set()
        self.log_offsets = {}
        self.last_log_scan = None
        self.logs_baselined = False

    def emit(self, name, message, **fields):
        self.app.events.emit(name, message, **fields)

    def check_services(self, data):
        previous = self.services
        current = dict(previous or {})
        for svc in data["services"]:
            key, state, restarts = svc["key"], svc["state"], svc.get("restarts")
            old = (previous or {}).get(key)
            busy = bool(svc.get("restart") and svc["restart"].get("in_progress"))
            if state not in self.STABLE:
                continue  # activating/deactivating: ждём установившегося состояния
            current[key] = (state, restarts)
            if old is None or busy:
                continue
            fields = {"key": key, "unit": svc["unit"], "state": state}
            if old[0] != state:
                if state == "active":
                    self.emit("service_up", "Service %s is running (was %s)" % (svc["unit"], old[0]), **fields)
                elif state == "failed":
                    self.emit("service_failed", "Service %s failed (was %s)" % (svc["unit"], old[0]), **fields)
                elif old[0] == "active":
                    self.emit("service_down", "Service %s is %s" % (svc["unit"], state), **fields)
            if restarts is not None and old[1] is not None and restarts > old[1] and state == "active":
                self.emit("service_auto_restart", "Service %s was restarted by systemd (%d times since boot)" % (
                    svc["unit"], restarts), count=restarts - old[1], **fields)
        self.services = current

    def check_system(self, data):
        mem = data["system"].get("memory") or {}
        if mem.get("total"):
            pct = round((mem["total"] - mem.get("available", 0)) * 100.0 / mem["total"], 1)
            if not self.memory_high and pct >= MEM_ALERT_PERCENT:
                self.memory_high = True
                self.emit("memory_high", "Memory usage %.1f%%" % pct, percent=pct)
            elif self.memory_high and pct < MEM_ALERT_PERCENT - ALERT_CLEAR_MARGIN:
                self.memory_high = False
                self.emit("memory_ok", "Memory usage %.1f%%" % pct, percent=pct)
        for disk in disk_usage(self.disk_paths):
            path, pct = disk["path"], disk["percent"]
            if path not in self.disks_high and pct >= DISK_ALERT_PERCENT:
                self.disks_high.add(path)
                self.emit("disk_high", "Filesystem %s is %.1f%% full" % (path, pct), path=path, percent=pct)
            elif path in self.disks_high and pct < DISK_ALERT_PERCENT - ALERT_CLEAR_MARGIN:
                self.disks_high.discard(path)
                self.emit("disk_ok", "Filesystem %s is %.1f%% full" % (path, pct), path=path, percent=pct)

    def check_logs(self):
        """Новые записи с ошибками в логах компонентов: одно событие на файл за проход."""
        for item in self.app.log_files:
            path = resolve_log_path(item["path"])
            if not path or not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                offset = self.log_offsets.get(path)
                if offset is None:
                    # при запуске старые записи не отправляем; новый файл (ротация vms) — с начала
                    offset = size if not self.logs_baselined else 0
                if size < offset:
                    offset = 0  # файл усечён или пересоздан
                scan = scan_log_levels(path, offset, max_bytes=LOG_SCAN_MAX, keep=1, end=size)
            except (OSError, IOError):
                continue
            self.log_offsets[path] = scan["next_offset"]
            if scan["errors"]:
                last = scan["last_errors"][-1]["message"] if scan["last_errors"] else ""
                self.emit("log_errors", "%s: %d new error record(s). Last: %s" % (item["title_en"], scan["errors"], last),
                          key=item["key"], file=path, count=scan["errors"])
        self.logs_baselined = True

    def tick(self):
        data = self.app.collector.get()
        self.check_services(data)
        self.check_system(data)
        now = self.clock()
        if self.last_log_scan is None or now - self.last_log_scan >= self.log_scan_interval:
            self.last_log_scan = now
            self.check_logs()

    def run(self, stop, interval=MONITOR_INTERVAL):
        while True:
            try:
                self.tick()
            except Exception as exc:
                log("state monitor failed: %s", exc)
            if stop.wait(interval):
                return


# ---------------------------------------------------------------------------
# Приложение и HTTP
# ---------------------------------------------------------------------------

def normalize_log_files(items):
    result = []
    seen = set()
    for item in items or []:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        key = str(item.get("key") or "").strip().lower()
        if not KEY_RE.match(key) or key in seen:
            continue
        seen.add(key)
        result.append({
            "key": key,
            "path": item["path"],
            "title_ru": str(item.get("title_ru") or item.get("title") or key),
            "title_en": str(item.get("title_en") or item.get("title") or key),
            "service": item.get("service"),
        })
    return result


class App(object):
    """Состояние приложения: доступно обработчику через self.server.app."""

    def __init__(self, services=None, log_files=None, collector=None, restarts=None,
                 auth=None, throttle=None, runner=None, log_dir=None, fail_delay=AUTH_FAIL_DELAY,
                 settings_path=None, siem=None):
        self.runner = runner or run_cmd
        # копии: имя службы СУБД уточняется автоматически (detect) и не должно менять SERVICES
        self.services = [dict(s) for s in (services if services is not None else SERVICES)]
        self.services_by_key = dict((s["key"], s) for s in self.services)
        self.log_files = normalize_log_files(LOG_FILES if log_files is None else log_files)
        self.log_files_by_key = dict((f["key"], f) for f in self.log_files)
        self.collector = collector or StatusCollector(self.services, runner=self.runner)
        self.restarts = restarts or RestartManager(runner=self.runner)
        self.collector.restarts = self.restarts
        self.auth = auth or RootAuthenticator()
        self.throttle = throttle or LoginThrottle()
        self.log_dir = log_dir or LOG_DIR
        self.fail_delay = fail_delay
        # True, если TLS не поднялся и сервис работает по HTTP: пароль root по открытому
        # каналу не принимается (кроме явного режима отладки --no-tls).
        self.insecure = False
        self.font = self._load_font()
        self.brand = self._load_branding()
        self.today_lock = threading.Lock()
        self.report_lock = threading.Lock()
        self.spawn = spawn_process                      # запуск tail -F / journalctl -f для Real-time
        self.live_slots = threading.BoundedSemaphore(LIVE_MAX_STREAMS)
        self.stopping = threading.Event()               # остановка сервиса: потоки Real-time закрываются
        self.settings_lock = threading.Lock()
        self.assets = build_assets()
        # события: перезапуски, вход, смена состояний -> журнал событий и SIEM
        self.events = EventBus()
        self.restarts.events = self.events
        self.settings_path = settings_path or SETTINGS_FILE
        self.siem = siem or SyslogSender(self.collector.fqdn)
        stored = load_settings(self.settings_path).get("siem") or {}
        config, error = normalize_siem(stored) if stored else (None, None)
        if config:
            self.siem.configure(config)
        elif stored:
            log("settings.json: SIEM settings ignored (%s)", error)
        self.events.subscribe(self.siem.submit)

    def _load_font(self):
        for ext, ctype in ((".ttf", "font/ttf"), (".otf", "font/otf"), (".woff2", "font/woff2")):
            found = find_asset(FONT_NAME + ext)
            if found:
                return load_static(found, ctype)
        return None

    def _load_branding(self):
        """Логотип в шапке и значок вкладки: встроенный (web/brand.png); его можно заменить
        файлами logo.svg|png, logo-dark.*, logo-light.*, favicon.* рядом со скриптом или в assets/."""
        brand = {}
        for name in ("logo", "logo-dark", "logo-light", "favicon"):
            for ext, ctype in ((".svg", "image/svg+xml"), (".png", "image/png")):
                found = find_asset(name + ext)
                if found:
                    brand[name] = load_static(found, ctype)
                    break
        builtin = builtin_brand()
        if not any(name in brand for name in ("logo", "logo-dark", "logo-light")):
            brand["logo"] = builtin
        brand.setdefault("favicon", builtin)
        return brand

    def logs_index(self):
        files = []
        for item in self.log_files:
            resolved = resolve_log_path(item["path"])
            meta = file_meta(resolved) if resolved else file_meta("")
            files.append(dict({"key": item["key"], "title_ru": item["title_ru"],
                               "title_en": item["title_en"], "path": item["path"],
                               "resolved": resolved, "service": item["service"]}, **meta))
        journals = [{"key": s["key"], "unit": s["unit"]} for s in self.services]
        return {"files": files, "journals": journals, "reports": list_reports(self.log_dir)}


ASSET_DIRS = (SCRIPT_DIR, os.path.join(SCRIPT_DIR, "assets"))


def find_asset(name, dirs=None):
    """Файл оформления рядом со скриптом или в assets/ (шрифт и логотипы не хранятся в git)."""
    for directory in dirs or ASSET_DIRS:
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            return path
    return None


def builtin_brand():
    data = base64.b64decode(BRAND_PNG_B64)
    return {"data": data, "type": "image/png", "etag": etag_for(data)}


def load_static(path, ctype):
    with open(path, "rb") as fh:
        data = fh.read()
    return {"data": data, "type": ctype, "etag": etag_for(data)}


def etag_for(data):
    return '"' + hashlib.sha256(data).hexdigest()[:20] + '"'


class MetricsServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address, handler, app):
        self.app = app
        self.heartbeat = time.monotonic()
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        HTTPServer.__init__(self, address, handler)

    def service_actions(self):
        self.heartbeat = time.monotonic()

    def process_request(self, request, client_address):
        if not self._slots.acquire(False):
            self.shutdown_request(request)
            return
        try:
            ThreadingMixIn.process_request(self, request, client_address)
        except Exception:  # pragma: no cover (не удалось создать поток)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            ThreadingMixIn.process_request_thread(self, request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, socket.timeout)):
            return  # сканеры, разорванные соединения, клиенты без доверия к сертификату
        log("request error from %s: %s", client_address[0], exc)


SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
     "form-action 'self'; frame-ancestors 'none'"),
)

ROUTE_RESTART = re.compile(r"^/api/services/([a-z0-9_-]+)/restart$")
ROUTE_LOG_FILE = re.compile(r"^/api/logs/file/([a-z0-9_-]+)$")
ROUTE_LOG_JOURNAL = re.compile(r"^/api/logs/journal/([a-z0-9_-]+)$")
ROUTE_LOG_LIVE = re.compile(r"^/api/logs/live/(file|journal)/([a-z0-9_-]+)$")


class MetricsHandler(BaseHTTPRequestHandler):
    server_version = "kvm-metrics"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT

    # -- инфраструктура ---------------------------------------------------------
    @property
    def app(self):
        return self.server.app

    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()  # с таймаутом сокета, в потоке обработчика

    def log_message(self, fmt, *args):
        pass

    def version_string(self):
        return self.server_version  # без версии Python в заголовке Server

    def client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def end_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        BaseHTTPRequestHandler.end_headers(self)

    def send_body(self, status, body, ctype, headers=None, head_only=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or []):
            self.send_header(name, value)
        self.end_headers()
        if not head_only and self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, obj, status=200, headers=None):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        hdrs = [("Cache-Control", "no-store")] + list(headers or [])
        self.send_body(status, body, "application/json; charset=utf-8", hdrs)

    def send_error_json(self, status, code, **extra):
        payload = {"ok": False, "error": code}
        payload.update(extra)
        self.send_json(payload, status)

    def send_static(self, data, ctype, etag, max_age=86400):
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_body(200, data, ctype, [("ETag", etag),
                                          ("Cache-Control", "public, max-age=%d" % max_age)])

    def parse_url(self):
        parts = urlsplit(self.path)
        return parts.path, parse_qs(parts.query, keep_blank_values=False)

    def dispatch(self, handler):
        try:
            handler()
        except (BrokenPipeError, ConnectionResetError, socket.timeout, ssl.SSLError):
            pass
        except Exception:
            log("unhandled error on %s %s:\n%s", self.command, self.path, traceback.format_exc())
            try:
                self.send_error_json(500, "internal_error")
            except Exception:  # pragma: no cover (клиент уже отключился)
                pass

    # -- методы ----------------------------------------------------------------
    def do_GET(self):
        self.dispatch(self.route_get)

    def do_HEAD(self):
        self.dispatch(self.route_get)

    def do_POST(self):
        self.dispatch(self.route_post)

    def method_not_allowed(self):
        self.send_body(405, b"Method Not Allowed", "text/plain; charset=utf-8", [("Allow", "GET, HEAD, POST")])

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = method_not_allowed

    def route_get(self):
        path, query = self.parse_url()
        static = self.app.assets
        if path in ("/", "/index.html"):
            return self.handle_index(query)
        if path == "/static/app.css":
            return self.send_static(static["css"], "text/css; charset=utf-8", static["css_etag"], 31536000)
        if path == "/static/app.js":
            return self.send_static(static["js"], "application/javascript; charset=utf-8",
                                    static["js_etag"], 31536000)
        if path == "/favicon.svg" or path == "/favicon.ico":
            return self.send_static(static["favicon"], "image/svg+xml", static["favicon_etag"])
        if path == "/font":
            font = self.app.font
            if not font:
                return self.send_body(404, b"Not Found", "text/plain; charset=utf-8")
            return self.send_static(font["data"], font["type"], font["etag"], 604800)
        if path == "/healthz":
            return self.send_json({"ok": True, "version": __version__})
        if path == "/api/status":
            data = dict(self.app.collector.get())
            data["auth"] = {"restart": "insecure" if self.app.insecure else self.app.auth.status()}
            siem = self.app.siem.status()
            data["siem"] = {"state": siem["state"], "enabled": siem["enabled"]}
            return self.send_json(data)
        if path == "/api/report-now":
            return self.handle_report_now()
        if path == "/api/siem":
            return self.send_json(self.siem_payload())
        if path == "/api/siem/events":
            return self.handle_siem_events(query)
        if path == "/api/logs":
            return self.send_json(self.app.logs_index())
        match = ROUTE_LOG_FILE.match(path)
        if match:
            return self.handle_log_file(match.group(1), query)
        match = ROUTE_LOG_JOURNAL.match(path)
        if match:
            return self.handle_journal(match.group(1), query)
        match = ROUTE_LOG_LIVE.match(path)
        if match:
            return self.handle_live(match.group(1), match.group(2), query)
        if path == "/api/reports":
            return self.send_json({"reports": list_reports(self.app.log_dir)})
        if path == "/log":
            return self.handle_report(query)
        if path == "/logs-archive":
            return self.handle_reports_archive(query)
        if path == "/logs-today":
            return self.handle_logs_day(date.today())
        if path == "/logs-day":
            day = parse_day(query.get("date", [""])[0])
            if day is None:
                return self.send_error_json(400, "bad_date")
            return self.handle_logs_day(day)
        if path.startswith("/brand/"):
            item = self.app.brand.get(path[len("/brand/"):])
            if not item:
                return self.send_body(404, b"Not Found", "text/plain; charset=utf-8")
            return self.send_static(item["data"], item["type"], item["etag"], 86400)
        if path.startswith("/api/"):
            return self.send_error_json(404, "not_found")
        return self.send_body(404, b"Not Found", "text/plain; charset=utf-8")

    def route_post(self):
        path, _ = self.parse_url()
        match = ROUTE_RESTART.match(path)
        if match:
            return self.handle_restart(match.group(1))
        if path == "/api/siem":
            return self.handle_siem_save()
        if path == "/api/siem/test":
            return self.handle_siem_test()
        return self.send_error_json(404, "not_found")

    # -- страницы ----------------------------------------------------------------
    def handle_index(self, query):
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        lang = pick(query.get("lang", [None])[0], cookies.get("kvm_lang"), ("ru", "en"), "ru")
        theme = pick(query.get("theme", [None])[0], cookies.get("kvm_theme"), ("dark", "light"), "dark")
        body = render_index(self.app.assets, lang, theme, self.app.collector.fqdn, self.app.brand)
        headers = [("Cache-Control", "no-cache, no-store, must-revalidate"), ("Pragma", "no-cache"),
                   ("Expires", "0")]
        for name, value, allowed in (("kvm_lang", query.get("lang", [None])[0], ("ru", "en")),
                                     ("kvm_theme", query.get("theme", [None])[0], ("dark", "light"))):
            if value in allowed:
                headers.append(("Set-Cookie", "%s=%s; Path=/; Max-Age=31536000; SameSite=Strict; Secure"
                                % (name, value)))
        self.send_body(200, body, "text/html; charset=utf-8", headers)

    # -- логи --------------------------------------------------------------------
    def handle_log_file(self, key, query):
        item = self.app.log_files_by_key.get(key)
        if item is None:
            return self.send_error_json(404, "unknown_log")
        count = clamp_int(query.get("lines", [TAIL_DEFAULT])[0], TAIL_DEFAULT, 1, TAIL_MAX)
        resolved = resolve_log_path(item["path"])
        if not resolved:
            return self.send_error_json(404, "file_not_found", path=item["path"])
        lines, code, status, command, message = read_log_tail(self.app.runner, resolved, count)
        if code:
            return self.send_error_json(status, code, path=resolved, command=command, message=message)
        meta = file_meta(resolved)
        self.send_json({"ok": True, "kind": "file", "key": key, "path": resolved, "command": command,
                        "lines": lines, "requested": count, "has_more": len(lines) >= count,
                        "size": meta["size"], "mtime": meta["mtime"], "time": now_iso()})

    def handle_journal(self, key, query):
        svc = self.app.services_by_key.get(key)
        if svc is None:
            return self.send_error_json(404, "unknown_service")
        count = clamp_int(query.get("lines", [TAIL_DEFAULT])[0], TAIL_DEFAULT, 1, TAIL_MAX)
        res = self.app.runner(["journalctl", "-u", svc["unit"], "-n", str(count), "--no-pager",
                               "-o", "short-iso", "-q"], timeout=15, c_locale=False)
        if res.rc != 0 and not res.out:
            return self.send_error_json(500, "journal_error", message=res.err.strip()[:300])
        lines = [strip_ansi(line)[:TAIL_MAX_LINE] for line in res.out.splitlines()
                 if not line.startswith("-- ")]
        self.send_json({"ok": True, "kind": "journal", "key": key, "path": "journalctl -u " + svc["unit"],
                        "command": "journalctl -u %s -n %d --no-pager" % (svc["unit"], count),
                        "lines": lines[-count:], "requested": count, "has_more": len(lines) >= count,
                        "time": now_iso()})

    def handle_live(self, kind, key, query):
        """Real-time: новые строки лога потоком Server-Sent Events, пока пользователь не нажмёт «Стоп»
        (браузер закрывает соединение — процесс tail/journalctl завершается)."""
        app = self.app
        count = clamp_int(query.get("lines", [TAIL_DEFAULT])[0], TAIL_DEFAULT, 0, TAIL_MAX)
        if kind == "file":
            item = app.log_files_by_key.get(key)
            if item is None:
                return self.send_error_json(404, "unknown_log")
            resolve = lambda: resolve_log_path(item["path"])  # noqa: E731
            path = resolve()
            if not path or not os.path.isfile(path):
                return self.send_error_json(404, "file_not_found", path=item["path"])

            def command_for(target, switched):
                return tail_command(target, TAIL_DEFAULT if switched else count, follow=True)
            source = path
        else:
            svc = app.services_by_key.get(key)
            if svc is None:
                return self.send_error_json(404, "unknown_service")
            resolve = None

            def command_for(target, switched):
                return ["journalctl", "-u", svc["unit"], "-n", str(count), "-f", "--no-pager", "-o", "short-iso", "-q"]
            source = "journalctl -u " + svc["unit"]
        if not app.live_slots.acquire(False):
            return self.send_error_json(429, "too_many_streams", limit=LIVE_MAX_STREAMS)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if self.command == "HEAD":
                return None

            def write(data):
                self.wfile.write(data)
                self.wfile.flush()
            write(sse_event("meta", {"kind": kind, "key": key, "path": source, "max_seconds": LIVE_MAX_SECONDS}))
            live_stream(write, app.spawn, command_for, resolve, stop=app.stopping, journal=kind == "journal",
                        conn=self.connection)
        finally:
            app.live_slots.release()

    def handle_report(self, query):
        name = query.get("file", [""])[0]
        path = report_path(name, self.app.log_dir)
        if not path:
            return self.send_body(404, b"Not Found", "text/plain; charset=utf-8")
        with open(path, "rb") as fh:
            data = fh.read()
        self.send_body(200, data, "application/json; charset=utf-8",
                       [("Content-Disposition", 'attachment; filename="%s"' % name),
                        ("Cache-Control", "no-store")])

    def handle_report_now(self):
        """Отчёт о состоянии на текущий момент — сразу скачивается, на диск не сохраняется."""
        now = datetime.now()
        with self.app.report_lock:  # подсчёт ошибок читает логи: не строим несколько отчётов сразу
            body = report_json_bytes(build_state_report(self.app, "on-demand", now))
        name = "%s%s.json" % (REPORT_PREFIX, now.strftime("%d_%m_%Y_%H%M%S"))
        self.send_body(200, body, "application/json; charset=utf-8",
                       [("Content-Disposition", 'attachment; filename="%s"' % name),
                        ("Cache-Control", "no-store")])

    def handle_reports_archive(self, query):
        names = []
        for raw in query.get("files", []):
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw.split(",")
            if isinstance(value, str):
                value = [value]
            if isinstance(value, list):
                names.extend(v for v in value if isinstance(v, str))
        names = list(dict.fromkeys(names))[:100]
        data, added = build_reports_zip(names, self.app.log_dir)
        if not added:
            return self.send_body(404, b"Not Found", "text/plain; charset=utf-8")
        archive = "kaspersky-vm-services-state-archive_%s.zip" % datetime.now().strftime("%d_%m_%Y")
        self.send_body(200, data, "application/zip",
                       [("Content-Disposition", 'attachment; filename="%s"' % archive),
                        ("Cache-Control", "no-store")])

    def handle_logs_day(self, day):
        """Архив логов компонентов за день (по одному архиву за раз — бережём диск и ЦП)."""
        now = datetime.now()
        with self.app.today_lock:
            tmp = tempfile.TemporaryFile()
            try:
                build_today_logs_zip(self.app.log_files, tmp, now=now, host=self.app.collector.fqdn, day=day)
                size = tmp.tell()
                tmp.seek(0)
                name = "kaspersky-vm-logs_%s_%s.zip" % (re.sub(r"[^A-Za-z0-9.-]", "_", self.app.collector.fqdn),
                                                         day.strftime("%d_%m_%Y"))
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(size))
                self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    while True:
                        chunk = tmp.read(256 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            finally:
                tmp.close()

    # -- перезапуск --------------------------------------------------------------
    def same_origin(self):
        if self.headers.get("X-Requested-With") != "kvm-metrics":
            return False
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            return urlsplit(origin).netloc.lower() == host.lower()
        return True

    def read_json_body(self):
        length = clamp_int(self.headers.get("Content-Length"), -1, -1, MAX_BODY + 1)
        if length < 0 or length > MAX_BODY:
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def authorize(self, body, action, target):
        """Общие проверки действий с паролем root: источник запроса, HTTPS, блокировка IP, пароль.
        True — можно выполнять; иначе ответ с ошибкой уже отправлен."""
        app = self.app
        client = self.client_ip()
        if not self.same_origin():
            log("AUDIT %s %s client=%s result=csrf_rejected", action, target, client)
            app.events.emit("csrf_rejected", "%s request from foreign origin rejected" % action,
                            client=client, action=action, outcome="failure")
            self.send_error_json(403, "csrf")
            return False
        if body is None:
            self.send_error_json(400, "bad_request")
            return False
        if app.insecure:
            self.send_error_json(403, "insecure_transport")
            return False
        retry = app.throttle.retry_after(client)
        if retry:
            self.send_error_json(429, "locked", retry_after=retry)
            return False
        status = app.auth.status()
        if status != "ok":
            self.send_error_json(503 if status == "unavailable" else 403,
                                 "auth_unavailable" if status == "unavailable" else "root_locked")
            return False
        password = body.get("password")
        if not isinstance(password, str) or not app.auth.verify(password):
            if app.fail_delay:
                time.sleep(app.fail_delay)
            left = app.throttle.fail(client)
            log("AUDIT %s %s client=%s result=bad_password attempts_left=%s", action, target, client, left)
            if left == 0:
                app.events.emit("auth_locked", "Client %s blocked for %d s after failed root password attempts" % (
                    client, app.throttle.lock_time), client=client, user="root", action=action, outcome="failure")
                self.send_error_json(429, "locked", retry_after=app.throttle.retry_after(client))
                return False
            app.events.emit("auth_failed", "Wrong root password (%s), attempts left: %d" % (action, left),
                            client=client, user="root", action=action, outcome="failure")
            self.send_error_json(401, "bad_password", attempts_left=left)
            return False
        app.throttle.success(client)
        return True

    def handle_restart(self, key):
        app = self.app
        client = self.client_ip()
        body = self.read_json_body()
        svc = app.services_by_key.get(key)
        if svc is None:
            return self.send_error_json(404, "unknown_service")
        if not self.authorize(body, "restart", "unit=" + svc["unit"]):
            return None
        if app.restarts.in_progress(key):
            return self.send_error_json(409, "in_progress")
        current = next((s for s in app.collector.get(force=True)["services"] if s["key"] == key), {})
        ok, code, message = app.restarts.start(svc, current.get("since_mono", 0), client)
        if not ok:
            return self.send_error_json(409 if code == "in_progress" else 500, code, message=message)
        app.collector.invalidate()
        self.send_json({"ok": True, "key": key, "unit": svc["unit"]}, 202)

    # -- SIEM --------------------------------------------------------------------
    def siem_payload(self):
        return {
            "ok": True,
            "config": self.app.siem.status(),
            "recommended": {"protocol": SIEM_RECOMMENDED_PROTOCOL, "port": SIEM_RECOMMENDED_PORT,
                            "standard_port": 514},
            "format": "syslog RFC 3164 + CEF:0, facility local0",
            "events": [{"name": name, "signature": v[0], "severity": v[1], "category": v[2], "title": v[3]}
                       for name, v in sorted(EVENT_TYPES.items(), key=lambda kv: kv[1][0])],
            "recent": list(reversed(self.app.events.recent(
                limit=SIEM_RECENT_SHOWN, raw=lambda e: format_syslog(e, self.app.siem.hostname)))),
            "total": self.app.events.count(),
        }

    def handle_siem_events(self, query):
        """Последние события строками syslog/CEF — для окна «Все события» (поиск, перенос, скачивание)."""
        count = clamp_int(query.get("lines", [TAIL_DEFAULT])[0], TAIL_DEFAULT, 1, TAIL_MAX)
        host = self.app.siem.hostname
        lines = [format_syslog(e, host) for e in self.app.events.raw_recent(count)]
        total = self.app.events.count()
        self.send_json({"ok": True, "kind": "siem", "lines": lines, "requested": count,
                        "total": total, "has_more": total > len(lines), "time": now_iso()})

    def handle_siem_save(self):
        app = self.app
        body = self.read_json_body()
        config, error = normalize_siem(body) if body is not None else (None, None)
        if body is not None and error and self.same_origin():
            return self.send_error_json(400, error)
        if not self.authorize(body, "siem_settings", "target=%s" % ((body or {}).get("host") or "-")):
            return None
        with app.settings_lock:
            settings = load_settings(app.settings_path)
            settings["siem"] = config
            try:
                save_settings(settings, app.settings_path)
            except (OSError, IOError) as exc:
                return self.send_error_json(500, "save_failed", message=str(exc)[:300])
            app.siem.configure(config)
        target = "%s:%s/%s" % (config["host"], config["port"], config["protocol"]) if config["host"] else "-"
        log("AUDIT siem_settings target=%s enabled=%s client=%s result=saved", target, config["enabled"],
            self.client_ip())
        app.events.emit("settings_changed", "SIEM forwarding %s: %s" % (
            "enabled" if config["enabled"] else "disabled", target),
            client=self.client_ip(), user="root", action="siem_settings", target=target, outcome="success")
        self.send_json(self.siem_payload())

    def handle_siem_test(self):
        body = self.read_json_body()
        config, error = normalize_siem(dict(body, enabled=True)) if body is not None else (None, None)
        if body is not None and error and self.same_origin():
            return self.send_error_json(400, error)
        if not self.authorize(body, "siem_test", "target=%s" % ((body or {}).get("host") or "-")):
            return None
        ok, message = send_test_event(config, self.app.collector.fqdn, self.app.events, self.client_ip())
        if not ok:
            return self.send_error_json(502, "send_failed", message=message, protocol=config["protocol"])
        self.send_json({"ok": True, "protocol": config["protocol"],
                        "target": "%s:%s" % (config["host"], config["port"])})


def parse_cookies(header):
    cookies = {}
    for part in (header or "").split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def pick(first, second, allowed, default):
    for value in (first, second):
        if value in allowed:
            return value
    return default


def html_escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#x27;"))


BRAND_MARK_DEFAULT = (
    '<span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" width="20" height="20">'
    '<path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linejoin="round"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>')


def brand_markup(brand):
    """Логотип в шапке: официальный (если положен рядом со скриптом) или нейтральный значок."""
    dark = "logo-dark" if "logo-dark" in brand else ("logo" if "logo" in brand else None)
    light = "logo-light" if "logo-light" in brand else ("logo" if "logo" in brand else None)
    if not dark and not light:
        return BRAND_MARK_DEFAULT
    parts = []
    if dark:
        parts.append('<img class="brand-logo brand-logo-dark" src="/brand/%s" alt="">' % dark)
    if light:
        parts.append('<img class="brand-logo brand-logo-light" src="/brand/%s" alt="">' % light)
    return "".join(parts)


def render_index(assets, lang, theme, host, brand=None):
    brand = brand or {}
    title = ("Kaspersky VM | Мониторинг" if lang == "ru" else "Kaspersky VM | Monitoring")
    html = (INDEX_HTML
            .replace("{{LANG}}", lang)
            .replace("{{THEME}}", theme)
            .replace("{{TITLE}}", html_escape(title))
            .replace("{{HOST}}", html_escape(host))
            .replace("{{VERSION}}", __version__)
            .replace("{{BRAND_MARK}}", brand_markup(brand))
            .replace("{{FAVICON}}", "/brand/favicon" if "favicon" in brand else "/favicon.svg")
            .replace("{{STATIC_FAVICON}}", "1" if "favicon" in brand else "0")
            .replace("{{CSS_V}}", assets["css_etag"].strip('"')[:10])
            .replace("{{JS_V}}", assets["js_etag"].strip('"')[:10]))
    return html.encode("utf-8")


def build_assets():
    css = APP_CSS.encode("utf-8")
    js = APP_JS.encode("utf-8")
    favicon = FAVICON_SVG.encode("utf-8")
    return {"css": css, "css_etag": etag_for(css), "js": js, "js_etag": etag_for(js),
            "favicon": favicon, "favicon_etag": etag_for(favicon)}


# ---------------------------------------------------------------------------
# Фоновые задачи
# ---------------------------------------------------------------------------

def background_loop(app, stop, context=None, interval=30):
    """Ежедневный отчёт в REPORT_HOUR:00 (с догоняющей записью) и продление сертификата."""
    last_date = None
    last_cert_check = time.monotonic()
    while not stop.wait(interval):
        now = datetime.now()
        try:
            if report_due(now, last_date, app.log_dir):
                with app.report_lock:
                    write_daily_report(app, app.log_dir, now)
                last_date = now.date()
        except Exception as exc:
            log("daily report failed: %s", exc)
        if context is not None and time.monotonic() - last_cert_check > 86400:
            last_cert_check = time.monotonic()
            try:
                if certificate_needs_renewal() and generate_certificate(app.collector.fqdn, force=True):
                    context.load_cert_chain(CERT_FILE, KEY_FILE)
                    log("certificate renewed and reloaded")
            except Exception as exc:
                log("certificate renewal failed: %s", exc)


def create_server(app, bind=BIND_ADDRESS, port=PORT, context=None):
    server = MetricsServer((bind, port), MetricsHandler, app)
    if context is not None:
        # Рукопожатие TLS выполняется в потоке обработчика, а не в accept():
        # медленный клиент больше не блокирует весь сервер.
        server.socket = context.wrap_socket(server.socket, server_side=True,
                                            do_handshake_on_connect=False)
    return server


def self_check(out=None, runner=None):
    """Проверка перед обновлением (install.sh): скрипт исполним на этом Python,
    встроенный интерфейс собирается, нужные модули и утилиты доступны.
    Не открывает порт и не трогает файлы. Возвращает код выхода."""
    out = out or sys.stdout
    problems, warnings = [], []
    try:
        build_assets()
        render_index(build_assets(), "ru", "dark", "check")
    except Exception as exc:
        problems.append("web assets: %s" % exc)
    if not hasattr(ssl, "SSLContext"):
        problems.append("python ssl module unavailable")
    if system_crypt("check", "$6$kvmcheck$") is None:
        warnings.append("crypt(3) unavailable: restart buttons will not accept the root password")
    for tool in ("systemctl", "ss", "openssl", "tail", "journalctl"):
        if not any(os.access(os.path.join(d, tool), os.X_OK)
                   for d in os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep) + ["/usr/sbin", "/sbin"]):
            warnings.append("command not found: " + tool)
    info = []
    runner = runner or run_cmd
    services = [dict(svc) for svc in SERVICES]
    for svc in services:
        if svc.get("detect"):
            svc["unit"] = detect_unit(runner, svc["detect"], svc["unit"])
    res = runner(["systemctl", "show"] + [svc["unit"] for svc in services] + ["--property=Id,LoadState,ActiveState"])
    blocks = parse_systemctl_show(res.out) if res.rc == 0 else []
    for svc, props in zip(services, blocks):
        state = service_state(props)
        info.append("unit %s: %s" % (svc["unit"], state))
        if state == "not-found":
            warnings.append("unit %s not found on this server" % svc["unit"])
    for item in normalize_log_files(LOG_FILES):
        resolved = resolve_log_path(item["path"])
        exists = bool(resolved) and os.path.isfile(resolved)
        info.append("log %s: %s (%s)" % (item["key"], resolved or item["path"], "ok" if exists else "not found"))
    for line in info:
        out.write("INFO " + line + "\n")
    for line in warnings:
        out.write("WARN " + line + "\n")
    for line in problems:
        out.write("FAIL " + line + "\n")
    if problems:
        return 1
    out.write("OK " + __version__ + "\n")
    return 0


def _sigterm(signum, frame):
    raise SystemExit(0)  # systemctl stop: штатно завершаем serve_forever (событие monitor_stopped)


def install_sigterm_handler():
    try:
        signal.signal(signal.SIGTERM, _sigterm)
        return True
    except ValueError:  # не главный поток (тесты)
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kaspersky VM Metrics")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--bind", default=BIND_ADDRESS)
    parser.add_argument("--no-tls", action="store_true", help="HTTP без TLS (для отладки)")
    parser.add_argument("--check", action="store_true", help="самопроверка перед обновлением и выход")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.check:
        return self_check()

    app = App()

    context = None
    if not args.no_tls:
        if generate_certificate(app.collector.fqdn) and os.path.exists(CERT_FILE):
            try:
                context = make_ssl_context()
            except (ssl.SSLError, OSError) as exc:
                log("TLS init failed: %s", exc)
    server = create_server(app, args.bind, args.port, context)
    stop = threading.Event()
    app.siem.start()
    threading.Thread(target=background_loop, args=(app, stop, context), daemon=True).start()
    threading.Thread(target=StateMonitor(app).run, args=(stop,), daemon=True).start()
    interval = watchdog_interval()
    if interval:
        threading.Thread(target=watchdog_loop, args=(server, stop, interval), daemon=True).start()

    scheme = "https" if context else "http"
    if context is None and not args.no_tls:
        app.insecure = True
        log("WARNING: Certificates not found. HTTP only; restart buttons are disabled")
    print("Kaspersky VM Metrics Server %s running on %s://%s:%d" % (
        __version__, scheme, app.collector.fqdn, args.port))
    sys.stdout.flush()
    install_sigterm_handler()
    app.events.emit("monitor_started", "Kaspersky VM Metrics %s started (%s://%s:%d)" % (
        __version__, scheme, app.collector.fqdn, args.port))
    sd_notify("READY=1")
    try:
        server.serve_forever(poll_interval=0.5)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        stop.set()
        app.stopping.set()
        sd_notify("STOPPING=1")
        app.events.emit("monitor_stopped", "Kaspersky VM Metrics %s stopped" % __version__)
        app.siem.stop()
        server.server_close()


# ---------------------------------------------------------------------------
# Веб-интерфейс (встроен в скрипт: установка остаётся «один файл + шрифт»)
# ---------------------------------------------------------------------------

# @@ASSETS-BEGIN@@ (сгенерировано tools/embed_assets.py из каталога web/, не редактировать вручную)

INDEX_HTML = r'''<!DOCTYPE html>
<html lang="{{LANG}}" data-theme="{{THEME}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="app-version" content="{{VERSION}}">
<title>{{TITLE}}</title>
<link rel="icon" href="{{FAVICON}}" id="favicon">
<meta name="static-favicon" content="{{STATIC_FAVICON}}">
<link rel="preload" href="/font" as="font" type="font/ttf" crossorigin>
<link rel="stylesheet" href="/static/app.css?v={{CSS_V}}">
<script src="/static/app.js?v={{JS_V}}" defer></script>
</head>
<body>
<a class="skip-link" href="#main" data-i18n="skip">Перейти к содержимому</a>

<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      {{BRAND_MARK}}
      <div class="brand-text">
        <div class="brand-title">Kaspersky Vulnerability Management</div>
        <div class="brand-sub" data-i18n="subtitle">Мониторинг компонентов решения</div>
      </div>
    </div>

    <div class="toolbar">
      <div class="refresh-ctl" role="group" data-i18n-aria="refresh_group">
        <label class="sr-only" for="interval" data-i18n="interval">Интервал обновления</label>
        <select id="interval" class="select select-sm">
          <option value="5">5 s</option>
          <option value="10">10 s</option>
          <option value="30">30 s</option>
          <option value="60">60 s</option>
          <option value="0" data-i18n="off">Выкл.</option>
        </select>
        <button type="button" class="btn btn-icon" id="btn-refresh" data-i18n-title="refresh_now" data-i18n-aria="refresh_now">
          <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
      </div>
      <div class="seg" role="group" aria-label="Language">
        <button type="button" class="seg-btn" data-lang="ru">RU</button>
        <button type="button" class="seg-btn" data-lang="en">EN</button>
      </div>
      <button type="button" class="btn btn-icon" id="btn-theme" data-i18n-title="theme" data-i18n-aria="theme">
        <svg class="i-sun" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        <svg class="i-moon" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>
      </button>
    </div>
  </div>
</header>

<div class="banner" id="banner" role="alert" hidden>
  <span id="banner-text"></span>
  <button type="button" class="btn btn-sm" id="banner-retry" data-i18n="retry">Повторить</button>
</div>

<main id="main" class="container" tabindex="-1">
  <section class="hero" aria-labelledby="overall-title">
    <div class="overall" id="overall" data-state="loading">
      <span class="overall-icon" aria-hidden="true"></span>
      <div class="overall-text">
        <h1 id="overall-title" class="overall-title" data-i18n="loading">Загрузка…</h1>
        <div class="overall-meta"><span id="host">{{HOST}}</span><span id="os-name">—</span></div>
        <div class="overall-time" id="server-time">—</div>
      </div>
    </div>
    <div class="kpis" id="kpis">
      <div class="kpi"><div class="kpi-label" data-i18n="kpi_services">Службы</div><div class="kpi-value" id="kpi-services">—</div><div class="kpi-sub" id="kpi-services-sub"></div></div>
      <div class="kpi"><div class="kpi-label" data-i18n="kpi_svc_mem">Память служб</div><div class="kpi-value" id="kpi-svc-mem">—</div><div class="kpi-sub" id="kpi-svc-mem-sub"></div></div>
      <div class="kpi"><div class="kpi-label" data-i18n="kpi_ram">ОЗУ</div><div class="kpi-value" id="kpi-ram">—</div><div class="kpi-sub" id="kpi-ram-sub"></div></div>
      <div class="kpi"><div class="kpi-label kpi-label-raw">vCPU</div><div class="kpi-value" id="kpi-cpu">—</div><div class="kpi-sub" id="kpi-cpu-sub"></div></div>
      <div class="kpi"><div class="kpi-label" data-i18n="kpi_uptime">Время работы сервера</div><div class="kpi-value" id="kpi-uptime">—</div><div class="kpi-sub" id="kpi-uptime-sub"></div></div>
    </div>
  </section>

  <section class="panel" aria-labelledby="mem-title">
    <div class="panel-head">
      <h2 id="mem-title" class="panel-title" data-i18n="memory">Оперативная память</h2>
      <span class="panel-note" id="mem-note"></span>
    </div>
    <div class="membar" id="membar" role="img">
      <span class="seg-anon" id="mem-anon"></span><span class="seg-cache" id="mem-cache"></span><span class="seg-free" id="mem-free"></span>
    </div>
    <ul class="legend">
      <li><span class="swatch swatch-anon"></span><span data-i18n="mem_processes">Процессы</span> <strong id="leg-anon">—</strong></li>
      <li><span class="swatch swatch-cache"></span><span data-i18n="mem_cached">Кэш</span> <strong id="leg-cache">—</strong></li>
      <li><span class="swatch swatch-free"></span><span data-i18n="mem_free">Свободно</span> <strong id="leg-free">—</strong></li>
    </ul>
  </section>

  <section aria-labelledby="svc-title">
    <div class="section-head">
      <h2 id="svc-title" class="section-title" data-i18n="services">Службы</h2>
      <div class="section-tools">
        <button type="button" class="btn btn-sm" id="btn-logs-today"><span data-i18n="logs_today">Скачать логи за сегодня</span></button>
        <button type="button" class="btn btn-sm" id="btn-logs-day"><span data-i18n="logs_day">Логи за другой день</span></button>
        <div class="seg seg-sm" role="group" data-i18n-aria="filter">
          <button type="button" class="seg-btn" data-filter="all"><span data-i18n="filter_all">Все</span> <span class="count" id="cnt-all">0</span></button>
          <button type="button" class="seg-btn" data-filter="problems"><span data-i18n="filter_problems">Требуют внимания</span> <span class="count" id="cnt-problems">0</span></button>
        </div>
      </div>
    </div>
    <div class="grid" id="services-grid" aria-live="polite" aria-busy="true">
      <div class="card skeleton"></div><div class="card skeleton"></div><div class="card skeleton"></div>
      <div class="card skeleton"></div><div class="card skeleton"></div><div class="card skeleton"></div>
    </div>
    <p class="empty" id="services-empty" hidden data-i18n="no_problems">Все службы работают штатно.</p>
  </section>

  <section class="panel" aria-labelledby="reports-title">
    <div class="panel-head">
      <div class="panel-heading">
        <h2 id="reports-title" class="panel-title" data-i18n="reports">Отчёты о состоянии</h2>
        <span class="panel-note" data-i18n="reports_note">JSON · ежедневно в 19:00 · хранятся 7 дней</span>
      </div>
      <div class="panel-actions">
        <button type="button" class="btn btn-sm btn-primary" id="btn-report-now"><span data-i18n="report_now">Сформировать отчёт сейчас</span></button>
        <button type="button" class="btn btn-sm" id="btn-reports-all" data-i18n="select_all">Выбрать все</button>
        <button type="button" class="btn btn-sm" id="btn-reports-dl" disabled data-i18n="download">Скачать</button>
      </div>
    </div>
    <div id="reports-list" class="rows"></div>
  </section>

  <section class="panel" id="siem-panel" aria-labelledby="siem-title">
    <div class="panel-head">
      <div class="panel-heading">
        <h2 id="siem-title" class="panel-title" data-i18n="siem">Отправка событий в SIEM</h2>
        <span class="pill pill-sm" id="siem-pill" hidden></span>
        <span class="panel-note">syslog · CEF</span>
      </div>
      <div class="panel-actions">
        <button type="button" class="btn btn-sm" id="btn-siem"><span data-i18n="siem_configure">Настроить</span></button>
      </div>
    </div>
    <div id="siem-body"></div>
  </section>

  <section class="panel collapsed" id="ports-panel" aria-labelledby="ports-title">
    <div class="panel-head">
      <button type="button" class="disclosure" id="ports-toggle" aria-expanded="false" aria-controls="ports-body">
        <svg class="chev" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="m9 6 6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <h2 id="ports-title" class="panel-title" data-i18n="ports">Статус соединений</h2>
        <span class="count" id="ports-count">0</span>
      </button>
    </div>
    <div id="ports-body" hidden>
      <div class="table-tools">
        <label class="sr-only" for="ports-filter" data-i18n="search">Поиск</label>
        <input type="search" id="ports-filter" class="input" autocomplete="off" data-i18n-placeholder="ports_filter">
        <label class="check"><input type="checkbox" id="ports-kvm"> <span data-i18n="ports_kvm_only">Только службы Kaspersky VM</span></label>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th aria-sort="none"><button type="button" class="th-sort" data-sort="netid"><span data-i18n="col_proto">Протокол</span><span class="sort-ind" aria-hidden="true"></span></button></th>
            <th aria-sort="none"><button type="button" class="th-sort" data-sort="state"><span data-i18n="col_state">Состояние</span><span class="sort-ind" aria-hidden="true"></span></button></th>
            <th aria-sort="none"><button type="button" class="th-sort" data-sort="local"><span data-i18n="col_local">Локальный адрес</span><span class="sort-ind" aria-hidden="true"></span></button></th>
            <th aria-sort="none"><button type="button" class="th-sort" data-sort="process"><span data-i18n="col_process">Процесс</span><span class="sort-ind" aria-hidden="true"></span></button></th>
            <th aria-sort="none"><button type="button" class="th-sort" data-sort="service"><span data-i18n="col_service">Служба</span><span class="sort-ind" aria-hidden="true"></span></button></th>
          </tr></thead>
          <tbody id="ports-tbody"></tbody>
        </table>
      </div>
    </div>
  </section>
</main>

<footer class="footer">Designed by Kaspersky Presales Russia Team · v{{VERSION}}</footer>

<div id="modal-root"></div>
<div class="toasts" id="toasts" role="status" aria-live="polite"></div>
<noscript><div class="banner">JavaScript is required.</div></noscript>
</body>
</html>
'''

APP_CSS = r'''@font-face {
  font-family: "KasperskySans";
  src: url("/font") format("truetype");
  font-display: swap;
}

:root {
  --font: "KasperskySans", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", "DejaVu Sans Mono", monospace;
  --accent: #00a88e;
  --accent-strong: #00c2a4;
  --radius: 12px;
  --radius-sm: 8px;
  --ease: cubic-bezier(.2, .7, .2, 1);
  --mem-anon: #e5534b;
  --mem-cache: #f0a020;
}

[data-theme="dark"] {
  color-scheme: dark;
  --bg: #1d1d1b;
  --surface: #262624;
  --surface-2: #2f2f2c;
  --surface-3: #383834;
  --border: #3a3a36;
  --border-strong: #4a4a45;
  --text: #ecece9;
  --text-2: #b0b0aa;
  --muted: #85857f;
  --accent-text: #2fd1b5;
  --accent-weak: rgba(0, 168, 142, .16);
  --ok: #2fd1b5;
  --ok-weak: rgba(0, 168, 142, .16);
  --bad: #ff6b74;
  --bad-solid: #ed2939;
  --bad-weak: rgba(237, 41, 57, .16);
  --warn: #f5b942;
  --warn-weak: rgba(245, 185, 66, .16);
  --idle: #9a9a94;
  --idle-weak: rgba(154, 154, 148, .16);
  --mem-free: #55554f;
  --shadow: 0 1px 2px rgba(0, 0, 0, .3), 0 4px 16px rgba(0, 0, 0, .18);
  --overlay: rgba(10, 10, 9, .62);
  --code-bg: #171715;
}

[data-theme="light"] {
  color-scheme: light;
  --bg: #efedee;
  --surface: #ffffff;
  --surface-2: #f6f5f5;
  --surface-3: #ecebeb;
  --border: #e2e0e1;
  --border-strong: #cfcdce;
  --text: #1d1d1b;
  --text-2: #55554f;
  --muted: #7d7d77;
  --accent-text: #00745f;
  --accent-weak: rgba(0, 168, 142, .12);
  --ok: #00806b;
  --ok-weak: rgba(0, 168, 142, .12);
  --bad: #c8102e;
  --bad-solid: #ed2939;
  --bad-weak: rgba(237, 41, 57, .1);
  --warn: #9a6200;
  --warn-weak: rgba(240, 160, 32, .16);
  --idle: #6f6f69;
  --idle-weak: rgba(111, 111, 105, .12);
  --mem-free: #cdcad1;
  --shadow: 0 1px 2px rgba(0, 0, 0, .05), 0 4px 14px rgba(0, 0, 0, .05);
  --overlay: rgba(29, 29, 27, .45);
  --code-bg: #fafafa;
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: 14px;
  line-height: 1.45;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}
h1, h2, h3, p { margin: 0; }
button, input, select { font: inherit; color: inherit; }
[hidden] { display: none !important; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
.skip-link { position: absolute; left: 12px; top: -48px; z-index: 100; background: var(--accent); color: #fff; padding: 8px 14px; border-radius: var(--radius-sm); text-decoration: none; }
.skip-link:focus { top: 12px; }
:focus-visible { outline: 2px solid var(--accent-strong); outline-offset: 2px; }
.mono { font-family: var(--mono); }
.tnum { font-variant-numeric: tabular-nums; }

/* ---------- top bar ---------- */

.topbar {
  position: sticky; top: 0; z-index: 50;
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  -webkit-backdrop-filter: saturate(140%) blur(10px);
  backdrop-filter: saturate(140%) blur(10px);
  border-bottom: 1px solid var(--border);
}
@supports not (background: color-mix(in srgb, red 50%, blue)) { .topbar { background: var(--surface); } }
.topbar-inner { max-width: 1500px; margin: 0 auto; padding: 10px 24px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
.brand-mark { width: 34px; height: 34px; border-radius: 9px; background: var(--accent); color: #fff; display: grid; place-items: center; flex-shrink: 0; }
.brand-logo { display: block; height: 36px; width: auto; max-width: 220px; flex-shrink: 0; border-radius: 9px; }
[data-theme="dark"] .brand-logo-light, [data-theme="light"] .brand-logo-dark { display: none; }
.brand-text { min-width: 0; }
.brand-title { font-weight: 700; font-size: 15px; letter-spacing: .1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.brand-sub { font-size: 12px; color: var(--muted); }
.toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.refresh-ctl { display: flex; align-items: center; gap: 6px; }

/* ---------- controls ---------- */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  height: 32px; padding: 0 12px;
  border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
  background: var(--surface); color: var(--text);
  font-size: 13px; font-weight: 600; white-space: nowrap; cursor: pointer;
  transition: background .15s var(--ease), border-color .15s var(--ease), color .15s var(--ease), transform .1s;
}
.btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent-text); }
.btn:active:not(:disabled) { transform: translateY(1px); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn-sm { height: 28px; padding: 0 10px; font-size: 12px; }
.btn-icon { width: 32px; padding: 0; }
.btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; }
.btn-danger { background: var(--bad-solid); border-color: var(--bad-solid); color: #fff; }
.btn-danger:hover:not(:disabled) { background: #ff3b4a; border-color: #ff3b4a; color: #fff; }
.btn-ghost { background: transparent; border-color: transparent; color: var(--text-2); }
.btn-ghost:hover:not(:disabled) { background: var(--surface-2); border-color: transparent; }
.btn .spinner { width: 14px; height: 14px; }
.btn svg { flex-shrink: 0; }
.btn.paused { color: var(--warn); border-color: var(--warn); }
#btn-refresh.spinning svg { animation: spin .8s linear infinite; }
[data-theme="dark"] .i-sun, [data-theme="light"] .i-moon { display: none; }

.seg { display: inline-flex; padding: 2px; background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius-sm); }
.seg-btn { border: 0; background: transparent; color: var(--text-2); height: 26px; padding: 0 10px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; }
.seg-btn:hover { color: var(--text); }
.seg-btn[aria-pressed="true"] { background: var(--surface); color: var(--accent-text); box-shadow: 0 1px 2px rgba(0, 0, 0, .15); }
.seg-sm .seg-btn { height: 24px; }

.select, .input {
  height: 32px; padding: 0 10px; border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong); background: var(--surface); color: var(--text);
  font-size: 13px;
}
.select-sm { height: 32px; padding: 0 6px; font-size: 12px; }
.input { min-width: 0; }
.input:focus, .select:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 3px var(--accent-weak); }
.check { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-2); cursor: pointer; user-select: none; }
.check input { accent-color: var(--accent); width: 16px; height: 16px; margin: 0; }
.count { display: inline-block; min-width: 20px; padding: 0 6px; height: 18px; line-height: 18px; border-radius: 9px; background: var(--surface-3); color: var(--text-2); font-size: 11px; font-weight: 700; text-align: center; }

/* ---------- layout ---------- */
.container { max-width: 1500px; margin: 0 auto; padding: 20px 24px 8px; display: flex; flex-direction: column; gap: 18px; outline: none; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; box-shadow: var(--shadow); }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.panel.collapsed .panel-head { margin-bottom: 0; }
.panel-title, .section-title { font-size: 13px; font-weight: 700; color: var(--text-2); text-transform: uppercase; letter-spacing: .6px; }
.panel-note { font-size: 12px; color: var(--muted); }
.panel-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
.empty { color: var(--muted); font-size: 13px; padding: 14px 0; text-align: center; }

.banner { max-width: 1500px; margin: 12px auto 0; padding: 10px 16px; display: flex; align-items: center; justify-content: space-between; gap: 12px; background: var(--bad-weak); color: var(--bad); border: 1px solid var(--bad); border-radius: var(--radius-sm); font-weight: 600; width: calc(100% - 48px); }

/* ---------- hero ---------- */
.hero { display: grid; grid-template-columns: minmax(280px, 1.1fr) 3fr; gap: 14px; }
.overall { display: flex; align-items: center; gap: 14px; padding: 18px 20px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); box-shadow: var(--shadow); position: relative; overflow: hidden; }
.overall::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--idle); }
.overall[data-state="ok"]::before { background: var(--accent); }
.overall[data-state="bad"]::before { background: var(--bad-solid); }
.overall[data-state="warn"]::before { background: var(--warn); }
.overall-icon { width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0; display: grid; place-items: center; background: var(--idle-weak); position: relative; }
.overall-icon::after { content: ""; width: 14px; height: 14px; border-radius: 50%; background: var(--idle); }
.overall[data-state="ok"] .overall-icon { background: var(--ok-weak); }
.overall[data-state="ok"] .overall-icon::after { background: var(--accent); box-shadow: 0 0 0 0 rgba(0, 168, 142, .5); animation: pulse 2.4s var(--ease) infinite; }
.overall[data-state="bad"] .overall-icon { background: var(--bad-weak); }
.overall[data-state="bad"] .overall-icon::after { background: var(--bad-solid); }
.overall[data-state="warn"] .overall-icon { background: var(--warn-weak); }
.overall[data-state="warn"] .overall-icon::after { background: var(--warn); }
.overall-text { min-width: 0; }
.overall-title { font-size: 18px; font-weight: 700; line-height: 1.25; }
.overall-meta { margin-top: 4px; font-size: 12px; color: var(--muted); display: flex; flex-wrap: wrap; align-items: center; gap: 2px 8px; }
.overall-meta span { white-space: nowrap; }
.overall-meta span + span::before { content: "·"; margin-right: 8px; opacity: .7; }
.overall-time { margin-top: 2px; font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }

.kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; box-shadow: var(--shadow); min-width: 0; }
.kpi-label-raw { text-transform: none !important; }
.kpi-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; overflow-wrap: anywhere; }
.kpi-value { font-size: 22px; font-weight: 700; margin-top: 4px; white-space: nowrap; font-variant-numeric: tabular-nums; }
.kpi-value.bad { color: var(--bad); }
.kpi-sub { font-size: 12px; color: var(--text-2); margin-top: 2px; min-height: 17px; overflow-wrap: anywhere; }

/* ---------- memory ---------- */
.membar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--mem-free); }
.membar span { display: block; height: 100%; width: 0; transition: width .6s var(--ease); }
.seg-anon, .swatch-anon { background: var(--mem-anon); }
.seg-cache, .swatch-cache { background: var(--mem-cache); }
.seg-free, .swatch-free { background: var(--mem-free); }
.legend { list-style: none; margin: 10px 0 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px 20px; font-size: 13px; color: var(--text-2); }
.legend li { display: inline-flex; align-items: center; gap: 6px; }
.legend strong { color: var(--text); font-variant-numeric: tabular-nums; }
.swatch { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
[data-theme="light"] .swatch-free { box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .12); }

/* ---------- service cards ---------- */
.grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }  /* 6 служб = 3 + 3 */
.card {
  position: relative; overflow: hidden;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 14px 14px 12px 18px; box-shadow: var(--shadow);
  display: flex; flex-direction: column; gap: 10px; min-width: 0;
  transition: border-color .2s var(--ease), box-shadow .2s var(--ease);
}
.card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--idle); transition: background .2s; }
.card[data-tone="ok"]::before { background: var(--accent); }
.card[data-tone="bad"]::before { background: var(--bad-solid); }
.card[data-tone="warn"]::before { background: var(--warn); }
.card[data-tone="bad"] { border-color: color-mix(in srgb, var(--bad-solid) 45%, var(--border)); }
.card:hover { box-shadow: 0 2px 4px rgba(0, 0, 0, .12), 0 8px 24px rgba(0, 0, 0, .12); }
.card.skeleton { min-height: 200px; background: linear-gradient(90deg, var(--surface) 0%, var(--surface-2) 50%, var(--surface) 100%); background-size: 200% 100%; animation: shimmer 1.4s linear infinite; }
.card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; flex: 1; }
.card-title { min-width: 0; }
.unit { font-family: var(--mono); font-size: 13px; font-weight: 600; overflow-wrap: anywhere; }
.desc { margin-top: 4px; font-size: 12px; color: var(--text-2); line-height: 1.4; }

.pill { display: inline-flex; align-items: center; gap: 6px; height: 24px; padding: 0 10px; border-radius: 12px; font-size: 12px; font-weight: 700; white-space: nowrap; flex-shrink: 0; background: var(--idle-weak); color: var(--idle); }
.pill::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.pill[data-tone="ok"] { background: var(--ok-weak); color: var(--ok); }
.pill[data-tone="bad"] { background: var(--bad-weak); color: var(--bad); }
.pill[data-tone="warn"] { background: var(--warn-weak); color: var(--warn); }
.pill[data-busy="true"]::before { width: 10px; height: 10px; background: none; border: 2px solid currentColor; border-right-color: transparent; animation: spin .8s linear infinite; }

.metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; padding: 10px 0; border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.metric { min-width: 0; }
.metric-label { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; overflow-wrap: anywhere; }
.metric-value { font-size: 15px; font-weight: 700; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.metric-value.na { color: var(--muted); font-weight: 400; }
.card-links { display: flex; flex-wrap: wrap; gap: 0; margin: -4px 0 0 -6px; }
.card-links .btn-link { padding: 0 5px; gap: 4px; font-size: 11.5px; }
@media (max-width: 1420px) and (min-width: 1101px) { .card-links .btn-link svg { display: none; } }
.btn-link { background: transparent; border-color: transparent; color: var(--accent-text); height: 26px; padding: 0 8px; }
.btn-link:hover:not(:disabled) { background: var(--accent-weak); border-color: transparent; }
.btn-copy { color: var(--text-2); }
.card-actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: auto; }
.card-actions .btn { flex: 1 1 auto; justify-content: center; }
.card-actions .spacer { flex: 1; }
.card-progress { position: absolute; inset: 0 0 auto 0; height: 3px; overflow: hidden; }
.card-progress::after { content: ""; position: absolute; top: 0; bottom: 0; width: 35%; background: var(--warn); animation: indeterminate 1.2s var(--ease) infinite; }

/* ---------- rows (logs, reports) ---------- */
.rows { display: flex; flex-direction: column; }
.row { display: flex; align-items: center; gap: 14px; padding: 10px 4px; border-top: 1px solid var(--border); min-width: 0; }
.row:first-child { border-top: 0; }
.row-main { flex: 1; min-width: 0; }
.row-title { font-weight: 600; font-size: 13px; }
.row-path { font-family: var(--mono); font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.row-meta { font-size: 12px; color: var(--text-2); white-space: nowrap; font-variant-numeric: tabular-nums; }
.row-meta.bad { color: var(--bad); }
.row .check { flex: 1; min-width: 0; }
.hint { font-size: 13px; color: var(--text-2); background: var(--surface-2); border: 1px dashed var(--border-strong); border-radius: var(--radius-sm); padding: 12px 14px; }
.hint code { font-family: var(--mono); font-size: 12px; background: var(--surface-3); padding: 1px 5px; border-radius: 4px; }

/* ---------- table ---------- */
.disclosure { display: inline-flex; align-items: center; gap: 8px; border: 0; background: none; padding: 4px 6px 4px 0; cursor: pointer; border-radius: 6px; }
.disclosure .chev { transition: transform .2s var(--ease); color: var(--muted); }
.disclosure[aria-expanded="true"] .chev { transform: rotate(90deg); }
.table-tools { display: flex; gap: 12px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
.table-tools .input { width: 320px; max-width: 100%; }
.table-wrap { max-height: 460px; overflow: auto; border: 1px solid var(--border); border-radius: var(--radius-sm); }
.table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.th-sort { all: unset; display: inline-flex; align-items: center; gap: 6px; cursor: pointer; text-transform: inherit; letter-spacing: inherit; font: inherit; color: inherit; border-radius: 4px; }
.th-sort:hover { color: var(--text); }
.th-sort:focus-visible { outline: 2px solid var(--accent-strong); outline-offset: 2px; }
.sort-ind { width: 0; height: 0; border-left: 4px solid transparent; border-right: 4px solid transparent; opacity: .35; border-top: 5px solid currentColor; }
th[aria-sort="ascending"] .sort-ind { opacity: 1; border-top: 0; border-bottom: 5px solid var(--accent-text); }
th[aria-sort="descending"] .sort-ind { opacity: 1; border-top: 5px solid var(--accent-text); }
th[aria-sort="ascending"], th[aria-sort="descending"] { color: var(--text); }
.table th { position: sticky; top: 0; background: var(--surface-2); color: var(--muted); text-transform: uppercase; font-size: 10.5px; letter-spacing: .5px; text-align: left; font-weight: 700; padding: 9px 12px; border-bottom: 1px solid var(--border); z-index: 1; }
.table td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }
.table tr:last-child td { border-bottom: 0; }
.table tbody tr:hover td { background: var(--surface-2); }
.table td.mono { font-size: 12px; }
.table tr.kvm td:first-child { box-shadow: inset 3px 0 0 var(--accent); }
.tag { display: inline-block; padding: 1px 8px; border-radius: 10px; background: var(--accent-weak); color: var(--accent-text); font-size: 11px; font-weight: 700; white-space: nowrap; }

/* ---------- modal ---------- */
.modal-backdrop { position: fixed; inset: 0; z-index: 80; background: var(--overlay); display: flex; align-items: center; justify-content: center; padding: 20px; animation: fade .15s var(--ease); }
.modal { width: 100%; max-width: 480px; max-height: calc(100vh - 40px); display: flex; flex-direction: column; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; box-shadow: 0 24px 64px rgba(0, 0, 0, .35); animation: pop .18s var(--ease); }
.modal-lg { max-width: 1200px; height: calc(100vh - 40px); }
.modal-md { max-width: 640px; }
.modal > form { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.modal-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 18px 20px 12px; }
.modal-title { font-size: 16px; font-weight: 700; }
.modal-sub { font-size: 12px; color: var(--muted); margin-top: 2px; font-family: var(--mono); overflow-wrap: anywhere; }
.modal-content { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.modal-body { padding: 4px 20px 16px; overflow: auto; flex: 1; min-height: 0; }
.modal-foot { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 20px 18px; border-top: 1px solid var(--border); flex-wrap: wrap; }
.modal-foot .spacer { flex: 1; }
.field { display: flex; flex-direction: column; gap: 6px; margin-top: 14px; }
.field label { font-size: 12px; font-weight: 600; color: var(--text-2); }
.field .input { height: 38px; width: 100%; }
.pw-wrap { position: relative; }
.pw-wrap .input { padding-right: 42px; }
.pw-wrap .btn { position: absolute; right: 3px; top: 3px; height: 32px; width: 34px; padding: 0; }
.field-error { color: var(--bad); font-size: 12.5px; font-weight: 600; min-height: 18px; }
.callout { display: flex; gap: 10px; padding: 10px 12px; border-radius: var(--radius-sm); background: var(--warn-weak); color: var(--text); font-size: 13px; margin-top: 12px; }
.callout::before { content: "!"; flex-shrink: 0; width: 18px; height: 18px; border-radius: 50%; background: var(--warn); color: #1d1d1b; font-weight: 800; font-size: 12px; display: grid; place-items: center; }
.confirm-text { color: var(--text-2); }
.confirm-text b { color: var(--text); font-family: var(--mono); font-weight: 600; white-space: nowrap; }

/* ---------- log viewer ---------- */
.log-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 0 20px 12px; }
.log-tools .input { width: 260px; max-width: 100%; height: 30px; }
.log-tools .select { height: 30px; }
.log-tools .spacer { flex: 1; }
.log-meta { font-size: 12px; color: var(--muted); }
.log-wrap { position: relative; flex: 1; min-height: 0; display: flex; flex-direction: column; }
.live-jump { position: absolute; right: 36px; bottom: 14px; box-shadow: var(--shadow); }
.live-status { display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 12px; border-radius: 15px; font-size: 12.5px; font-weight: 700; background: var(--idle-weak); color: var(--idle); }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.live-status[data-state="running"] { background: var(--bad-weak); color: var(--bad); }
.live-status[data-state="running"] .live-dot { animation: blink 1.2s ease-in-out infinite; }
.live-status[data-state="connecting"], .live-status[data-state="reconnecting"] { background: var(--warn-weak); color: var(--warn); }
.btn-danger-soft { color: var(--bad); border-color: color-mix(in srgb, var(--bad-solid) 45%, var(--border)); }
.btn-danger-soft:hover:not(:disabled) { background: var(--bad-weak); }
.live-notice { font-size: 12.5px; color: var(--warn); font-weight: 600; }
.log-lines li.live-sep { color: var(--accent-text); font-style: italic; padding: 4px 12px 4px 64px; }
.log-lines li.live-sep::before { display: none; }
.row-actions { display: flex; gap: 8px; flex-shrink: 0; }
.log-view { margin: 0 20px; flex: 1; min-height: 0; overflow: auto; background: var(--code-bg); border: 1px solid var(--border); border-radius: var(--radius-sm); font-family: var(--mono); font-size: 12px; line-height: 1.55; }
.log-lines { list-style: none; margin: 0; padding: 8px 0; }
.log-lines { min-width: 100%; width: max-content; }
.log-lines li { display: flex; padding: 0 12px 0 0; white-space: pre; }
.log-lines li::before { content: attr(data-n); flex-shrink: 0; width: 52px; padding-right: 12px; text-align: right; color: var(--muted); user-select: none; position: sticky; left: 0; background: var(--code-bg); }
.log-lines li:hover { background: var(--surface-2); }
.log-lines li.lv-error { color: var(--bad); background: var(--bad-weak); box-shadow: inset 3px 0 0 var(--bad-solid); font-weight: 600; }
.log-lines li.lv-error::before { background: color-mix(in srgb, var(--bad-solid) 14%, var(--code-bg)); }
.log-lines li.lv-warn { color: var(--warn); }
.log-lines li.lv-debug { color: var(--muted); }
.log-lines li.hidden { display: none; }
/* «Перенос строк»: длинные строки переносятся по ширине окна, номер строки остаётся слева */
.log-view.wrap .log-lines { width: auto; min-width: 0; }
.log-view.wrap .log-lines li { display: block; position: relative; padding-left: 64px; white-space: pre-wrap; overflow-wrap: anywhere; }
.log-view.wrap .log-lines li::before { position: absolute; left: 0; top: 0; bottom: 0; }
.log-view.wrap .log-lines li.hidden { display: none; }
.log-lines mark { background: rgba(245, 185, 66, .45); color: inherit; border-radius: 2px; }
.log-empty { padding: 32px; text-align: center; color: var(--muted); font-family: var(--font); }
.log-view .spinner { margin: 40px auto; display: block; }

/* ---------- toasts ---------- */
.toasts { position: fixed; right: 20px; bottom: 20px; z-index: 90; display: flex; flex-direction: column; gap: 8px; align-items: flex-end; pointer-events: none; }
.toast { pointer-events: auto; display: flex; align-items: flex-start; gap: 10px; min-width: 260px; max-width: 420px; padding: 12px 14px; border-radius: 10px; background: var(--surface); color: var(--text); border: 1px solid var(--border); box-shadow: 0 12px 32px rgba(0, 0, 0, .28); font-size: 13px; animation: slide-in .2s var(--ease); }
.toast::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); margin-top: 6px; flex-shrink: 0; }
.toast[data-tone="bad"]::before { background: var(--bad-solid); }
.toast[data-tone="warn"]::before { background: var(--warn); }
.toast.out { opacity: 0; transform: translateY(6px); transition: all .2s; }
.toast-body { flex: 1; }
.toast-title { font-weight: 700; }
.toast-text { color: var(--text-2); margin-top: 2px; word-break: break-word; }
.toast-close { border: 0; background: none; color: var(--muted); cursor: pointer; padding: 0 2px; font-size: 16px; line-height: 1; }

.spinner { width: 20px; height: 20px; border-radius: 50%; border: 2px solid var(--border-strong); border-top-color: var(--accent); animation: spin .8s linear infinite; display: inline-block; }
.footer { text-align: center; color: var(--muted); font-size: 11px; padding: 18px 24px 28px; opacity: .8; }

@keyframes spin { to { transform: rotate(360deg); } }
@keyframes shimmer { to { background-position: -200% 0; } }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(0, 168, 142, .45); } 70% { box-shadow: 0 0 0 10px rgba(0, 168, 142, 0); } 100% { box-shadow: 0 0 0 0 rgba(0, 168, 142, 0); } }
@keyframes indeterminate { 0% { left: -35%; } 100% { left: 100%; } }
@keyframes fade { from { opacity: 0; } }
@keyframes pop { from { opacity: 0; transform: translateY(8px) scale(.98); } }
@keyframes slide-in { from { opacity: 0; transform: translateY(8px); } }

/* ---- отчёты и SIEM ---- */
.panel-heading { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; min-width: 0; }
.pill-sm { height: 22px; font-size: 11.5px; padding: 0 9px; }
.pill[data-tone="idle"] { background: var(--idle-weak); color: var(--idle); }
.chip { display: inline-flex; align-items: center; height: 20px; padding: 0 7px; border-radius: 5px; font-size: 10.5px; font-weight: 700; letter-spacing: .4px; background: var(--accent-weak); color: var(--accent-text); flex-shrink: 0; }
.chip-muted { background: var(--surface-3); color: var(--muted); }
.siem-target { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 13.5px; }
.siem-target .mono { font-weight: 600; }
.subhead { margin: 16px 0 6px; font-size: 11px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; color: var(--muted); }
.events { list-style: none; margin: 0; padding: 0; }
.events > li { border-top: 1px solid var(--border); }
.event > summary { display: flex; align-items: baseline; gap: 10px; padding: 7px 4px; font-size: 13px; min-width: 0; cursor: pointer; list-style: none; border-radius: 6px; }
.event > summary::-webkit-details-marker { display: none; }
.event > summary::before { content: ""; flex-shrink: 0; width: 6px; height: 6px; margin: 0 2px 2px; border-right: 2px solid var(--muted); border-bottom: 2px solid var(--muted); transform: rotate(-45deg); transition: transform .15s var(--ease); align-self: center; }
.event[open] > summary::before { transform: rotate(45deg); }
.event > summary:hover { background: var(--surface-2); }
.event-time { flex-shrink: 0; color: var(--muted); font-size: 12px; }
.event-msg { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.events.wrap .event-msg { white-space: normal; overflow-wrap: anywhere; }
.event-st { flex-shrink: 0; font-size: 11.5px; font-weight: 600; color: var(--idle); white-space: nowrap; }
.event-st[data-st="sent"] { color: var(--ok); }
.event-st[data-st="queued"] { color: var(--warn); }
.event-st[data-st="dropped"] { color: var(--bad); }
.event-body { padding: 2px 4px 14px 30px; }
.event-meta { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; font-size: 12.5px; color: var(--text-2); }
.event-label { margin-top: 6px; font-size: 11px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; color: var(--muted); }
.event-raw { margin: 6px 0 0; padding: 10px 12px; background: var(--code-bg); border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 12px; line-height: 1.5; white-space: pre; overflow-x: auto; }
.events.wrap .event-raw { white-space: pre-wrap; overflow-wrap: anywhere; }
.events-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 16px 0 6px; }
.events-head .spacer { flex: 1; }
.events-head .subhead { margin: 0; }
#reports-list .empty, #siem-body .empty { text-align: left; }
.section-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.sev { display: inline-grid; place-items: center; min-width: 22px; height: 20px; padding: 0 5px; border-radius: 5px; font-size: 11px; font-weight: 800; background: var(--ok-weak); color: var(--ok); flex-shrink: 0; }
.sev[data-tone="warn"] { background: var(--warn-weak); color: var(--warn); }
.sev[data-tone="bad"] { background: var(--bad-weak); color: var(--bad); }
.callout-bad { background: var(--bad-weak); }
.callout-bad::before { background: var(--bad-solid); color: #fff; }
.callout-accent { flex-direction: column; gap: 4px; margin-top: 0; padding-left: 14px; background: var(--accent-weak); box-shadow: inset 3px 0 0 var(--accent); }
.callout-accent::before { display: none; }
.callout-title { font-weight: 700; color: var(--accent-text); }
.check-strong { margin-top: 14px; color: var(--text); font-weight: 600; }
.field-row { display: flex; gap: 12px; align-items: flex-end; }
.field-row .field { margin-top: 14px; }
.field-grow { flex: 1; min-width: 0; }
.input-port { width: 120px !important; }
.field .label { font-size: 12px; font-weight: 600; color: var(--text-2); }
.field-hint { font-weight: 500; color: var(--muted); }
.field-hint .btn-link { height: auto; padding: 0; font-size: 12px; font-weight: 700; color: var(--accent-text); }
.seg-proto { align-self: flex-start; }
.seg-proto .seg-btn { height: 30px; padding: 0 14px; font-size: 13px; }
.reco-badge { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; padding: 2px 6px; border-radius: 4px; background: #00806c; color: #ffffff; }  /* белый текст: контраст 4,9:1 */
.details { margin-top: 14px; font-size: 13px; }
.details summary { cursor: pointer; color: var(--text-2); font-weight: 600; }
.details .table-wrap { margin-top: 8px; max-height: 240px; overflow: auto; border: 1px solid var(--border); border-radius: var(--radius-sm); }
.table-compact td { padding: 5px 10px; word-break: normal; }

@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .25; } }

@media (min-width: 2200px) {
  .topbar-inner, .container, .banner { max-width: 1840px; }
}
/* 4K без масштабирования в ОС (3840×2160 при 100 %): интерфейс крупнее, а не «мелкий островок» */
@media (min-width: 3200px) {
  body { zoom: 1.5; }
}
@media (max-width: 1360px) {  /* 1280×720, 1280×1024: обе кнопки карточки в одну строку */
  .grid { gap: 12px; }
  .card-actions .btn { padding: 0 8px; gap: 5px; }
}
@media (max-width: 1100px) {
  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 1280px) {
  .hero { grid-template-columns: 1fr; }
}
@media (max-width: 900px) {
  .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .topbar-inner, .container { padding-left: 16px; padding-right: 16px; }
  .banner { width: calc(100% - 32px); }
}
@media (max-width: 520px) {
  .grid { grid-template-columns: 1fr; }
  .brand-title { font-size: 13px; }
  .row { flex-wrap: wrap; gap: 6px 12px; }
  .row-main, .row .check { flex-basis: 100%; }
  .row .check .mono { overflow-wrap: anywhere; font-size: 12px; }
  .field-row { flex-direction: column; align-items: stretch; gap: 0; }
  .input-port { width: 100% !important; }
  .event > summary { flex-wrap: wrap; }
  .event-msg { flex-basis: 100%; white-space: normal; }
  .event-body { padding-left: 4px; }
  .overall-meta span + span::before { display: none; }
  .overall-meta { flex-direction: column; align-items: flex-start; }
  .modal-backdrop { padding: 0; }
  .modal, .modal-lg, .modal-md { max-width: none; height: 100%; max-height: none; border-radius: 0; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }
}
@media print {
  .topbar, .toolbar, .card-actions, .card-links, .toasts { display: none !important; }
  body { background: #fff; color: #000; }
}
'''

APP_JS = r'''/* Kaspersky VM Metrics — web UI. Без внешних зависимостей; работает под строгим CSP. */
(function () {
  'use strict';

  // ------------------------------------------------------------------ i18n
  var I18N = {
    ru: {
      skip: 'Перейти к содержимому',
      subtitle: 'Мониторинг компонентов решения',
      title: 'Kaspersky VM | Мониторинг',
      updated_to: 'Сервис обновлён до версии {v}. Перезагрузка страницы…',
      loading: 'Загрузка…',
      interval: 'Интервал обновления',
      off: 'Выкл.',
      refresh_group: 'Обновление данных',
      refresh_now: 'Обновить сейчас (R)',
      theme: 'Сменить тему',
      retry: 'Повторить',
      conn_lost: 'Нет связи с сервером мониторинга. Показаны данные на {time}.',
      conn_lost_first: 'Не удалось получить данные от сервера мониторинга.',
      all_up: 'Все службы работают',
      some_down: 'Требуют внимания: {n} из {total}',
      restarting_now: 'Выполняется перезапуск: {units}',
      kpi_services: 'Службы',
      kpi_svc_mem: 'Потребляемая память',
      kpi_ram: 'ОЗУ',
      kpi_uptime: 'Время работы сервера',
      running_of: 'запущены',
      of_total: 'из {total}',
      used_of: 'используется из {total}',
      since: 'с {date}',
      cpu_load: 'загрузка процессора: {v}%',
      of_ram: '{v}% от объёма ОЗУ',
      memory: 'Оперативная память',
      mem_note: '{used} используется из {total} ({pct}%)',
      mem_processes: 'Процессы',
      mem_cached: 'Кэш',
      mem_free: 'Не используется',
      services: 'Службы',
      filter: 'Фильтр служб',
      filter_all: 'Все',
      filter_problems: 'Требуют внимания',
      no_problems: 'Все службы работают штатно.',
      st_active: 'Работает',
      st_activating: 'Запускается',
      st_deactivating: 'Останавливается',
      st_reloading: 'Перезагрузка',
      st_inactive: 'Остановлена',
      st_failed: 'Сбой',
      'st_not-found': 'Не установлена',
      st_masked: 'Заблокирована',
      st_unknown: 'Неизвестно',
      st_restarting: 'Перезапуск… {s}',
      m_memory: 'Память',
      m_pid: 'PID',
      m_uptime: 'Время работы',
      m_rss: 'оценка по RSS',
      btn_restart: 'Перезапустить',
      btn_start: 'Запустить',
      btn_journal: 'Журнал службы',
      btn_copy_cmd: 'Скопировать команду перезапуска',
      btn_copy_short: 'Копировать команду перезапуска',
      copy_cmd_hint: 'Скопировать в буфер обмена команду для терминала: {cmd}',
      copied: 'Скопировано в буфер обмена',
      copy_failed: 'Не удалось скопировать',
      restart_title: 'Перезапуск службы',
      start_title: 'Запуск службы',
      restart_confirm: 'Служба {unit} будет перезапущена. На время перезапуска её функции будут недоступны.',
      start_confirm: 'Будет выполнен запуск службы {unit}.',
      root_password: 'Пароль root',
      show_password: 'Показать пароль',
      hide_password: 'Скрыть пароль',
      cancel: 'Отмена',
      close: 'Закрыть',
      err_bad_password: 'Неверный пароль. Осталось попыток: {n}.',
      err_locked: 'Слишком много неудачных попыток. Повторите через {t}.',
      err_root_locked: 'Для root не задан пароль или учётная запись заблокирована. Задайте пароль командой passwd root.',
      err_auth_unavailable: 'Сервис не может проверить пароль root (нет доступа к /etc/shadow).',
      err_insecure_transport: 'Сервис работает без HTTPS: передача пароля root по открытому каналу запрещена. Проверьте сертификат в каталоге сервиса.',
      err_in_progress: 'Перезапуск этой службы уже выполняется.',
      err_systemctl_failed: 'systemctl вернул ошибку: {msg}',
      err_csrf: 'Запрос отклонён: недопустимый источник.',
      err_network: 'Сервер недоступен. Проверьте соединение.',
      err_generic: 'Ошибка: {code}',
      err_empty_password: 'Введите пароль root.',
      restart_queued: 'Перезапуск запущен',
      restart_queued_text: '{unit} — страница обновится автоматически.',
      restart_ok: 'Служба перезапущена',
      restart_failed: 'Служба не запустилась',
      restart_failed_text: '{unit}: проверьте журнал службы.',
      restart_timeout: 'Перезапуск не завершился вовремя',
      logs_day: 'Логи за другой день',
      logs_day_title: 'Логи компонентов за день',
      logs_day_label: 'День',
      logs_day_hint: 'В архив попадут записи за выбранный день из лог-файлов компонентов, в том числе из ротированных копий, если они сохранились на сервере.',
      logs_day_download: 'Скачать архив',
      logs_day_bad: 'Выберите день не позже сегодняшнего.',
      logs_note: 'Просмотр последних строк',
      logs_today: 'Скачать логи за сегодня',
      logs_today_started: 'Архив формируется — загрузка начнётся автоматически',
      log_missing: 'Файл не найден',
      log_unreadable: 'Нет прав на чтение',
      btn_log: 'Лог компонента',
      btn_log_title: 'Последние 50 строк лог-файла',
      btn_live: 'Real-time лога компонента',
      btn_live_journal: 'Real-time журнала службы',
      btn_live_title: 'Новые строки в режиме реального времени',
      live_sub: 'Real-time · новые строки появляются сразу',
      live_connecting: 'Подключение…',
      live_running: 'Real-time',
      live_stopped: 'Остановлено',
      live_reconnecting: 'Переподключение…',
      live_stop: 'Стоп',
      live_resume: 'Продолжить',
      live_clear: 'Очистить',
      live_waiting: 'Ожидание новых строк…',
      live_jump: 'К новым строкам',
      live_meta: 'получено строк: {n} · с {time}',
      live_switch: 'Новый файл лога: {path}',
      live_end_time_limit: 'Просмотр остановлен через час. Нажмите «Продолжить», чтобы возобновить.',
      live_end_exited: 'Команда чтения лога завершилась.',
      live_end_server_stopping: 'Сервис мониторинга перезапускается — нажмите «Продолжить» через несколько секунд.',
      live_connect_failed: 'Не удалось подключиться: {msg}',
      err_too_many_streams: 'Открыто слишком много окон Real-time (не больше {n}). Закройте лишние.',
      lv_err_file_not_found: 'Файл не найден на сервере',
      lv_err_permission_denied: 'Нет прав на чтение файла (сервис запущен не от root, а sudo без пароля не настроен)',
      lv_err_timeout: 'Команда не завершилась за 10 секунд',
      lv_err_read_error: 'Ошибка чтения',
      reports: 'Отчёты о состоянии',
      reports_note: 'JSON · ежедневно в 19:00 · хранятся 7 дней',
      reports_empty: 'Ежедневных отчётов пока нет: отчёт формируется в 19:00. Чтобы сформировать отчёт на текущий момент, нажмите кнопку «Сформировать отчёт сейчас».',
      report_now: 'Сформировать отчёт сейчас',
      report_now_started: 'Отчёт формируется — загрузка начнётся автоматически',
      siem: 'Отправка событий в SIEM',
      siem_configure: 'Настроить',
      siem_st_off: 'Выключено',
      siem_st_ok: 'Работает',
      siem_st_error: 'Ошибка отправки',
      siem_st_waiting: 'Ожидает событий',
      siem_off_text: 'Укажите адрес и порт SIEM-системы — сервис будет отправлять события в формате CEF по syslog: остановки и сбои служб, перезапуски, неверный пароль root, ошибки в логах компонентов, нехватка памяти и места на диске.',
      siem_stats: 'отправлено: {sent} · ошибок: {failed} · в очереди: {queued}',
      siem_last_error: 'Последняя ошибка ({time}): {msg}',
      siem_recent: 'Отправляемые события',
      siem_raw: 'Строка, которая отправляется в SIEM (syslog + CEF):',
      siem_all: 'Все события ({n})',
      siem_all_title: 'Отправляемые события',
      siem_ev_sent: 'отправлено',
      siem_ev_queued: 'в очереди',
      siem_ev_dropped: 'не отправлено',
      siem_ev_none: 'SIEM выключена',
      siem_recent_empty: 'Событий пока нет.',
      siem_sub: 'syslog (RFC 3164) · CEF:0 · facility local0',
      siem_reco: 'Рекомендуется: TCP, порт {port}',
      siem_reco_text: 'TCP подтверждает доставку и не обрезает длинные события; пока SIEM недоступна, события копятся в очереди.',
      siem_host: 'Адрес SIEM-системы',
      siem_host_ph: 'IP-адрес или имя, например 10.0.0.15',
      siem_port: 'Порт',
      siem_proto: 'Протокол',
      recommended: 'рекомендуется',
      siem_udp_warn: 'UDP не подтверждает доставку, события длиннее 2048 байт обрезаются. Выбирайте, только если коллектор не принимает TCP.',
      siem_enabled: 'Отправлять события в SIEM',
      siem_events_list: 'Какие события отправляются ({n})',
      col_sig: 'ID',
      col_sev: 'Важность',
      col_event: 'Событие',
      siem_save: 'Сохранить',
      siem_test: 'Отправить тестовое событие',
      siem_saved: 'Настройки SIEM сохранены',
      siem_saved_off: 'Отправка событий в SIEM выключена',
      siem_test_ok: 'Тестовое событие отправлено',
      siem_test_ok_text: '{target} ({proto}) — проверьте его в SIEM.',
      siem_test_udp: 'Для UDP доставка не подтверждается.',
      err_send_failed: 'Не удалось отправить событие: {msg}',
      err_host_required: 'Укажите адрес SIEM-системы.',
      err_bad_host: 'Недопустимый адрес SIEM-системы.',
      err_bad_port: 'Порт — число от 1 до 65535.',
      err_bad_protocol: 'Недопустимый протокол.',
      err_save_failed: 'Не удалось сохранить настройки: {msg}',
      select_all: 'Выбрать все',
      select_none: 'Снять выбор',
      download: 'Скачать',
      download_n: 'Скачать ({n})',
      ports: 'Статус соединений',
      ports_note: 'ss -tulnp',
      ports_filter: 'Поиск по порту, адресу, процессу',
      ports_kvm_only: 'Только службы Kaspersky VM',
      ports_empty: 'Нет данных',
      search: 'Поиск',
      col_proto: 'Протокол',
      col_state: 'Состояние',
      col_local: 'Локальный адрес',
      col_process: 'Процесс',
      col_service: 'Служба',
      lv_lines: 'Строк',
      lv_events: 'Событий',
      lv_filter_siem: 'Поиск по событиям',
      lv_filter: 'Поиск по файлу',
      lv_wrap: 'Перенос строк',
      lv_wrap_title: 'Переносить длинные строки по ширине окна',
      lv_refresh: 'Обновить',
      lv_copy: 'Копировать',
      lv_download: 'Скачать .log',
      lv_meta: '{n} строк · {size} · изменён {mtime} · получен {time}',
      lv_meta_journal: '{n} строк · получен {time}',
      lv_meta_siem: 'событий: {n} из {total} · обновлено {time}',
      lv_empty: 'Журнал пуст',
      lv_no_match: 'Нет строк, содержащих «{q}»',
      lv_matches: 'совпадений: {n}',
      lv_error: 'Не удалось получить лог: {msg}',
      journal_of: 'Журнал systemd',
      u_d: 'д', u_h: 'ч', u_m: 'м', u_s: 'с',
      b_B: 'Б', b_KB: 'КБ', b_MB: 'МБ', b_GB: 'ГБ', b_TB: 'ТБ',
      na: '—'
    },
    en: {
      skip: 'Skip to content',
      subtitle: 'Monitoring of solution components',
      title: 'Kaspersky VM | Monitoring',
      updated_to: 'Service updated to version {v}. Reloading the page…',
      loading: 'Loading…',
      interval: 'Refresh interval',
      off: 'Off',
      refresh_group: 'Data refresh',
      refresh_now: 'Refresh now (R)',
      theme: 'Toggle theme',
      retry: 'Retry',
      conn_lost: 'Monitoring server is unreachable. Showing data as of {time}.',
      conn_lost_first: 'Could not get data from the monitoring server.',
      all_up: 'All services running',
      some_down: 'Need attention: {n} of {total}',
      restarting_now: 'Restart in progress: {units}',
      kpi_services: 'Services',
      kpi_svc_mem: 'Memory consumption',
      kpi_ram: 'RAM',
      kpi_uptime: 'Server uptime',
      running_of: 'running',
      of_total: 'of {total}',
      used_of: 'used of {total}',
      since: 'since {date}',
      cpu_load: 'CPU load: {v}%',
      of_ram: '{v}% of total RAM',
      memory: 'Memory',
      mem_note: '{used} used of {total} ({pct}%)',
      mem_processes: 'Processes',
      mem_cached: 'Cached',
      mem_free: 'Not used',
      services: 'Services',
      filter: 'Service filter',
      filter_all: 'All',
      filter_problems: 'Need attention',
      no_problems: 'All services are running normally.',
      st_active: 'Running',
      st_activating: 'Starting',
      st_deactivating: 'Stopping',
      st_reloading: 'Reloading',
      st_inactive: 'Stopped',
      st_failed: 'Failed',
      'st_not-found': 'Not installed',
      st_masked: 'Masked',
      st_unknown: 'Unknown',
      st_restarting: 'Restarting… {s}',
      m_memory: 'Memory',
      m_pid: 'PID',
      m_uptime: 'Uptime',
      m_rss: 'RSS estimate',
      btn_restart: 'Restart',
      btn_start: 'Start',
      btn_journal: 'Service journal',
      btn_copy_cmd: 'Copy restart command',
      btn_copy_short: 'Copy restart command',
      copy_cmd_hint: 'Copy the terminal command to the clipboard: {cmd}',
      copied: 'Copied to clipboard',
      copy_failed: 'Copy failed',
      restart_title: 'Restart service',
      start_title: 'Start service',
      restart_confirm: 'Service {unit} will be restarted. Its functions will be unavailable during the restart.',
      start_confirm: 'Service {unit} will be started.',
      root_password: 'Root password',
      show_password: 'Show password',
      hide_password: 'Hide password',
      cancel: 'Cancel',
      close: 'Close',
      err_bad_password: 'Wrong password. Attempts left: {n}.',
      err_locked: 'Too many failed attempts. Try again in {t}.',
      err_root_locked: 'Root has no password or the account is locked. Set it with passwd root.',
      err_auth_unavailable: 'The service cannot verify the root password (no access to /etc/shadow).',
      err_insecure_transport: 'The service runs without HTTPS: sending the root password over plain HTTP is not allowed. Check the certificate in the service directory.',
      err_in_progress: 'A restart of this service is already in progress.',
      err_systemctl_failed: 'systemctl returned an error: {msg}',
      err_csrf: 'Request rejected: invalid origin.',
      err_network: 'Server is unreachable. Check the connection.',
      err_generic: 'Error: {code}',
      err_empty_password: 'Enter the root password.',
      restart_queued: 'Restart started',
      restart_queued_text: '{unit} — the page will refresh automatically.',
      restart_ok: 'Service restarted',
      restart_failed: 'Service failed to start',
      restart_failed_text: '{unit}: check the service journal.',
      restart_timeout: 'Restart did not finish in time',
      logs_day: 'Logs for another day',
      logs_day_title: 'Component logs for a day',
      logs_day_label: 'Day',
      logs_day_hint: 'The archive contains the entries for the selected day from the component log files, including rotated copies if they are still on the server.',
      logs_day_download: 'Download archive',
      logs_day_bad: 'Choose a day no later than today.',
      logs_note: 'View the latest lines',
      logs_today: 'Download today\'s logs',
      logs_today_started: 'The archive is being prepared — the download will start automatically',
      log_missing: 'File not found',
      log_unreadable: 'No read permission',
      btn_log: 'Component log',
      btn_log_title: 'Last 50 lines of the log file',
      btn_live: 'Real-time component log',
      btn_live_journal: 'Real-time service journal',
      btn_live_title: 'New lines in real time',
      live_sub: 'Real-time · new lines appear immediately',
      live_connecting: 'Connecting…',
      live_running: 'Real-time',
      live_stopped: 'Stopped',
      live_reconnecting: 'Reconnecting…',
      live_stop: 'Stop',
      live_resume: 'Resume',
      live_clear: 'Clear',
      live_waiting: 'Waiting for new lines…',
      live_jump: 'Jump to new lines',
      live_meta: 'lines received: {n} · since {time}',
      live_switch: 'New log file: {path}',
      live_end_time_limit: 'Viewing stopped after one hour. Click “Resume” to continue.',
      live_end_exited: 'The log reader exited.',
      live_end_server_stopping: 'The monitoring service is restarting — click “Resume” in a few seconds.',
      live_connect_failed: 'Could not connect: {msg}',
      err_too_many_streams: 'Too many Real-time windows are open (at most {n}). Close some of them.',
      lv_err_file_not_found: 'File not found on the server',
      lv_err_permission_denied: 'No permission to read the file (service is not running as root and passwordless sudo is not configured)',
      lv_err_timeout: 'The command did not finish within 10 seconds',
      lv_err_read_error: 'Read error',
      reports: 'State reports',
      reports_note: 'JSON · daily at 19:00 · kept for 7 days',
      reports_empty: 'No daily reports yet: a report is created at 19:00. To create a report as of now, click “Create report now”.',
      report_now: 'Create report now',
      report_now_started: 'The report is being prepared — the download will start automatically',
      siem: 'SIEM event forwarding',
      siem_configure: 'Configure',
      siem_st_off: 'Off',
      siem_st_ok: 'Working',
      siem_st_error: 'Delivery error',
      siem_st_waiting: 'Waiting for events',
      siem_off_text: 'Enter the SIEM address and port and the service will send CEF events over syslog: service stops and failures, restarts, wrong root password, errors in component logs, low memory and disk space.',
      siem_stats: 'sent: {sent} · errors: {failed} · queued: {queued}',
      siem_last_error: 'Last error ({time}): {msg}',
      siem_recent: 'Forwarded events',
      siem_raw: 'Line sent to the SIEM (syslog + CEF):',
      siem_all: 'All events ({n})',
      siem_all_title: 'Forwarded events',
      siem_ev_sent: 'sent',
      siem_ev_queued: 'queued',
      siem_ev_dropped: 'not sent',
      siem_ev_none: 'SIEM off',
      siem_recent_empty: 'No events yet.',
      siem_sub: 'syslog (RFC 3164) · CEF:0 · facility local0',
      siem_reco: 'Recommended: TCP, port {port}',
      siem_reco_text: 'TCP confirms delivery and does not truncate long events; while the SIEM is unreachable, events are queued.',
      siem_host: 'SIEM address',
      siem_host_ph: 'IP address or host name, e.g. 10.0.0.15',
      siem_port: 'Port',
      siem_proto: 'Protocol',
      recommended: 'recommended',
      siem_udp_warn: 'UDP does not confirm delivery; events longer than 2048 bytes are truncated. Use it only if the collector does not accept TCP.',
      siem_enabled: 'Send events to the SIEM',
      siem_events_list: 'Events that are sent ({n})',
      col_sig: 'ID',
      col_sev: 'Severity',
      col_event: 'Event',
      siem_save: 'Save',
      siem_test: 'Send test event',
      siem_saved: 'SIEM settings saved',
      siem_saved_off: 'SIEM event forwarding is off',
      siem_test_ok: 'Test event sent',
      siem_test_ok_text: '{target} ({proto}) — check it in the SIEM.',
      siem_test_udp: 'UDP delivery is not confirmed.',
      err_send_failed: 'Could not send the event: {msg}',
      err_host_required: 'Enter the SIEM address.',
      err_bad_host: 'Invalid SIEM address.',
      err_bad_port: 'Port must be a number from 1 to 65535.',
      err_bad_protocol: 'Invalid protocol.',
      err_save_failed: 'Could not save the settings: {msg}',
      select_all: 'Select all',
      select_none: 'Clear selection',
      download: 'Download',
      download_n: 'Download ({n})',
      ports: 'Connection Status',
      ports_note: 'ss -tulnp',
      ports_filter: 'Search by port, address, process',
      ports_kvm_only: 'Kaspersky VM services only',
      ports_empty: 'No data',
      search: 'Search',
      col_proto: 'Proto',
      col_state: 'State',
      col_local: 'Local address',
      col_process: 'Process',
      col_service: 'Service',
      lv_lines: 'Lines',
      lv_events: 'Events',
      lv_filter_siem: 'Search events',
      lv_filter: 'Search in file',
      lv_wrap: 'Wrap lines',
      lv_wrap_title: 'Wrap long lines to the window width',
      lv_refresh: 'Refresh',
      lv_copy: 'Copy',
      lv_download: 'Download .log',
      lv_meta: '{n} lines · {size} · modified {mtime} · received {time}',
      lv_meta_journal: '{n} lines · received {time}',
      lv_meta_siem: 'events: {n} of {total} · updated {time}',
      lv_empty: 'Log is empty',
      lv_no_match: 'No lines contain “{q}”',
      lv_matches: 'matches: {n}',
      lv_error: 'Could not fetch the log: {msg}',
      journal_of: 'systemd journal',
      u_d: 'd', u_h: 'h', u_m: 'm', u_s: 's',
      b_B: 'B', b_KB: 'KB', b_MB: 'MB', b_GB: 'GB', b_TB: 'TB',
      na: '—'
    }
  };

  var STATES = {
    active: { tone: 'ok' },
    activating: { tone: 'warn', busy: true },
    deactivating: { tone: 'warn', busy: true },
    reloading: { tone: 'warn', busy: true },
    inactive: { tone: 'bad' },
    failed: { tone: 'bad' },
    'not-found': { tone: 'idle' },
    masked: { tone: 'idle' },
    unknown: { tone: 'idle' }
  };

  var LOG_LEVELS = [
    ['error', /\b(ERROR|ERR|FATAL|CRIT|CRITICAL|EMERG|ALERT|SEVERE|PANIC|Traceback|Exception)\b/i],
    ['warn', /\b(WARN|WARNING)\b/i],
    ['debug', /\b(DEBUG|TRACE|VERBOSE)\b/i]
  ];

  // ------------------------------------------------------------------ state
  var root = document.documentElement;
  var state = {
    lang: root.getAttribute('lang') === 'en' ? 'en' : 'ru',
    theme: root.getAttribute('data-theme') === 'light' ? 'light' : 'dark',
    data: null,
    logs: null,
    filter: 'all',
    interval: 10,
    timer: null,
    inflight: false,
    lastOk: 0,
    failures: 0,
    pending: {},
    cards: {},
    portsOpen: false,
    portsKvm: false,
    portsQuery: '',
    portsSort: { key: null, dir: 'asc' },
    selectedReports: {},
    siem: null,
    siemSig: '',
    siemViewer: null,
    siemOpen: {}
  };

  function $(id) { return document.getElementById(id); }

  function store(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem('kvm.' + key);
      window.localStorage.setItem('kvm.' + key, String(value));
    } catch (e) { /* приватный режим, запрет хранилища */ }
    return null;
  }

  function setCookie(name, value) {
    var secure = location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = name + '=' + value + '; Path=/; Max-Age=31536000; SameSite=Strict' + secure;
  }

  function t(key, vars) {
    var dict = I18N[state.lang] || I18N.ru;
    var str = dict[key];
    if (str === undefined) str = I18N.ru[key] !== undefined ? I18N.ru[key] : key;
    if (vars) {
      str = str.replace(/\{(\w+)\}/g, function (m, k) { return vars[k] !== undefined ? vars[k] : m; });
    }
    return str;
  }

  /** DOM-конструктор: строки попадают только в textContent (защита от XSS). */
  function h(tag, props) {
    var el = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (k === 'dataset') Object.keys(v).forEach(function (d) { el.dataset[d] = v[d]; });
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, v);
      });
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(el, c); }); return; }
    el.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function icon(name, size) {
    var paths = {
      restart: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
      play: 'M7 4.5v15l12-7.5-12-7.5Z',
      doc: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Zm0 0v5h5M9 13h6M9 17h6',
      copy: 'M9 9h10v10H9zM5 15V5h10',
      eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
      download: 'M12 4v11m0 0-4-4m4 4 4-4M5 20h14',
      close: 'M6 6l12 12M18 6 6 18',
      calendar: 'M7 3v3M17 3v3M4 9h16M5 5.5h14a1 1 0 0 1 1 1V20a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6.5a1 1 0 0 1 1-1Z',
      report: 'M9 4h6v3H9zM7 5.5H6a2 2 0 0 0-2 2V19a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5a2 2 0 0 0-2-2h-1M8 16v-3M12 16v-6M16 16v-2',
      send: 'M21 3 10 14M21 3l-7 18-4-7-7-4 18-7Z',
      settings: 'M4 7h10M18 7h2M4 17h4M12 17h8M14 4v6M8 14v6',
      live: 'M3 12h4l3-7 4 14 3-7h4',
      stop: 'M7 7h10v10H7z',
      trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3'
    };
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', size || 16);
    svg.setAttribute('height', size || 16);
    svg.setAttribute('aria-hidden', 'true');
    var p = document.createElementNS(ns, 'path');
    p.setAttribute('d', paths[name]);
    p.setAttribute('fill', 'none');
    p.setAttribute('stroke', 'currentColor');
    p.setAttribute('stroke-width', '2');
    p.setAttribute('stroke-linecap', 'round');
    p.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(p);
    return svg;
  }

  // ------------------------------------------------------------------ formatting
  function locale() { return state.lang === 'ru' ? 'ru-RU' : 'en-US'; }

  function fmtNum(v, digits) {
    if (v === null || v === undefined || isNaN(v)) return t('na');
    return Number(v).toLocaleString(locale(), { minimumFractionDigits: digits || 0, maximumFractionDigits: digits || 0 });
  }

  function fmtBytes(b) {
    if (b === null || b === undefined) return t('na');
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    var v = Number(b);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    var digits = i === 0 ? 0 : (v >= 100 ? 0 : 1);
    return fmtNum(v, digits) + ' ' + t('b_' + units[i]);
  }

  function fmtDuration(sec) {
    if (sec === null || sec === undefined || sec < 0) return t('na');
    sec = Math.floor(sec);
    var d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    if (d > 0) return d + t('u_d') + ' ' + hh + t('u_h');
    if (hh > 0) return hh + t('u_h') + ' ' + m + t('u_m');
    if (m > 0) return m + t('u_m') + ' ' + s + t('u_s');
    return s + t('u_s');
  }

  function fmtDate(epochSec) {
    if (!epochSec) return t('na');
    return new Date(epochSec * 1000).toLocaleString(locale(), { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function fmtClock(d) {
    return (d || new Date()).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function svcDesc(svc) { return state.lang === 'ru' ? svc.desc_ru : svc.desc_en; }

  // ------------------------------------------------------------------ network
  function api(path, opts) {
    opts = opts || {};
    var ctrl = window.AbortController ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, opts.timeout || 15000) : null;
    var init = { method: opts.method || 'GET', headers: { 'Accept': 'application/json' }, credentials: 'same-origin', cache: 'no-store' };
    if (ctrl) init.signal = ctrl.signal;
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-Requested-With'] = 'kvm-metrics';
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (resp) {
      return resp.text().then(function (txt) {
        var data = null;
        try { data = txt ? JSON.parse(txt) : null; } catch (e) { data = null; }
        return { ok: resp.ok, status: resp.status, data: data };
      });
    }, function () {
      return { ok: false, status: 0, data: null };
    }).then(function (res) {
      if (timer) clearTimeout(timer);
      return res;
    });
  }

  // ------------------------------------------------------------------ i18n apply
  function applyI18n() {
    root.setAttribute('lang', state.lang);
    document.querySelectorAll('[data-i18n]').forEach(function (el) { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-title]').forEach(function (el) { el.title = t(el.getAttribute('data-i18n-title')); });
    document.querySelectorAll('[data-i18n-aria]').forEach(function (el) { el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria'))); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) { el.placeholder = t(el.getAttribute('data-i18n-placeholder')); });
    document.querySelectorAll('[data-lang]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-lang') === state.lang)); });
    $('interval').querySelectorAll('option').forEach(function (o) {
      if (o.value !== '0') o.textContent = o.value + ' ' + t('u_s');
    });
  }

  // ------------------------------------------------------------------ rendering
  function problems(data) {
    return data.services.filter(function (s) { return s.state !== 'active'; });
  }

  function restartingServices(data) {
    return data.services.filter(function (s) { return s.restart && s.restart.in_progress; });
  }

  function renderOverall(data) {
    var bad = problems(data);
    var busy = restartingServices(data);
    var el = $('overall');
    var title;
    if (busy.length) {
      el.setAttribute('data-state', 'warn');
      title = t('restarting_now', { units: busy.map(function (s) { return s.unit.replace(/\.service$/, ''); }).join(', ') });
    } else if (!bad.length) {
      el.setAttribute('data-state', 'ok');
      title = t('all_up');
    } else {
      el.setAttribute('data-state', bad.some(function (s) { return STATES[s.state] && STATES[s.state].tone === 'bad'; }) ? 'bad' : 'warn');
      title = t('some_down', { n: bad.length, total: data.services.length });
    }
    $('overall-title').textContent = title;
    $('host').textContent = data.host;
    $('os-name').textContent = data.system.os_name;
    $('server-time').textContent = fmtServerTime(data.time);

    document.title = (bad.length ? '(' + bad.length + ') ' : '') + t('title');
    setFavicon(busy.length ? '#f5b942' : bad.length ? '#ed2939' : '#00a88e', busy.length ? 'warn' : bad.length ? 'bad' : 'ok');
  }

  function fmtServerTime(iso) {
    var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})/.exec(iso || '');
    if (!m) return iso || '';
    return state.lang === 'ru' ? m[3] + '.' + m[2] + '.' + m[1] + ', ' + m[4] : m[1] + '-' + m[2] + '-' + m[3] + ' ' + m[4];
  }

  var lastFavicon = '';
  var faviconImg = null;

  /** Значок вкладки — логотип сервиса; при проблемах поверх него рисуется цветная точка. */
  var faviconWant = null;  // последнее запрошенное состояние: применяется и после загрузки картинки
  function brandFavicon(color, tone) {
    var link = $('favicon');
    faviconWant = [color, tone];
    if (!faviconImg) {
      faviconImg = new Image();
      faviconImg.onload = function () { brandFavicon(faviconWant[0], faviconWant[1]); };
      faviconImg.src = '/brand/favicon';
      return;
    }
    if (!faviconImg.complete || !faviconImg.naturalWidth) return;
    if (tone === 'ok') { link.setAttribute('href', '/brand/favicon'); return; }
    var canvas = document.createElement('canvas');
    canvas.width = canvas.height = 64;
    var ctx = canvas.getContext('2d');
    ctx.drawImage(faviconImg, 0, 0, 64, 64);
    ctx.beginPath();
    ctx.arc(48, 16, 14, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 4;
    ctx.strokeStyle = '#ffffff';
    ctx.stroke();
    link.setAttribute('href', canvas.toDataURL('image/png'));
  }

  function setFavicon(color, tone) {
    if (color + tone === lastFavicon) return;
    lastFavicon = color + tone;
    var fixed = document.querySelector('meta[name="static-favicon"]');
    if (fixed && fixed.getAttribute('content') === '1') { brandFavicon(color, tone); return; }
    var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='#1d1d1b'/>" +
      "<circle cx='16' cy='16' r='8' fill='" + color + "'/></svg>";
    $('favicon').setAttribute('href', 'data:image/svg+xml,' + encodeURIComponent(svg));
  }

  function renderKpis(data) {
    var sum = data.summary, sys = data.system, mem = sys.memory;
    var kpiSvc = $('kpi-services');
    kpiSvc.textContent = sum.running + ' / ' + sum.total;
    kpiSvc.classList.toggle('bad', sum.running < sum.total);
    $('kpi-services-sub').textContent = t('running_of');
    $('kpi-svc-mem').textContent = fmtBytes(sum.services_memory_bytes);
    $('kpi-svc-mem-sub').textContent = mem.total ? t('of_ram', { v: fmtNum(pct(sum.services_memory_bytes, mem.total), 1) }) : '';
    $('kpi-ram').textContent = fmtBytes(mem.used);
    $('kpi-ram-sub').textContent = t('used_of', { total: fmtBytes(mem.total) });
    $('kpi-cpu').textContent = fmtNum(sys.cpu_threads);
    $('kpi-cpu-sub').textContent = sys.cpu_percent !== null && sys.cpu_percent !== undefined
      ? t('cpu_load', { v: fmtNum(sys.cpu_percent, sys.cpu_percent < 10 ? 1 : 0) }) : '';
    $('kpi-uptime').textContent = fmtDuration(sys.uptime_sec);
    $('kpi-uptime-sub').textContent = sys.uptime_sec ? t('since', { date: fmtDate(Date.now() / 1000 - sys.uptime_sec) }) : '';
  }

  function pct(part, total) { return total > 0 ? Math.max(0, Math.min(100, part * 100 / total)) : 0; }

  function renderMemory(data) {
    var m = data.system.memory;
    // части всегда складываются в целое: процессы + кэш = используется, + не используется = всего
    $('mem-anon').style.width = pct(m.processes, m.total) + '%';
    $('mem-cache').style.width = pct(m.cache, m.total) + '%';
    $('mem-free').style.width = pct(m.free, m.total) + '%';
    $('leg-anon').textContent = fmtBytes(m.processes);
    $('leg-cache').textContent = fmtBytes(m.cache);
    $('leg-free').textContent = fmtBytes(m.free);
    var note = t('mem_note', { used: fmtBytes(m.used), total: fmtBytes(m.total), pct: fmtNum(pct(m.used, m.total)) });
    $('mem-note').textContent = note;
    $('membar').setAttribute('aria-label', note);
  }

  function metric(label) {
    var value = h('div', { class: 'metric-value' });
    var el = h('div', { class: 'metric' }, h('div', { class: 'metric-label', text: label }), value);
    return { el: el, value: value };
  }

  function buildCard(svc) {
    var c = {};
    c.pill = h('span', { class: 'pill' });
    c.unit = h('div', { class: 'unit' });
    c.desc = h('div', { class: 'desc' });
    c.mMem = metric(''); c.mPid = metric(''); c.mUp = metric('');
    c.progress = h('div', { class: 'card-progress', hidden: true });
    c.btnRestart = h('button', { type: 'button', class: 'btn btn-sm', onclick: function () { openRestartDialog(svc.key); } });
    c.btnJournal = h('button', { type: 'button', class: 'btn btn-sm btn-link btn-journal', onclick: function () {
      openLogViewer({ kind: 'journal', key: svc.key, title: t('journal_of') + ': ' + c.unitName.replace(/\.service$/, '') });
    } });
    c.btnLog = h('button', { type: 'button', class: 'btn btn-sm btn-link btn-log', hidden: true, onclick: function () {
      var f = logFileForService(svc.key);
      if (f) openLogViewer({ kind: 'file', key: f.key, title: state.lang === 'ru' ? f.title_ru : f.title_en });
    } });
    c.btnLive = h('button', { type: 'button', class: 'btn btn-sm btn-link btn-live', onclick: function () {
      var f = logFileForService(svc.key);
      if (f && !f.exists) f = null;
      if (f) openLiveViewer({ kind: 'file', key: f.key, title: state.lang === 'ru' ? f.title_ru : f.title_en });
      else openLiveViewer({ kind: 'journal', key: svc.key, title: t('journal_of') + ': ' + c.unitName.replace(/\.service$/, '') });
    } });
    c.btnCopy = h('button', { type: 'button', class: 'btn btn-sm btn-copy', onclick: function () {
      copyText('sudo systemctl restart ' + c.unitName);
    } });
    c.el = h('article', { class: 'card', 'data-key': svc.key },
      c.progress,
      h('div', { class: 'card-head' }, h('div', { class: 'card-title' }, c.unit, c.desc), c.pill),
      h('div', { class: 'card-links' }, c.btnLive, c.btnLog, c.btnJournal),
      h('div', { class: 'metrics' }, c.mMem.el, c.mPid.el, c.mUp.el),
      h('div', { class: 'card-actions' }, c.btnRestart, h('span', { class: 'spacer' }), c.btnCopy));
    return c;
  }

  function setMetric(m, label, value, title) {
    m.el.firstChild.textContent = label;
    m.value.textContent = value;
    m.value.classList.toggle('na', value === t('na'));
    if (title) m.value.title = title; else m.value.removeAttribute('title');
  }

  function updateCard(c, svc) {
    var st = STATES[svc.state] || STATES.unknown;
    var restarting = svc.restart && svc.restart.in_progress;
    var tone = restarting ? 'warn' : st.tone;
    c.el.setAttribute('data-tone', tone);
    c.el.setAttribute('aria-busy', String(!!restarting));
    c.pill.setAttribute('data-tone', tone);
    c.pill.setAttribute('data-busy', String(!!(restarting || st.busy)));
    c.pill.textContent = restarting ? t('st_restarting', { s: fmtDuration(svc.restart.elapsed) }) : t('st_' + svc.state);
    c.pill.title = svc.sub_state ? svc.state + ' (' + svc.sub_state + ')' : svc.state;
    c.unit.textContent = svc.unit;
    c.unitName = svc.unit;
    c.desc.textContent = svcDesc(svc);
    var active = svc.state === 'active';
    setMetric(c.mMem, t('m_memory'), active || svc.memory_bytes ? fmtBytes(svc.memory_bytes) : t('na'),
      svc.memory_source === 'rss' ? t('m_rss') : '');
    setMetric(c.mPid, t('m_pid'), svc.pid ? String(svc.pid) : t('na'));
    setMetric(c.mUp, t('m_uptime'), fmtDuration(svc.uptime_sec));

    c.progress.hidden = !restarting;
    var installed = svc.state !== 'not-found' && svc.state !== 'masked';
    clear(c.btnRestart);
    append(c.btnRestart, [icon(active ? 'restart' : 'play'), active ? t('btn_restart') : t('btn_start')]);
    c.btnRestart.className = 'btn btn-sm ' + (active ? '' : 'btn-primary');
    c.btnRestart.disabled = !!restarting || !installed;
    clear(c.btnJournal);
    append(c.btnJournal, [icon('doc'), t('btn_journal')]);
    updateCardLogButton(c, svc.key);
    clear(c.btnCopy);
    append(c.btnCopy, [icon('copy'), t('btn_copy_short')]);
    c.btnCopy.title = t('copy_cmd_hint', { cmd: 'sudo systemctl restart ' + svc.unit });
    c.btnCopy.setAttribute('aria-label', t('btn_copy_cmd') + ': ' + svc.unit);
  }

  function renderServices(data) {
    var grid = $('services-grid');
    grid.querySelectorAll('.skeleton').forEach(function (n) { n.remove(); });
    grid.setAttribute('aria-busy', 'false');
    var bad = problems(data);
    $('cnt-all').textContent = data.services.length;
    $('cnt-problems').textContent = bad.length;
    var shown = 0;
    data.services.forEach(function (svc) {
      var c = state.cards[svc.key];
      if (!c) { c = state.cards[svc.key] = buildCard(svc); grid.appendChild(c.el); }
      updateCard(c, svc);
      var visible = state.filter === 'all' || svc.state !== 'active';
      c.el.hidden = !visible;
      if (visible) shown++;
    });
    $('services-empty').hidden = shown > 0;
  }

  function portSortValue(p, key, unitByKey) {
    if (key === 'local') return [p.port === null || p.port === undefined ? 70000 : p.port, p.local];
    if (key === 'service') return [p.service ? 0 : 1, p.service ? unitByKey[p.service] : ''];
    return [String(p[key] || '').toLowerCase(), p.port || 0];
  }

  function compareValues(a, b) {
    for (var i = 0; i < a.length; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }

  /** Сортировка таблицы соединений по выбранному столбцу (по умолчанию — порядок сервера). */
  function sortPorts(rows, unitByKey) {
    var key = state.portsSort.key;
    if (!key) return rows;
    var dir = state.portsSort.dir === 'desc' ? -1 : 1;
    return rows.map(function (p, i) { return { p: p, i: i, v: portSortValue(p, key, unitByKey) }; })
      .sort(function (a, b) { return compareValues(a.v, b.v) * dir || a.i - b.i; })
      .map(function (x) { return x.p; });
  }

  function setPortsSort(key) {
    var cur = state.portsSort;
    if (cur.key !== key) state.portsSort = { key: key, dir: 'asc' };
    else if (cur.dir === 'asc') state.portsSort = { key: key, dir: 'desc' };
    else state.portsSort = { key: null, dir: 'asc' };
    document.querySelectorAll('.th-sort').forEach(function (b) {
      var active = b.getAttribute('data-sort') === state.portsSort.key;
      b.parentNode.setAttribute('aria-sort', active ? (state.portsSort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
    });
    if (state.data) renderPorts(state.data);
  }

  function renderPorts(data) {
    var tbody = $('ports-tbody');
    $('ports-count').textContent = data.ports.length;
    if (!state.portsOpen) return;
    clear(tbody);
    var q = state.portsQuery.toLowerCase();
    var unitByKey = {};
    data.services.forEach(function (s) { unitByKey[s.key] = s.unit.replace(/\.service$/, ''); });
    var rows = data.ports.filter(function (p) {
      if (state.portsKvm && !p.service) return false;
      if (!q) return true;
      return [p.netid, p.state, p.local, p.process, p.service ? unitByKey[p.service] : ''].join(' ').toLowerCase().indexOf(q) !== -1;
    });
    rows = sortPorts(rows, unitByKey);
    if (!rows.length) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: t('ports_empty') })));
      return;
    }
    var frag = document.createDocumentFragment();
    rows.forEach(function (p) {
      frag.appendChild(h('tr', { class: p.service ? 'kvm' : null },
        h('td', { text: p.netid }),
        h('td', { text: p.state }),
        h('td', { class: 'mono', text: p.local }),
        h('td', { class: 'mono', text: p.process + (p.pids && p.pids.length ? ' (' + p.pids.join(', ') + ')' : '') }),
        h('td', null, p.service ? h('span', { class: 'tag', text: unitByKey[p.service] || p.service }) : '')));
    });
    tbody.appendChild(frag);
  }

  function render() {
    var data = state.data;
    if (!data) return;
    renderOverall(data);
    renderKpis(data);
    renderMemory(data);
    renderServices(data);
    renderPorts(data);
  }

  // ------------------------------------------------------------------ logs & reports
  function logFileForService(key) {
    var files = (state.logs && state.logs.files) || [];
    return files.filter(function (f) { return f.service === key; })[0] || null;
  }

  function updateCardLogButton(c, key) {
    var f = logFileForService(key);
    clear(c.btnLive);  // нет лог-файла (СУБД) — Real-time показывает журнал службы
    append(c.btnLive, [icon('live'), f && f.exists ? t('btn_live') : t('btn_live_journal')]);
    c.btnLive.title = t('btn_live_title');
    c.btnLog.hidden = !f;
    if (!f) return;
    clear(c.btnLog);
    append(c.btnLog, [icon('doc'), t('btn_log')]);
    c.btnLog.title = (f.exists ? t('btn_log_title') : t('log_missing')) + ': ' + (f.resolved || f.path);
    c.btnLog.disabled = !f.exists || !f.readable;
  }

  function renderLogs() {
    Object.keys(state.cards).forEach(function (k) { updateCardLogButton(state.cards[k], k); });
  }

  function renderReports() {
    var list = $('reports-list');
    clear(list);
    var reports = (state.logs && state.logs.reports) || [];
    var names = {};
    reports.forEach(function (r) { names[r.name] = true; });
    Object.keys(state.selectedReports).forEach(function (n) { if (!names[n]) delete state.selectedReports[n]; });
    if (!reports.length) {
      list.appendChild(h('p', { class: 'empty', text: t('reports_empty') }));
    }
    reports.forEach(function (r) {
      var cb = h('input', { type: 'checkbox', checked: !!state.selectedReports[r.name], onchange: function () {
        if (cb.checked) state.selectedReports[r.name] = true; else delete state.selectedReports[r.name];
        updateReportButtons();
      } });
      list.appendChild(h('div', { class: 'row' },
        h('label', { class: 'check' }, cb, h('span', { class: 'mono', text: r.name })),
        h('span', { class: 'row-meta', text: fmtBytes(r.size) + ' · ' + fmtDate(r.mtime) }),
        h('a', { class: 'btn btn-sm btn-ghost btn-icon', href: '/log?file=' + encodeURIComponent(r.name), title: t('download'), 'aria-label': t('download') + ' ' + r.name }, icon('download'))));
    });
    updateReportButtons();
  }

  function updateReportButtons() {
    var total = ((state.logs && state.logs.reports) || []).length;
    var n = Object.keys(state.selectedReports).length;
    var dl = $('btn-reports-dl');
    dl.disabled = n === 0;
    dl.textContent = n ? t('download_n', { n: n }) : t('download');
    var all = $('btn-reports-all');
    all.disabled = total === 0;
    all.textContent = n === total && total ? t('select_none') : t('select_all');
  }

  function loadLogs() {
    return api('/api/logs').then(function (res) {
      if (!res.ok || !res.data) return;
      state.logs = res.data;
      state.logsAt = Date.now();
      renderLogs();
      renderReports();
    });
  }

  function downloadReports() {
    var names = Object.keys(state.selectedReports);
    if (!names.length) return;
    location.href = names.length === 1 ? '/log?file=' + encodeURIComponent(names[0])
      : '/logs-archive?files=' + encodeURIComponent(JSON.stringify(names));
  }

  // ------------------------------------------------------------------ SIEM
  var SIEM_TONES = { off: 'idle', ok: 'ok', error: 'bad', waiting: 'warn' };

  function sevTone(sev) { return sev >= 4 ? 'bad' : sev >= 3 ? 'warn' : 'ok'; }  // важность 1–5

  function fmtIso(iso) {
    var d = iso ? new Date(iso) : null;
    if (!d || isNaN(d.getTime())) return iso || t('na');
    return d.toLocaleString(locale(), { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  /** Состояние SIEM обновляется вместе с остальными данными (цикл обновления), без перезагрузки страницы.
   *  Панель перерисовывается, только если что-то изменилось, — раскрытые события и выделение не сбиваются. */
  function loadSiem() {
    return api('/api/siem').then(function (res) {
      if (!res.ok || !res.data) return;
      var sig = JSON.stringify([res.data.config, res.data.recent, res.data.total, state.lang]);
      state.siem = res.data;
      if (sig !== state.siemSig || !$('siem-body').firstChild) { state.siemSig = sig; renderSiem(); }
      if (state.siemViewer) state.siemViewer();
    });
  }

  function renderSiem() {
    var box = $('siem-body');
    var s = state.siem;
    if (!box || !s) return;
    clear(box);
    var c = s.config;
    var pill = $('siem-pill');
    pill.textContent = t('siem_st_' + c.state);
    pill.setAttribute('data-tone', SIEM_TONES[c.state] || 'idle');
    pill.hidden = false;
    if (!c.enabled) {
      box.appendChild(h('p', { class: 'hint', text: t('siem_off_text') }));
    } else {
      box.appendChild(h('div', { class: 'siem-target' },
        h('span', { class: 'mono', text: c.host + ':' + c.port }),
        h('span', { class: 'chip', text: c.protocol.toUpperCase() }),
        h('span', { class: 'row-meta', text: t('siem_stats', { sent: c.stats.sent, failed: c.stats.failed, queued: c.stats.queued }) })));
      if (c.state === 'error' && c.stats.last_error) {
        box.appendChild(h('div', { class: 'callout callout-bad', text: t('siem_last_error', { time: fmtIso(c.stats.last_error_time), msg: c.stats.last_error }) }));
      }
    }
    renderSiemEvents(box, s.recent || [], s.total);
  }

  /** Отправляемые события: 5 последних — раскрывающимся списком (у каждого строка syslog/CEF, как она
   *  уходит в SIEM); все — в окне «Все события» с поиском, переносом строк и скачиванием. */
  function renderSiemEvents(box, recent, total) {
    var wrap = store('siemWrap') === '1';
    var head = h('div', { class: 'events-head' }, h('span', { class: 'subhead', text: t('siem_recent') }));
    box.appendChild(head);
    if (!recent.length) { box.appendChild(h('p', { class: 'empty', text: t('siem_recent_empty') })); return; }
    var cb = h('input', { type: 'checkbox', class: 'siem-wrap' });
    cb.checked = wrap;
    head.appendChild(h('span', { class: 'spacer' }));
    head.appendChild(h('label', { class: 'check', title: t('lv_wrap_title') }, cb, h('span', { text: t('lv_wrap') })));
    head.appendChild(h('button', { type: 'button', class: 'btn btn-sm events-all', onclick: function () {
      openLogViewer({ kind: 'siem', key: 'siem-events', title: t('siem_all_title') });
    } }, icon('doc'), t('siem_all', { n: total || recent.length })));
    var list = h('ul', { class: 'events' + (wrap ? ' wrap' : '') });
    cb.addEventListener('change', function () {
      store('siemWrap', cb.checked ? '1' : '0');
      list.classList.toggle('wrap', cb.checked);
    });
    recent.forEach(function (e) {
      var st = e.siem || 'none';
      var details = h('details', { class: 'event', 'data-id': String(e.id) });
      details.open = !!state.siemOpen[e.id];
      details.addEventListener('toggle', function () {
        if (details.open) state.siemOpen[e.id] = true; else delete state.siemOpen[e.id];
      });
      append(details, [
        h('summary', null,
          h('span', { class: 'sev', 'data-tone': sevTone(e.severity), text: String(e.severity), title: t('col_sev') }),
          h('span', { class: 'event-time mono', text: fmtIso(e.time) }),
          h('span', { class: 'event-msg', text: e.message, title: e.title }),
          h('span', { class: 'event-st', 'data-st': st, text: t('siem_ev_' + st), title: e.siem_time ? fmtIso(e.siem_time) : '' })),
        h('div', { class: 'event-body' },
          h('div', { class: 'event-meta' },
            h('span', null, h('b', { text: e.title }), ' · ID ' + e.signature + ' · ' + t('col_sev').toLowerCase() + ' ' + e.severity + ' · ' + e.category),
            h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: function () { copyText(e.raw || ''); } }, icon('copy'), t('lv_copy'))),
          h('div', { class: 'event-label', text: t('siem_raw') }),
          h('pre', { class: 'event-raw mono', text: e.raw || '' }))
      ]);
      list.appendChild(h('li', null, details));
    });
    box.appendChild(list);
  }

  function openSiemDialog() {
    var s = state.siem;
    if (!s) return;
    var c = s.config, reco = s.recommended;
    var proto = c.enabled || c.host ? c.protocol : reco.protocol;
    var host = h('input', { type: 'text', class: 'input', id: 'siem-host', autocomplete: 'off', spellcheck: 'false', placeholder: t('siem_host_ph') });
    host.value = c.host || '';
    var port = h('input', { type: 'number', class: 'input input-port', id: 'siem-port', min: '1', max: '65535', inputmode: 'numeric' });
    port.value = String(c.host ? c.port : reco.port);
    var enabled = h('input', { type: 'checkbox', id: 'siem-enabled' });
    enabled.checked = c.enabled || !c.host;
    var protoBtns = ['tcp', 'udp'].map(function (p) {
      return h('button', { type: 'button', class: 'seg-btn', 'data-proto': p },
        p.toUpperCase(), p === reco.protocol ? h('span', { class: 'reco-badge', text: t('recommended') }) : null);
    });
    var udpWarn = h('div', { class: 'callout', text: t('siem_udp_warn') });
    function setProto(p) {
      proto = p;
      protoBtns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-proto') === p)); });
      udpWarn.hidden = p !== 'udp';
    }
    protoBtns.forEach(function (b) { b.addEventListener('click', function () { setProto(b.getAttribute('data-proto')); }); });
    var portHint = h('button', { type: 'button', class: 'btn btn-sm btn-link', text: String(reco.port), title: t('siem_reco', { port: reco.port }) });
    portHint.addEventListener('click', function () { port.value = String(reco.port); setProto(reco.protocol); port.focus(); });
    var pw = passwordField('siem-pw');
    var cancel = h('button', { type: 'button', class: 'btn', text: t('cancel') });
    var test = h('button', { type: 'button', class: 'btn' }, icon('send'), t('siem_test'));
    var save = h('button', { type: 'submit', class: 'btn btn-primary', text: t('siem_save') });
    var rows = s.events.map(function (e) {
      return h('tr', null, h('td', { class: 'mono', text: String(e.signature) }),
        h('td', null, h('span', { class: 'sev', 'data-tone': sevTone(e.severity), text: String(e.severity) })),
        h('td', { text: e.title }));
    });
    var form = h('form', { novalidate: true },
      h('div', { class: 'modal-body' },
        h('div', { class: 'callout callout-accent' },
          h('div', { class: 'callout-title', text: t('siem_reco', { port: reco.port }) }),
          h('div', { text: t('siem_reco_text', { port: reco.port }) })),
        h('label', { class: 'check check-strong' }, enabled, h('span', { text: t('siem_enabled') })),
        h('div', { class: 'field-row' },
          h('div', { class: 'field field-grow' }, h('label', { for: 'siem-host', text: t('siem_host') }), host),
          h('div', { class: 'field' }, h('label', { for: 'siem-port' }, t('siem_port'), ' ', h('span', { class: 'field-hint' }, '(', t('recommended'), ': ', portHint, ')')), port)),
        h('div', { class: 'field' }, h('span', { class: 'label', text: t('siem_proto') }),
          h('div', { class: 'seg seg-proto', role: 'group', 'aria-label': t('siem_proto') }, protoBtns)),
        udpWarn,
        h('details', { class: 'details' }, h('summary', { text: t('siem_events_list', { n: s.events.length }) }),
          h('div', { class: 'table-wrap' }, h('table', { class: 'table table-compact' },
            h('thead', null, h('tr', null, h('th', { text: t('col_sig') }), h('th', { text: t('col_sev') }), h('th', { text: t('col_event') }))),
            h('tbody', null, rows)))),
        pw.field),
      h('div', { class: 'modal-foot' }, test, h('span', { class: 'spacer' }), cancel, save));
    setProto(proto);
    var modal = openModal({ title: t('siem'), sub: t('siem_sub'), content: form, focus: host, size: 'md' });
    var unavailable = authUnavailableText();
    if (unavailable) {
      pw.err.textContent = unavailable;
      pw.input.disabled = true; save.disabled = true; test.disabled = true;
    }
    cancel.addEventListener('click', function () { modal.close(); });

    function payload() {
      return { password: pw.input.value, enabled: enabled.checked, host: host.value.trim(), port: port.value, protocol: proto };
    }
    function submitTo(path, button, onOk) {
      if (button.disabled) return;
      if (!pw.input.value) { pw.err.textContent = t('err_empty_password'); pw.input.focus(); return; }
      pw.err.textContent = '';
      var buttons = [save, test, cancel];
      buttons.forEach(function (b) { b.disabled = true; });
      modal.locked = true;
      var spinner = h('span', { class: 'spinner' });
      button.insertBefore(spinner, button.firstChild);
      api(path, { method: 'POST', body: payload(), timeout: 30000 }).then(function (res) {
        spinner.remove();
        modal.locked = false;
        if (res.ok) { onOk(res); return; }
        var d = res.data || {};
        pw.err.textContent = authErrorText(res);
        var permanent = PERMANENT_AUTH_ERRORS.indexOf(d.error) !== -1;
        buttons.forEach(function (b) { b.disabled = permanent && b !== cancel; });
        if (d.error === 'bad_password') { pw.input.value = ''; pw.input.focus(); }
        else if (/host/.test(d.error || '')) host.focus();
        else if (d.error === 'bad_port') port.focus();
      });
    }
    test.addEventListener('click', function () {
      submitTo('/api/siem/test', test, function (res) {
        [save, test, cancel].forEach(function (b) { b.disabled = false; });
        var d = res.data;
        toast(t('siem_test_ok'), t('siem_test_ok_text', { target: d.target, proto: d.protocol.toUpperCase() }) +
          (d.protocol === 'udp' ? ' ' + t('siem_test_udp') : ''), 'ok', 7000);
        loadSiem();
      });
    });
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      submitTo('/api/siem', save, function (res) {
        pw.input.value = '';
        modal.close();
        state.siem = res.data;
        renderSiem();
        toast(res.data.config.enabled ? t('siem_saved') : t('siem_saved_off'),
          res.data.config.enabled ? res.data.config.host + ':' + res.data.config.port + ' · ' + res.data.config.protocol.toUpperCase() : '', 'ok');
      });
    });
  }

  function downloadReportNow() {
    var btn = $('btn-report-now');
    btn.disabled = true;
    toast(t('report_now_started'), '', 'ok', 4000);
    location.href = '/api/report-now';
    setTimeout(function () { btn.disabled = false; }, 5000);
  }

  function isoDay(d) {
    return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
  }

  /** Архив логов компонентов за выбранный день (сегодня — отдельная кнопка «Скачать логи за сегодня»). */
  function openLogsDayDialog() {
    var now = new Date();
    var yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    var input = h('input', { type: 'date', class: 'input', id: 'logs-day', max: isoDay(now), required: true });
    input.value = isoDay(yesterday);
    var err = h('div', { class: 'field-error', role: 'alert', hidden: true, text: t('logs_day_bad') });
    var btn = h('button', { type: 'submit', class: 'btn btn-primary' }, icon('download'), t('logs_day_download'));
    var form = h('form', { novalidate: true },
      h('div', { class: 'modal-body' },
        h('p', { class: 'confirm-text', text: t('logs_day_hint') }),
        h('div', { class: 'field' }, h('label', { for: 'logs-day', text: t('logs_day_label') }), input, err)),
      h('div', { class: 'modal-foot' }, h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'btn', onclick: function () { modal.close(); } }, t('cancel')), btn));
    var modal = openModal({ title: t('logs_day_title'), content: form, focus: input });
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v = input.value;
      var ok = /^\d{4}-\d{2}-\d{2}$/.test(v) && v <= isoDay(new Date());
      err.hidden = ok;
      if (!ok) { input.focus(); return; }
      toast(t('logs_today_started'), '', 'ok', 4000);
      location.href = '/logs-day?date=' + encodeURIComponent(v);
      modal.close();
    });
    return modal;
  }

  // ------------------------------------------------------------------ refresh loop
  function setRefreshing(on) {
    $('btn-refresh').classList.toggle('spinning', on);
  }

  function anyRestart() {
    if (Object.keys(state.pending).length) return true;
    return !!(state.data && restartingServices(state.data).length);
  }

  function refresh() {
    if (state.inflight) { state.again = true; return Promise.resolve(); }  // повторим сразу после текущего
    state.inflight = true;
    clearTimeout(state.timer);
    setRefreshing(true);
    return api('/api/status', { timeout: 12000 }).then(function (res) {
      state.inflight = false;
      setRefreshing(false);
      if (res.ok && res.data && res.data.services) {
        if (checkVersion(res.data.version)) return;
        state.data = res.data;
        state.lastOk = Date.now();
        state.failures = 0;
        $('banner').hidden = true;
        render();
        checkRestarts(res.data);
        loadSiem();
        if (Date.now() - (state.logsAt || 0) > 60000) loadLogs();  // отчёты и лог-файлы — раз в минуту
      } else {
        state.failures++;
        $('banner-text').textContent = state.lastOk ? t('conn_lost', { time: fmtClock(new Date(state.lastOk)) }) : t('conn_lost_first');
        $('banner').hidden = false;
      }
      if (state.again) { state.again = false; refresh(); return; }
      schedule();
    });
  }

  function schedule() {
    clearTimeout(state.timer);
    var delay = anyRestart() ? 1000 : state.interval * 1000;
    if (state.failures && delay) delay = Math.min(30000, Math.max(delay, 2000 * Math.pow(2, state.failures - 1)));
    if (!delay || document.hidden) return;
    state.timer = setTimeout(refresh, delay);
  }

  /**
   * Бесшовное обновление: после обновления сервиса открытые вкладки сами
   * перезагружаются, чтобы получить новый интерфейс (один раз на версию).
   */
  function checkVersion(serverVersion) {
    var meta = document.querySelector('meta[name="app-version"]');
    var current = meta ? meta.getAttribute('content') : '';
    if (!serverVersion || !current || serverVersion === current) return false;
    var key = 'kvm.reloadedFor';
    var already = null;
    try { already = window.sessionStorage.getItem(key); } catch (e) { already = null; }
    if (already === serverVersion) return false;
    try { window.sessionStorage.setItem(key, serverVersion); } catch (e) { /* без хранилища */ }
    toast(t('updated_to', { v: serverVersion }), '', 'ok', 3000);
    setTimeout(function () { location.reload(); }, 800);
    return true;
  }

  /** Автообновление после перезапуска: опрос раз в секунду до завершения, затем уведомление. */
  function checkRestarts(data) {
    Object.keys(state.pending).forEach(function (key) {
      var svc = data.services.filter(function (s) { return s.key === key; })[0];
      var pending = state.pending[key];
      if (!svc) { delete state.pending[key]; return; }
      var r = svc.restart;
      if (r && r.in_progress) { pending.seen = true; return; }
      // Результат на сервере сбрасывается при каждом новом запуске, поэтому любой
      // результат после нашего запроса относится к нему (без сравнения часов клиента и сервера).
      if (r && (pending.seen || Date.now() - pending.at > 3000)) {
        delete state.pending[key];
        if (r.result === 'ok') toast(t('restart_ok'), svc.unit, 'ok');
        else if (r.result === 'timeout') toast(t('restart_timeout'), svc.unit, 'warn');
        else toast(t('restart_failed'), t('restart_failed_text', { unit: svc.unit }), 'bad');
        loadLogs();
        return;
      }
      if (Date.now() - pending.at > 200000) delete state.pending[key];
    });
  }

  // ------------------------------------------------------------------ toasts & clipboard
  function toast(title, text, tone, ms) {
    var box = $('toasts');
    var close = h('button', { type: 'button', class: 'toast-close', 'aria-label': t('close'), text: '×' });
    var el = h('div', { class: 'toast', 'data-tone': tone || 'ok' },
      h('div', { class: 'toast-body' }, h('div', { class: 'toast-title', text: title }), text ? h('div', { class: 'toast-text', text: text }) : null),
      close);
    function dismiss() {
      el.classList.add('out');
      setTimeout(function () { el.remove(); }, 220);
    }
    close.addEventListener('click', dismiss);
    box.appendChild(el);
    while (box.children.length > 4) box.removeChild(box.firstChild);
    setTimeout(dismiss, ms || (tone === 'bad' ? 9000 : 5000));
  }

  function copyText(text) {
    function fallback() {
      var ta = h('textarea', { readonly: true, class: 'sr-only' });
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      ta.remove();
      toast(ok ? t('copied') : t('copy_failed'), ok ? text : '', ok ? 'ok' : 'bad', 2500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { toast(t('copied'), text.length > 80 ? '' : text, 'ok', 2500); }, fallback);
    } else fallback();
  }

  // ------------------------------------------------------------------ modal
  var openModals = [];

  function openModal(opts) {
    var opener = document.activeElement;
    var titleId = 'm-' + Math.random().toString(36).slice(2);
    var closeBtn = h('button', { type: 'button', class: 'btn btn-icon btn-ghost', 'aria-label': t('close'), title: t('close') }, icon('close'));
    var modal = h('div', { class: 'modal' + (opts.size ? ' modal-' + opts.size : ''), role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
      h('div', { class: 'modal-head' },
        h('div', null, h('div', { class: 'modal-title', id: titleId, text: opts.title }), opts.sub ? h('div', { class: 'modal-sub', text: opts.sub }) : null),
        closeBtn),
      opts.content);
    var backdrop = h('div', { class: 'modal-backdrop' }, modal);
    var handle = {
      el: modal,
      locked: false,
      close: function () {
        if (!backdrop.parentNode) return;
        backdrop.remove();
        openModals = openModals.filter(function (m) { return m !== handle; });
        document.removeEventListener('keydown', onKey, true);
        if (opts.onClose) opts.onClose();
        if (opener && opener.focus && document.contains(opener)) opener.focus();
      }
    };
    function onKey(e) {
      if (openModals[openModals.length - 1] !== handle) return;
      if (e.key === 'Escape') { if (!handle.locked) { e.preventDefault(); handle.close(); } return; }
      if (e.key !== 'Tab') return;
      var focusable = Array.prototype.filter.call(modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'),
        function (n) { return !n.disabled && n.offsetParent !== null; });
      if (!focusable.length) return;
      var first = focusable[0], last = focusable[focusable.length - 1];
      if (!modal.contains(document.activeElement)) { e.preventDefault(); (e.shiftKey ? last : first).focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
    closeBtn.addEventListener('click', function () { if (!handle.locked) handle.close(); });
    backdrop.addEventListener('mousedown', function (e) { if (e.target === backdrop && !handle.locked) handle.close(); });
    document.addEventListener('keydown', onKey, true);
    $('modal-root').appendChild(backdrop);
    openModals.push(handle);
    (opts.focus || closeBtn).focus();
    setTimeout(function () { if (!modal.contains(document.activeElement)) (opts.focus || closeBtn).focus(); }, 30);
    return handle;
  }

  // ------------------------------------------------------------------ restart dialog
  function findService(key) {
    return state.data ? state.data.services.filter(function (s) { return s.key === key; })[0] : null;
  }

  function authErrorText(res) {
    var d = res.data || {};
    switch (d.error) {
      case 'bad_password': return t('err_bad_password', { n: d.attempts_left });
      case 'locked': return t('err_locked', { t: fmtDuration(d.retry_after) });
      case 'root_locked': return t('err_root_locked');
      case 'auth_unavailable': return t('err_auth_unavailable');
      case 'in_progress': return t('err_in_progress');
      case 'systemctl_failed': return t('err_systemctl_failed', { msg: d.message || '' });
      case 'csrf': return t('err_csrf');
      case 'insecure_transport': return t('err_insecure_transport');
      case 'send_failed': return t('err_send_failed', { msg: d.message || '' });
      case 'save_failed': return t('err_save_failed', { msg: d.message || '' });
      case 'host_required': case 'bad_host': case 'bad_port': case 'bad_protocol': return t('err_' + d.error);
      default: return res.status === 0 ? t('err_network') : t('err_generic', { code: d.error || res.status });
    }
  }

  var PERMANENT_AUTH_ERRORS = ['root_locked', 'auth_unavailable', 'insecure_transport', 'locked'];

  function authUnavailableText() {
    var s = state.data && state.data.auth ? state.data.auth.restart : 'ok';
    if (s === 'locked') return t('err_root_locked');
    if (s === 'insecure') return t('err_insecure_transport');
    if (s === 'unavailable') return t('err_auth_unavailable');
    return '';
  }

  function passwordField(id) {
    var input = h('input', { type: 'password', class: 'input', id: id, autocomplete: 'off', spellcheck: 'false', 'aria-describedby': id + '-err' });
    var toggle = h('button', { type: 'button', class: 'btn btn-ghost', 'aria-label': t('show_password'), title: t('show_password') }, icon('eye'));
    var err = h('div', { class: 'field-error', id: id + '-err', role: 'alert' });
    toggle.addEventListener('click', function () {
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggle.setAttribute('aria-label', show ? t('hide_password') : t('show_password'));
      toggle.title = toggle.getAttribute('aria-label');
      input.focus();
    });
    var field = h('div', { class: 'field' }, h('label', { for: id, text: t('root_password') }), h('div', { class: 'pw-wrap' }, input, toggle), err);
    return { field: field, input: input, err: err };
  }

  function openRestartDialog(key) {
    var svc = findService(key);
    if (!svc) return;
    var active = svc.state === 'active';
    var pw = passwordField('root-pw');
    var input = pw.input, err = pw.err;
    var cancel = h('button', { type: 'button', class: 'btn', text: t('cancel') });
    var submit = h('button', { type: 'submit', class: 'btn ' + (active ? 'btn-danger' : 'btn-primary') }, icon(active ? 'restart' : 'play'), active ? t('btn_restart') : t('btn_start'));
    var warn = state.lang === 'ru' ? svc.warn_ru : svc.warn_en;
    var confirmText = (active ? t('restart_confirm') : t('start_confirm')).split('{unit}');
    var form = h('form', { novalidate: true },
      h('div', { class: 'modal-body' },
        h('p', { class: 'confirm-text' }, confirmText[0], h('b', { text: svc.unit }), confirmText[1] || ''),
        warn ? h('div', { class: 'callout', text: warn }) : null,
        pw.field),
      h('div', { class: 'modal-foot' }, cancel, submit));

    var modal = openModal({ title: active ? t('restart_title') : t('start_title'), sub: svc.unit, content: form, focus: input });

    if (authUnavailableText()) {
      err.textContent = authUnavailableText();
      input.disabled = true;
      submit.disabled = true;
    }

    cancel.addEventListener('click', function () { modal.close(); });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (submit.disabled) return;
      if (!input.value) { err.textContent = t('err_empty_password'); input.focus(); return; }
      err.textContent = '';
      submit.disabled = true; cancel.disabled = true; input.disabled = true; modal.locked = true;
      var spinner = h('span', { class: 'spinner' });
      submit.insertBefore(spinner, submit.firstChild);
      api('/api/services/' + encodeURIComponent(key) + '/restart', { method: 'POST', body: { password: input.value }, timeout: 30000 }).then(function (res) {
        spinner.remove();
        modal.locked = false;
        if (res.status === 202) {
          input.value = '';
          modal.close();
          state.pending[key] = { at: Date.now() };
          toast(t('restart_queued'), t('restart_queued_text', { unit: svc.unit }), 'warn');
          refresh();
          return;
        }
        var d = res.data || {};
        err.textContent = authErrorText(res);
        cancel.disabled = false;
        var permanent = PERMANENT_AUTH_ERRORS.concat(['in_progress']).indexOf(d.error) !== -1;
        input.disabled = permanent;
        submit.disabled = permanent;
        if (!permanent) { input.value = ''; input.focus(); }
      });
    });
  }

  // ------------------------------------------------------------------ log viewer
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // Логи компонентов Kaspersky VM — JSON: {"level":"error",...}; уровень берётся из поля,
  // иначе (текстовые логи, журнал systemd) — по ключевым словам.
  var JSON_LEVEL = /"(?:level|lvl|severity)"\s*:\s*"([a-zA-Z]+)"/;
  var JSON_LEVELS = { error: 'error', err: 'error', fatal: 'error', panic: 'error', critical: 'error', crit: 'error',
    alert: 'error', emerg: 'error', warn: 'warn', warning: 'warn', debug: 'debug', trace: 'debug' };

  function classify(line) {
    var m = JSON_LEVEL.exec(line);
    if (m) return JSON_LEVELS[m[1].toLowerCase()] || '';
    for (var i = 0; i < LOG_LEVELS.length; i++) if (LOG_LEVELS[i][1].test(line)) return LOG_LEVELS[i][0];
    return '';
  }

  function highlight(li, text, re) {
    clear(li);
    if (!re) { li.textContent = text; return; }
    var last = 0;
    text.replace(re, function (m, off) {
      if (off > last) li.appendChild(document.createTextNode(text.slice(last, off)));
      li.appendChild(h('mark', { text: m }));
      last = off + m.length;
      return m;
    });
    if (last < text.length) li.appendChild(document.createTextNode(text.slice(last)));
  }

  /** Галочка «Перенос строк»: одна для обычного просмотра и Real-time, выбор запоминается. */
  function wrapToggle(view) {
    var cb = h('input', { type: 'checkbox', class: 'wrap-toggle' });
    cb.checked = store('wrap') === '1';
    view.classList.toggle('wrap', cb.checked);
    cb.addEventListener('change', function () {
      view.classList.toggle('wrap', cb.checked);
      store('wrap', cb.checked ? '1' : '0');
    });
    return h('label', { class: 'check', title: t('lv_wrap_title') }, cb, h('span', { text: t('lv_wrap') }));
  }

  /** Уровень строки события SIEM — по важности CEF (1–5): 5–4 ошибка, 3 предупреждение. */
  var CEF_SEV = /CEF:0\|(?:[^|\\]|\\.)*\|(?:[^|\\]|\\.)*\|(?:[^|\\]|\\.)*\|(?:[^|\\]|\\.)*\|(?:[^|\\]|\\.)*\|(\d+)\|/;

  function classifySiem(line) {
    var m = CEF_SEV.exec(line);
    var sev = m ? Number(m[1]) : 0;
    return sev >= 4 ? 'error' : sev === 3 ? 'warn' : '';
  }

  function openLogViewer(src) {
    var siem = src.kind === 'siem';
    var lv = { lines: [], count: siem ? 200 : 50, data: null };
    var view = h('div', { class: 'log-view', tabindex: '0' });
    var meta = h('span', { class: 'log-meta' });
    var linesSel = h('select', { class: 'select', 'aria-label': t('lv_lines') },
      (siem ? [50, 100, 200, 500] : [50, 100, 200, 500, 1000]).map(function (n) {
        return h('option', { value: String(n), text: (siem ? t('lv_events') : t('lv_lines')) + ': ' + n });
      }));
    linesSel.value = String(lv.count);
    var ph = siem ? t('lv_filter_siem') : t('lv_filter');
    var filter = h('input', { type: 'search', class: 'input', placeholder: ph, 'aria-label': ph });
    var btnRefresh = h('button', { type: 'button', class: 'btn btn-sm' }, icon('restart'), t('lv_refresh'));
    var btnCopy = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, icon('copy'), t('lv_copy'));
    var btnDl = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, icon('download'), t('lv_download'));

    var content = h('div', { class: 'modal-content' });
    append(content, [
      h('div', { class: 'log-tools' }, linesSel, filter, wrapToggle(view),
        h('span', { class: 'spacer' }), btnRefresh, btnCopy, btnDl),
      view,
      h('div', { class: 'modal-foot' }, meta, h('span', { class: 'spacer' }))
    ]);

    var modal = openModal({ title: src.title, content: content, size: 'lg', focus: view, onClose: function () {
      if (state.siemViewer === reload) state.siemViewer = null;
    } });
    function reload() { if (!btnRefresh.disabled) load(); }
    if (siem) state.siemViewer = reload;  // новые события подгружаются вместе с циклом обновления

    function renderLines(scrollBottom) {
      var q = filter.value.trim();
      var re = q ? new RegExp(escapeRe(q), 'gi') : null;
      clear(view);
      if (!lv.lines.length) { view.appendChild(h('div', { class: 'log-empty', text: t('lv_empty') })); return; }
      var ol = h('ol', { class: 'log-lines' });
      var matches = 0;
      lv.lines.forEach(function (line, i) {
        var li = h('li', { 'data-n': String(i + 1) });
        var lvl = siem ? classifySiem(line) : classify(line);
        if (lvl) li.className = 'lv-' + lvl;
        if (re) {
          re.lastIndex = 0;
          if (!re.test(line)) li.classList.add('hidden');
          else matches++;
          re.lastIndex = 0;
        }
        highlight(li, line, re);
        ol.appendChild(li);
      });
      view.appendChild(ol);
      if (re && !matches) view.appendChild(h('div', { class: 'log-empty', text: t('lv_no_match', { q: q }) }));
      updateMeta(re ? matches : null);
      if (scrollBottom) view.scrollTop = view.scrollHeight;
    }

    function updateMeta(matches) {
      var d = lv.data;
      if (!d) return;
      var time = fmtClock(new Date());
      var txt = d.kind === 'file'
        ? t('lv_meta', { n: d.lines.length, size: fmtBytes(d.size), mtime: fmtDate(d.mtime), time: time })
        : d.kind === 'siem' ? t('lv_meta_siem', { n: d.lines.length, total: d.total, time: time })
          : t('lv_meta_journal', { n: d.lines.length, time: time });
      if (matches !== null && matches !== undefined) txt += ' · ' + t('lv_matches', { n: matches });
      meta.textContent = txt;
    }

    function load() {
      var atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
      if (!lv.data) { clear(view); view.appendChild(h('span', { class: 'spinner' })); }
      btnRefresh.disabled = true;
      var url = siem ? '/api/siem/events?lines=' + lv.count
        : '/api/logs/' + src.kind + '/' + encodeURIComponent(src.key) + '?lines=' + lv.count;
      return api(url).then(function (res) {
        btnRefresh.disabled = false;
        if (!res.ok || !res.data) {
          var d = res.data || {};
          var known = d.error && I18N.ru['lv_err_' + d.error] !== undefined;
          var msg = known ? t('lv_err_' + d.error) : (d.message || d.error || res.status || t('err_network'));
          clear(view);
          view.appendChild(h('div', { class: 'log-empty', text: t('lv_error', { msg: msg }) }));
          return;
        }
        lv.data = res.data;
        lv.lines = res.data.lines || [];
        renderLines(!lv.loaded || atBottom);
        lv.loaded = true;
      });
    }

    linesSel.addEventListener('change', function () { lv.count = Number(linesSel.value); load(); });
    filter.addEventListener('input', function () { renderLines(false); });
    btnRefresh.addEventListener('click', load);
    btnCopy.addEventListener('click', function () { copyText(lv.lines.join('\n')); });
    btnDl.addEventListener('click', function () {
      var blob = new Blob([lv.lines.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
      var a = h('a', { href: URL.createObjectURL(blob), download: src.key + '-' + new Date().toISOString().replace(/[:.]/g, '-') + '.log' });
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    });
    load();
    return modal;
  }

  // ------------------------------------------------------------------ Real-time
  var LIVE_MAX = 5000;  // строк в окне; более старые удаляются

  function openLiveViewer(src) {
    var lv = { es: null, running: false, opened: false, total: 0, items: [], since: null, timer: null };
    var ol = h('ol', { class: 'log-lines' });
    var waiting = h('div', { class: 'log-empty', text: t('live_waiting') });
    var view = h('div', { class: 'log-view', tabindex: '0' }, ol, waiting);
    var jump = h('button', { type: 'button', class: 'btn btn-sm btn-primary live-jump', hidden: true }, t('live_jump'));
    var statusText = h('span', { class: 'live-text' });
    var status = h('span', { class: 'live-status', role: 'status' }, h('span', { class: 'live-dot' }), statusText);
    var ph = t('lv_filter');
    var filter = h('input', { type: 'search', class: 'input', placeholder: ph, 'aria-label': ph });
    var btnToggle = h('button', { type: 'button', class: 'btn btn-sm live-toggle' });
    var btnClear = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, icon('trash'), t('live_clear'));
    var btnCopy = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, icon('copy'), t('lv_copy'));
    var btnDl = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, icon('download'), t('lv_download'));
    var meta = h('span', { class: 'log-meta' });
    var notice = h('span', { class: 'live-notice' });
    var content = h('div', { class: 'modal-content' },
      h('div', { class: 'log-tools' }, status, filter, wrapToggle(view), h('span', { class: 'spacer' }), btnToggle, btnClear, btnCopy, btnDl),
      h('div', { class: 'log-wrap' }, view, jump),
      h('div', { class: 'modal-foot' }, meta, h('span', { class: 'spacer' }), notice));
    var modal = openModal({ title: src.title, sub: t('live_sub'), content: content, size: 'lg', focus: view,
      onClose: function () { stop(); } });

    function setStatus(st, text) {
      status.setAttribute('data-state', st);
      statusText.textContent = text || t('live_' + st);
      clear(btnToggle);
      var on = st === 'running' || st === 'connecting' || st === 'reconnecting';
      append(btnToggle, on ? [icon('stop'), t('live_stop')] : [icon('play'), t('live_resume')]);
      btnToggle.className = 'btn btn-sm live-toggle' + (on ? ' btn-danger-soft' : ' btn-primary');
    }

    function currentRe() {
      var q = filter.value.trim();
      return q ? new RegExp(escapeRe(q), 'gi') : null;
    }

    function paint(item, re) {
      var hit = true;
      if (re) { re.lastIndex = 0; hit = re.test(item.text); re.lastIndex = 0; }
      item.li.classList.toggle('hidden', !hit);
      highlight(item.li, item.text, hit ? re : null);
      return hit;
    }

    function updateMeta() {
      var txt = lv.since ? t('live_meta', { n: lv.total, time: fmtClock(lv.since) }) : '';
      var re = currentRe();
      if (re) txt += (txt ? ' · ' : '') + t('lv_matches', { n: lv.items.filter(function (i) { return !i.li.classList.contains('hidden'); }).length });
      meta.textContent = txt;
    }

    function atBottom() { return view.scrollHeight - view.scrollTop - view.clientHeight < 40; }

    function addLines(lines, cls) {
      var stick = atBottom();
      var re = currentRe();
      lines.forEach(function (text) {
        var li = h('li', { 'data-n': cls ? '' : String(++lv.total) });
        var lvl = cls || classify(text);
        if (lvl) li.className = cls ? lvl : 'lv-' + lvl;
        var item = { li: li, text: text };
        paint(item, re);
        ol.appendChild(li);
        lv.items.push(item);
      });
      while (lv.items.length > LIVE_MAX) lv.items.shift().li.remove();
      waiting.hidden = lv.items.length > 0;
      if (stick) view.scrollTop = view.scrollHeight;
      else jump.hidden = false;
      updateMeta();
    }

    function stop(text) {
      lv.running = false;
      clearTimeout(lv.timer);
      if (lv.es) { lv.es.close(); lv.es = null; }
      setStatus('stopped');
      if (text !== undefined) notice.textContent = text;
    }

    function connectFailed(url) {
      // ответ не поток (ошибка до начала) — узнаём причину обычным запросом
      api(url, { timeout: 5000 }).then(function (res) {
        var d = res.data || {};
        var msg = d.error === 'too_many_streams' ? t('err_too_many_streams', { n: d.limit })
          : d.error && I18N.ru['lv_err_' + d.error] !== undefined ? t('lv_err_' + d.error)
            : d.error || (res.status ? 'HTTP ' + res.status : t('err_network'));
        stop(t('live_connect_failed', { msg: msg }));
      });
    }

    function start() {
      if (lv.es) lv.es.close();
      var url = '/api/logs/live/' + src.kind + '/' + encodeURIComponent(src.key) + '?lines=' + (lv.opened ? 0 : 50);
      lv.running = true;
      notice.textContent = '';
      setStatus(lv.opened ? 'reconnecting' : 'connecting');
      var es = new EventSource(url);
      var gotData = false;
      lv.es = es;
      es.addEventListener('meta', function () {
        gotData = true;
        lv.opened = true;
        if (!lv.since) lv.since = new Date();
        setStatus('running');
        updateMeta();
      });
      es.addEventListener('lines', function (e) { addLines(JSON.parse(e.data)); });
      es.addEventListener('switch', function (e) {
        var d = JSON.parse(e.data);
        addLines([t('live_switch', { path: d.path })], 'live-sep');
      });
      es.addEventListener('end', function (e) {
        var d = JSON.parse(e.data);
        stop(t('live_end_' + d.reason) === 'live_end_' + d.reason ? '' : t('live_end_' + d.reason));
      });
      es.onerror = function () {
        if (lv.es !== es) return;
        es.close();
        lv.es = null;
        if (!lv.running) return;
        if (!gotData && !lv.opened) { connectFailed(url); return; }
        // связь прервалась: переподключаемся без повтора уже показанных строк
        setStatus('reconnecting');
        lv.timer = setTimeout(function () { if (lv.running) start(); }, 2000);
      };
    }

    btnToggle.addEventListener('click', function () { if (lv.running) stop(''); else start(); });
    btnClear.addEventListener('click', function () {
      lv.items.forEach(function (i) { i.li.remove(); });
      lv.items = [];
      waiting.hidden = false;
      jump.hidden = true;
      updateMeta();
    });
    filter.addEventListener('input', function () {
      var re = currentRe();
      lv.items.forEach(function (i) { paint(i, re); });
      updateMeta();
    });
    view.addEventListener('scroll', function () { if (atBottom()) jump.hidden = true; });
    jump.addEventListener('click', function () { view.scrollTop = view.scrollHeight; jump.hidden = true; view.focus(); });
    btnCopy.addEventListener('click', function () { copyText(lv.items.map(function (i) { return i.text; }).join('\n')); });
    btnDl.addEventListener('click', function () {
      var blob = new Blob([lv.items.map(function (i) { return i.text; }).join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
      var a = h('a', { href: URL.createObjectURL(blob), download: src.key + '-realtime-' + new Date().toISOString().replace(/[:.]/g, '-') + '.log' });
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    });
    start();
    return modal;
  }

  // ------------------------------------------------------------------ preferences
  function setLang(lang) {
    if (lang === state.lang) return;
    state.lang = lang;
    setCookie('kvm_lang', lang);
    applyI18n();
    render();
    renderLogs();
    renderReports();
    renderSiem();
    if (!state.data) document.title = t('title');
  }

  function setTheme(theme) {
    state.theme = theme;
    root.setAttribute('data-theme', theme);
    setCookie('kvm_theme', theme);
  }

  function setPortsOpen(open) {
    state.portsOpen = open;
    $('ports-toggle').setAttribute('aria-expanded', String(open));
    $('ports-body').hidden = !open;
    $('ports-panel').classList.toggle('collapsed', !open);
    store('portsOpen', open ? '1' : '0');
    if (open && state.data) renderPorts(state.data);
  }

  function setFilter(filter) {
    state.filter = filter;
    document.querySelectorAll('[data-filter]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-filter') === filter)); });
    store('filter', filter);
    if (state.data) renderServices(state.data);
  }

  // ------------------------------------------------------------------ init
  function init() {
    // Параметры ?lang= / ?theme= уже применены сервером — убираем их из адресной строки.
    if (location.search && window.history && history.replaceState) {
      var url = new URL(location.href);
      url.searchParams.delete('lang');
      url.searchParams.delete('theme');
      history.replaceState(null, '', url.pathname + (url.search || '') + url.hash);
    }
    var savedInterval = store('interval');
    if (savedInterval !== null && ['0', '5', '10', '30', '60'].indexOf(savedInterval) !== -1) state.interval = Number(savedInterval);
    $('interval').value = String(state.interval);
    state.portsOpen = store('portsOpen') === '1';
    state.portsKvm = store('portsKvm') === '1';
    $('ports-kvm').checked = state.portsKvm;

    applyI18n();
    setFilter(store('filter') === 'problems' ? 'problems' : 'all');
    setPortsOpen(state.portsOpen);

    document.querySelectorAll('[data-lang]').forEach(function (b) {
      b.addEventListener('click', function () { setLang(b.getAttribute('data-lang')); });
    });
    document.querySelectorAll('[data-filter]').forEach(function (b) {
      b.addEventListener('click', function () { setFilter(b.getAttribute('data-filter')); });
    });
    $('btn-theme').addEventListener('click', function () { setTheme(state.theme === 'dark' ? 'light' : 'dark'); });
    $('btn-refresh').addEventListener('click', function () { refresh(); loadLogs(); loadSiem(); });
    $('banner-retry').addEventListener('click', function () { refresh(); });
    $('interval').addEventListener('change', function () {
      state.interval = Number($('interval').value);
      store('interval', state.interval);
      schedule();
    });
    $('ports-toggle').addEventListener('click', function () { setPortsOpen(!state.portsOpen); });
    $('ports-filter').addEventListener('input', function (e) { state.portsQuery = e.target.value; if (state.data) renderPorts(state.data); });
    $('ports-kvm').addEventListener('change', function (e) {
      state.portsKvm = e.target.checked;
      store('portsKvm', state.portsKvm ? '1' : '0');
      if (state.data) renderPorts(state.data);
    });
    $('btn-reports-all').addEventListener('click', function () {
      var reports = (state.logs && state.logs.reports) || [];
      var allSelected = Object.keys(state.selectedReports).length === reports.length;
      state.selectedReports = {};
      if (!allSelected) reports.forEach(function (r) { state.selectedReports[r.name] = true; });
      renderReports();
    });
    $('btn-reports-dl').addEventListener('click', downloadReports);
    var reportNow = $('btn-report-now');
    reportNow.insertBefore(icon('report'), reportNow.firstChild);
    reportNow.addEventListener('click', downloadReportNow);
    var siemBtn = $('btn-siem');
    siemBtn.insertBefore(icon('settings'), siemBtn.firstChild);
    siemBtn.addEventListener('click', openSiemDialog);
    document.querySelectorAll('.th-sort').forEach(function (b) {
      b.addEventListener('click', function () { setPortsSort(b.getAttribute('data-sort')); });
    });
    var today = $('btn-logs-today');
    today.insertBefore(icon('download'), today.firstChild);
    today.addEventListener('click', function () {
      today.disabled = true;
      toast(t('logs_today_started'), '', 'ok', 4000);
      location.href = '/logs-today';
      setTimeout(function () { today.disabled = false; }, 5000);
    });
    var day = $('btn-logs-day');
    day.insertBefore(icon('calendar'), day.firstChild);
    day.addEventListener('click', openLogsDayDialog);

    document.addEventListener('keydown', function (e) {
      if (openModals.length || e.ctrlKey || e.metaKey || e.altKey) return;
      var tag = (e.target && e.target.tagName) || '';
      if (/INPUT|TEXTAREA|SELECT/.test(tag)) return;
      if (e.key === 'r' || e.key === 'R' || e.key === 'к' || e.key === 'К') { e.preventDefault(); refresh(); }
    });
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) { refresh(); } else { schedule(); }
    });
    setInterval(function () {
      if (state.data) restartingServices(state.data).forEach(function (s) {
        var c = state.cards[s.key];
        if (c) c.pill.textContent = t('st_restarting', { s: fmtDuration(s.restart.elapsed + (Date.now() - state.lastOk) / 1000) });
      });
    }, 1000);

    refresh();
    loadLogs();
    loadSiem();
  }

  // Экспорт для UI-тестов (не используется приложением).
  window.KVM = { state: state, t: t, fmtBytes: fmtBytes, fmtDuration: fmtDuration, classify: classify, escapeRe: escapeRe, refresh: refresh,
    sortPorts: sortPorts, fmtServerTime: fmtServerTime, fmtIso: fmtIso, authErrorText: authErrorText, loadSiem: loadSiem, openLiveViewer: openLiveViewer };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
'''

FAVICON_SVG = r'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#1d1d1b"/><circle cx="16" cy="16" r="8" fill="#00a88e"/></svg>
'''

BRAND_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAIAAABMXPacAABJ9ElEQVR42rW9ebxeVXU//F17n3Oe6c43NwMJSSAkDEmYB0UriBQQ"
    "a62KbXGkVOpQq9ahWqdq1Z+1Igq1te2r4lwnEKWAQmWwAjJDGJMQMECmm+SOz3jO2Wu9f5xp7/M8+H7e9/N5r340uXmGc/bZew3f"
    "9V3fRfTXfwoCEUEgIoT0RwAABAiEQCAIiAgAhAWE5M8QEhEIkL8zeyOI0t/n/06ll4hI8rv024TylxAgIIIiJJ9vfa71IQKR9AOy"
    "CwKS64Ug/2XyL9mLiST5KxEBwkKAKMpek95r+l3JB0n6Ccmt5HcGQNJbhSRvVAoCiKSLSeltpi8EZZeYXLZ4+bUBIEpXk5Iry36d"
    "XA1J+knpg5B85bLFKu4TUJQvcd9Pujgi2ROV/GYpX8H0gjlbhfQ5Jt9DzqKLgJxHhPyRFftI7H8FgUglvyQiya8pfTwEwP1t+gmU"
    "fJOUPju9AyFQfsPJU8qWEAzrCpL1EhHyCCTZdSDfy+nDynenpMshyYuKj8m+K3uPpAcmv/Zsn5MQZRcnxSqma0HFpSFdFyiybj67"
    "JYVk9xDyXZS8UaE4bvmZKP4vX8Rsyam0G5A8RCIQJZtX8mVIj2Cyz9JnnW1/QvriYoNDIBCS7OgnG8s5yoLkSRE8iCC/odSmkL2Z"
    "LAuC7OtQfLCwCLKtjOKk5RtBrAcp6Qo761ps5NQOFU89vw5KDz6E4Dx628hQ8ZxgPwMUdy7WehdbILvR1NoI7I9xjjAVf6X0maX3"
    "LpIaltwmu3eZf2NyXCXbKF5yetKPsB9RerfifDGRtbmt67TWy7aZ5GxhSX8l6VYSWOfZ+dA+f0Iqueri5KXPKduQIu77Sn7CuVjK"
    "rVxuwSQ5lATHCLjrWDoxbO8NgBSEISSO60lcq/MUs5vPfADl3sZau3yFqNhw+emmbIELX0LutSbWzP5F2QrnJyM5iI5BI/s4pjYh"
    "MVOO5XcfUuJCi42S3YkUzxv2drfPnO1LbPMg1hNxjontTbOrsa2uWOsp1v7LH0u2ugC8fJNQ8WnJykqxrMnNc/n0lwyUY7VgPVYB"
    "WDLHU/aMWUghxZbMrQqRdXvukWMBQIoyC0pInFryFhHbe6L0dum7cskdbroASSgCFseSUBGuFCc2N1mpFSp5HMuV5+cs/RxJo6A0"
    "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"
    "pjwAAAAASUVORK5CYII="
)

# @@ASSETS-END@@

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
