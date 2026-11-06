# -*- coding: utf-8 -*-
import unittest

from helpers import SS_LISTEN, SS_TAN, kvm


class OsReleaseTest(unittest.TestCase):
    def test_pretty_name_double_quotes(self):
        self.assertEqual(kvm.parse_os_release('NAME="Debian"\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n'),
                         "Debian GNU/Linux 11 (bullseye)")

    def test_single_quotes_and_comments(self):
        text = "# comment\nPRETTY_NAME='Astra Linux (Orel 2.12.46)'\n"
        self.assertEqual(kvm.parse_os_release(text), "Astra Linux (Orel 2.12.46)")

    def test_fallback_to_name(self):
        self.assertEqual(kvm.parse_os_release("NAME=RED OS\nID=redos\n"), "RED OS")

    def test_unknown(self):
        self.assertEqual(kvm.parse_os_release(""), "Unknown")
        self.assertEqual(kvm.parse_os_release("garbage line\n"), "Unknown")

    def test_value_with_equals(self):
        self.assertEqual(kvm.parse_os_release('PRETTY_NAME="a=b"'), "a=b")


class MeminfoTest(unittest.TestCase):
    SAMPLE = ("MemTotal:       16303428 kB\nMemFree:         1203428 kB\nMemAvailable:    8203428 kB\n"
              "Buffers:          203428 kB\nCached:          6103428 kB\nAnonPages:       7003428 kB\n"
              "HugePages_Total:       0\nbroken line\nEmpty:\n")

    def test_parse_kb_to_bytes(self):
        mi = kvm.parse_meminfo(self.SAMPLE)
        self.assertEqual(mi["MemTotal"], 16303428 * 1024)
        self.assertEqual(mi["HugePages_Total"], 0)
        self.assertNotIn("Empty", mi)

    def test_summary_parts_add_up(self):
        s = kvm.memory_summary(kvm.parse_meminfo(self.SAMPLE))
        kb = 1024
        self.assertEqual(s["total"], 16303428 * kb)
        self.assertEqual(s["free"], 1203428 * kb)
        self.assertEqual(s["used"], (16303428 - 1203428) * kb, "используется = всего - не используется")
        self.assertEqual(s["cache"], (6103428 + 203428) * kb, "кэш = Cached + Buffers (+ SReclaimable)")
        self.assertEqual(s["processes"] + s["cache"], s["used"], "процессы + кэш = используется")
        self.assertEqual(s["used"] + s["free"], s["total"])
        self.assertEqual(s["available"], 8203428 * kb)

    def test_sreclaimable_counted_as_cache(self):
        s = kvm.memory_summary({"MemTotal": 1000, "MemFree": 100, "Cached": 200, "Buffers": 50, "SReclaimable": 30})
        self.assertEqual(s["cache"], 280)
        self.assertEqual(s["processes"], 620)

    def test_summary_without_memavailable(self):
        s = kvm.memory_summary({"MemTotal": 1000, "MemFree": 100, "Buffers": 50, "Cached": 200})
        self.assertEqual(s["available"], 350)
        self.assertEqual(s["used"], 900)
        self.assertEqual(s["processes"], 650)

    def test_cache_never_exceeds_used(self):
        s = kvm.memory_summary({"MemTotal": 1000, "MemFree": 900, "Cached": 500})
        self.assertEqual(s["cache"], 100)
        self.assertEqual(s["processes"], 0)

    def test_free_never_exceeds_total(self):
        s = kvm.memory_summary({"MemTotal": 100, "MemFree": 500})
        self.assertEqual(s["free"], 100)
        self.assertEqual(s["used"], 0)

    def test_summary_empty(self):
        s = kvm.memory_summary({})
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["used"], 0)

    def test_available_never_exceeds_total(self):
        s = kvm.memory_summary({"MemTotal": 100, "MemFree": 100, "MemAvailable": 500})
        self.assertEqual(s["available"], 100)
        self.assertEqual(s["used"], 0)


class SmallParsersTest(unittest.TestCase):
    def test_uptime(self):
        self.assertEqual(kvm.parse_uptime("12345.67 4000.00\n"), 12345)
        self.assertIsNone(kvm.parse_uptime(""))
        self.assertIsNone(kvm.parse_uptime("abc"))

    def test_cpu_times(self):
        text = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0\n"
        self.assertEqual(kvm.parse_cpu_times(text), (150, 1000))
        self.assertIsNone(kvm.parse_cpu_times(""))
        self.assertIsNone(kvm.parse_cpu_times("cpu a b c d"))
        self.assertIsNone(kvm.parse_cpu_times("cpu 1 2"))
        self.assertEqual(kvm.parse_cpu_times("cpu 10 0 10 80"), (20, 100))

    def test_cpu_percent(self):
        self.assertEqual(kvm.cpu_percent((100, 1000), (150, 1100)), 50.0)
        self.assertEqual(kvm.cpu_percent((100, 1000), (100, 1100)), 0.0)
        self.assertIsNone(kvm.cpu_percent((100, 1000), (100, 1000)))
        self.assertIsNone(kvm.cpu_percent(None, (1, 2)))
        self.assertEqual(kvm.cpu_percent((0, 0), (500, 400)), 100.0, "ограничение сверху")

    def test_to_int(self):
        self.assertEqual(kvm.to_int("123"), 123)
        self.assertEqual(kvm.to_int(" 7 "), 7)
        for value in (None, "", "[not set]", "infinity", "18446744073709551615", "-1", "1.5", "abc"):
            self.assertIsNone(kvm.to_int(value), value)

    def test_clamp_int(self):
        self.assertEqual(kvm.clamp_int("50", 10, 1, 100), 50)
        self.assertEqual(kvm.clamp_int("5000", 10, 1, 100), 100)
        self.assertEqual(kvm.clamp_int("-3", 10, 1, 100), 1)
        self.assertEqual(kvm.clamp_int("abc", 10, 1, 100), 10)
        self.assertEqual(kvm.clamp_int(None, 10, 1, 100), 10)

    def test_strip_ansi(self):
        self.assertEqual(kvm.strip_ansi("\x1b[1;31mERROR\x1b[0m text"), "ERROR text")

    def test_cookies_and_pick(self):
        c = kvm.parse_cookies("a=1; kvm_lang=en ; broken; kvm_theme=light")
        self.assertEqual(c["kvm_lang"], "en")
        self.assertEqual(c["kvm_theme"], "light")
        self.assertEqual(kvm.pick(None, "en", ("ru", "en"), "ru"), "en")
        self.assertEqual(kvm.pick("ru", "en", ("ru", "en"), "ru"), "ru")
        self.assertEqual(kvm.pick("xx", "yy", ("ru", "en"), "ru"), "ru")

    def test_html_escape(self):
        self.assertEqual(kvm.html_escape('<a href="x">\'&'), "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;")

    def test_build_san(self):
        self.assertEqual(kvm.build_san("kvm.corp.local"),
                         "DNS:kvm.corp.local,DNS:kvm,DNS:localhost,IP:127.0.0.1")
        self.assertEqual(kvm.build_san("kvm"), "DNS:kvm,DNS:localhost,IP:127.0.0.1")
        self.assertEqual(kvm.build_san("localhost"), "DNS:localhost,IP:127.0.0.1")


class SystemctlShowTest(unittest.TestCase):
    TEXT = ("Id=a.service\nActiveState=active\nMemoryCurrent=[not set]\n\n"
            "Id=b.service\nActiveState=failed\nExecStart={ path=/bin/x ; argv[]=/bin/x a=b }\n\n\n"
            "Id=c.service\nLoadState=not-found\nActiveState=inactive")

    def test_blocks(self):
        blocks = kvm.parse_systemctl_show(self.TEXT)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[0]["MemoryCurrent"], "[not set]")
        self.assertEqual(blocks[1]["ExecStart"], "{ path=/bin/x ; argv[]=/bin/x a=b }")
        self.assertEqual(blocks[2]["LoadState"], "not-found")

    def test_empty(self):
        self.assertEqual(kvm.parse_systemctl_show(""), [])

    def test_service_state(self):
        self.assertEqual(kvm.service_state({"ActiveState": "active"}), "active")
        self.assertEqual(kvm.service_state({"ActiveState": "failed"}), "failed")
        self.assertEqual(kvm.service_state({"LoadState": "not-found", "ActiveState": "inactive"}), "not-found")
        self.assertEqual(kvm.service_state({"LoadState": "masked", "ActiveState": "inactive"}), "masked")
        self.assertEqual(kvm.service_state({}), "unknown")
        self.assertEqual(kvm.service_state({"LoadState": "loaded"}), "unknown")


class SsTest(unittest.TestCase):
    def test_users(self):
        self.assertEqual(kvm.parse_ss_users('users:(("sshd",pid=812,fd=3),("sshd",pid=813,fd=3))'),
                         [("sshd", 812), ("sshd", 813)])
        self.assertEqual(kvm.parse_ss_users(""), [])
        self.assertEqual(kvm.parse_ss_users(None), [])

    def test_split_port(self):
        self.assertEqual(kvm.split_port("0.0.0.0:22"), 22)
        self.assertEqual(kvm.split_port("[::]:5432"), 5432)
        self.assertEqual(kvm.split_port("*:8999"), 8999)
        self.assertEqual(kvm.split_port("127.0.0.53%lo:53"), 53)
        self.assertIsNone(kvm.split_port("0.0.0.0:*"))
        self.assertIsNone(kvm.split_port("nothing"))

    def test_listen_parsing_and_sort(self):
        ports = kvm.parse_ss_listen(SS_LISTEN)
        self.assertEqual(len(ports), 7)
        self.assertTrue(all(p["netid"] == "tcp" for p in ports[:-1]))
        self.assertEqual(ports[-1]["netid"], "udp")
        tcp_ports = [p["port"] for p in ports if p["netid"] == "tcp"]
        self.assertEqual(tcp_ports, sorted(tcp_ports))
        priv = [p for p in ports if p["port"] == 8443][0]
        self.assertEqual(priv["process"], "kvm-privateapi")
        self.assertEqual(priv["pids"], [1102])

    def test_listen_without_process_column(self):
        text = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
        ports = kvm.parse_ss_listen(text)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["process"], "")
        self.assertEqual(ports[0]["pids"], [])

    def test_count_established_counts_only_server_side(self):
        # Оригинальный код считал ":5432 " в обе стороны и удваивал локальные соединения.
        self.assertEqual(kvm.count_established(SS_TAN, 5432), 3)
        self.assertEqual(kvm.count_established(SS_TAN, 22), 1)
        self.assertEqual(kvm.count_established("", 5432), 0)


class NormalizeLogFilesTest(unittest.TestCase):
    def test_filters_invalid_and_duplicates(self):
        items = [
            {"key": "Scanner", "path": "/var/log/a.log", "title_ru": "Сканер"},
            {"key": "scanner", "path": "/var/log/dup.log"},
            {"key": "../bad", "path": "/etc/shadow"},
            {"key": "nopath"},
            "string",
            {"key": "vms", "path": "/var/log/vms/*.log", "title": "VMS"},
        ]
        result = kvm.normalize_log_files(items)
        self.assertEqual([r["key"] for r in result], ["scanner", "vms"])
        self.assertEqual(result[0]["title_ru"], "Сканер")
        self.assertEqual(result[0]["title_en"], "scanner")
        self.assertEqual(result[1]["title_en"], "VMS")

    def test_none(self):
        self.assertEqual(kvm.normalize_log_files(None), [])


if __name__ == "__main__":
    unittest.main()
