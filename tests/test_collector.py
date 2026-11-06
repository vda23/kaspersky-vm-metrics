# -*- coding: utf-8 -*-
import os
import threading
import unittest

from helpers import MONO, FakeClock, FakeSystem, TempDir, kvm


def is_status_show(call):
    """Основной опрос состояния (не вызовы автоопределения имени СУБД)."""
    return call[:2] == ["systemctl", "show"] and any("MemoryCurrent" in a for a in call)


def by_key(data):
    return dict((s["key"], s) for s in data["services"])


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeSystem()
        self.collector = kvm.StatusCollector(kvm.SERVICES, runner=self.fake, ttl=60, clock=MONO)

    def test_all_running(self):
        data = self.collector.collect()
        self.assertEqual(data["summary"]["total"], 6)
        self.assertEqual(data["summary"]["running"], 6)
        self.assertTrue(data["summary"]["all_up"])
        svc = by_key(data)["scanner"]
        self.assertEqual(svc["state"], "active")
        self.assertEqual(svc["memory_source"], "cgroup")
        self.assertGreater(svc["memory_bytes"], 0)
        self.assertGreaterEqual(svc["uptime_sec"], 3 * 3600 + 119)
        self.assertLess(svc["uptime_sec"], 3 * 3600 + 130)
        self.assertEqual(data["summary"]["services_memory_bytes"],
                         sum(s["memory_bytes"] for s in data["services"]))
        self.assertEqual(data["version"], kvm.__version__)

    def test_single_systemctl_call_for_all_units(self):
        self.collector.collect()
        show_calls = [c for c in self.fake.calls if is_status_show(c)]
        self.assertEqual(len(show_calls), 1)
        self.assertEqual(len([a for a in show_calls[0] if a.endswith(".service")]), 6)

    def test_stopped_and_failed(self):
        self.fake.stop("kaspersky-vm-vms.service")
        self.fake.stop("kaspersky-vm-worker.service", failed=True)
        data = self.collector.collect()
        s = by_key(data)
        self.assertEqual(s["vms"]["state"], "inactive")
        self.assertEqual(s["worker"]["state"], "failed")
        self.assertEqual(s["worker"]["pid"], 0)
        self.assertEqual(s["worker"]["memory_bytes"], 0)
        self.assertIsNone(s["worker"]["uptime_sec"])
        self.assertEqual(data["summary"]["running"], 4)
        self.assertFalse(data["summary"]["all_up"])

    def test_memory_not_set_does_not_mark_running_service_as_stopped(self):
        # В исходной версии int('[not set]') падал, и работающая служба показывалась «Остановлена».
        self.fake.set("kaspersky-vm-scanner.service", MemoryCurrent="[not set]", TasksCurrent="[not set]")
        svc = by_key(self.collector.collect())["scanner"]
        self.assertEqual(svc["state"], "active")
        self.assertIsNone(svc["tasks"])

    def test_memory_fallback_to_cgroup_rss(self):
        with TempDir() as d:
            cg = os.path.join(d, "cg", "system.slice", "kaspersky-vm-scanner.service")
            os.makedirs(cg)
            with open(os.path.join(cg, "cgroup.procs"), "w") as fh:
                fh.write("101\n102\n103\n")
            for pid, rss in (("101", 1000), ("102", 2000)):
                os.makedirs(os.path.join(d, "proc", pid))
                with open(os.path.join(d, "proc", pid, "status"), "w") as fh:
                    fh.write("Name:\tx\nVmRSS:\t   %d kB\n" % rss)
            collector = kvm.StatusCollector(kvm.SERVICES, runner=self.fake, proc_root=os.path.join(d, "proc"),
                                            cgroup_roots=(os.path.join(d, "missing"), os.path.join(d, "cg")))
            self.fake.set("kaspersky-vm-scanner.service", MemoryCurrent="[not set]")
            svc = by_key(collector.collect())["scanner"]
            self.assertEqual(svc["memory_bytes"], 3000 * 1024)
            self.assertEqual(svc["memory_source"], "rss")

    def test_not_installed_unit(self):
        services = kvm.SERVICES + [{"key": "ghost", "unit": "ghost.service", "desc_ru": "", "desc_en": ""}]
        collector = kvm.StatusCollector(services, runner=self.fake)
        svc = by_key(collector.collect())["ghost"]
        self.assertEqual(svc["state"], "not-found")

    def test_db_connections_only_for_postgres(self):
        s = by_key(self.collector.collect())
        self.assertEqual(s["postgresql"]["db_connections"], 3)
        self.assertNotIn("db_connections", s["scanner"])

    def test_ports_mapped_to_services(self):
        data = self.collector.collect()
        mapping = dict((p["port"], p["service"]) for p in data["ports"] if p["netid"] == "tcp")
        self.assertEqual(mapping[5432], "postgresql")
        self.assertEqual(mapping[22], None)

    def test_systemctl_unavailable(self):
        def runner(args, timeout=5, c_locale=True):
            return kvm.CmdResult(127, "", "No such file")
        data = kvm.StatusCollector(kvm.SERVICES, runner=runner).collect()
        self.assertTrue(all(s["state"] == "unknown" for s in data["services"]))
        self.assertEqual(data["ports"], [])
        self.assertEqual(data["summary"]["running"], 0)

    def test_system_info_shape(self):
        info = self.collector.system_info()
        for key in ("os_name", "cpu_threads", "cpu_percent", "memory", "uptime_sec"):
            self.assertIn(key, info)
        self.assertGreaterEqual(info["cpu_threads"], 1)


class CacheTest(unittest.TestCase):
    def test_ttl_cache_and_invalidate(self):
        fake = FakeSystem()
        clock = FakeClock()
        collector = kvm.StatusCollector(kvm.SERVICES, runner=fake, ttl=1.0, clock=clock)
        collector.get()
        collector.get()
        self.assertEqual(len([c for c in fake.calls if is_status_show(c)]), 1)
        clock.advance(1.5)
        collector.get()
        self.assertEqual(len([c for c in fake.calls if is_status_show(c)]), 2)
        collector.invalidate()
        collector.get()
        self.assertEqual(len([c for c in fake.calls if is_status_show(c)]), 3)
        collector.get(force=True)
        self.assertEqual(len([c for c in fake.calls if is_status_show(c)]), 4)

    def test_concurrent_requests_collect_once(self):
        fake = FakeSystem()
        collector = kvm.StatusCollector(kvm.SERVICES, runner=fake, ttl=60)
        threads = [threading.Thread(target=collector.get) for _ in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(len([c for c in fake.calls if is_status_show(c)]), 1)


class RunCmdTest(unittest.TestCase):
    def test_success(self):
        res = kvm.run_cmd(["sh", "-c", "printf 'привет'; printf err >&2; exit 3"])
        self.assertEqual(res.rc, 3)
        self.assertEqual(res.out, "привет")
        self.assertEqual(res.err, "err")

    def test_missing_binary(self):
        res = kvm.run_cmd(["/nonexistent/binary"])
        self.assertEqual(res.rc, 127)

    def test_timeout(self):
        res = kvm.run_cmd(["sleep", "5"], timeout=0.2)
        self.assertEqual(res.rc, 124)

    def test_c_locale(self):
        res = kvm.run_cmd(["sh", "-c", "echo $LC_ALL"])
        self.assertEqual(res.out.strip(), "C")
        res = kvm.run_cmd(["sh", "-c", "echo ${SYSTEMD_PAGER}x"], c_locale=False)
        self.assertEqual(res.out.strip(), "x")


if __name__ == "__main__":
    unittest.main()
