# -*- coding: utf-8 -*-
import os
import sys
import unittest

from helpers import FakeClock, FakeSystem, TempDir, kvm, make_shadow

try:
    from unittest import mock
except ImportError:  # pragma: no cover
    mock = None

SCANNER = kvm.SERVICES[0]


def svc_row(state="active", since=100):
    return {"key": SCANNER["key"], "unit": SCANNER["unit"], "state": state, "since_mono": since, "restart": None}


class RestartManagerTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeSystem()
        self.clock = FakeClock()
        self.rm = kvm.RestartManager(runner=self.fake, clock=self.clock, timeout=60, settle=2)

    def test_start_runs_no_block_restart(self):
        ok, code, _ = self.rm.start(SCANNER, 100, "10.0.0.1")
        self.assertTrue(ok)
        self.assertIsNone(code)
        self.assertIn(["systemctl", "restart", "--no-block", SCANNER["unit"]], self.fake.calls)
        self.assertTrue(self.rm.in_progress("scanner"))

    def test_duplicate_restart_rejected(self):
        self.rm.start(SCANNER, 100, "a")
        ok, code, _ = self.rm.start(SCANNER, 100, "b")
        self.assertFalse(ok)
        self.assertEqual(code, "in_progress")
        restarts = [c for c in self.fake.calls if c[1] == "restart"]
        self.assertEqual(len(restarts), 1)

    def test_systemctl_failure(self):
        self.fake.fail_restart.add(SCANNER["unit"])
        ok, code, message = self.rm.start(SCANNER, 100, "a")
        self.assertFalse(ok)
        self.assertEqual(code, "systemctl_failed")
        self.assertIn("Access denied", message)
        self.assertFalse(self.rm.in_progress("scanner"))

    def test_completion_ok_requires_new_activation(self):
        self.rm.start(SCANNER, 100, "a")
        rows = [svc_row("active", 100)]
        self.rm.annotate(rows)
        self.assertTrue(rows[0]["restart"]["in_progress"])
        self.clock.advance(3)
        rows = [svc_row("active", 100)]   # ещё старый экземпляр
        self.rm.annotate(rows)
        self.assertTrue(rows[0]["restart"]["in_progress"])
        rows = [svc_row("activating", 0)]
        self.rm.annotate(rows)
        self.assertTrue(rows[0]["restart"]["in_progress"])
        rows = [svc_row("active", 555)]
        self.rm.annotate(rows)
        self.assertFalse(rows[0]["restart"]["in_progress"])
        self.assertEqual(rows[0]["restart"]["result"], "ok")
        self.assertFalse(self.rm.in_progress("scanner"))
        rows = [svc_row("active", 555)]
        self.rm.annotate(rows)  # результат остаётся видимым для других клиентов
        self.assertEqual(rows[0]["restart"]["result"], "ok")

    def test_settle_time(self):
        self.rm.start(SCANNER, 0, "a")
        rows = [svc_row("failed", 0)]
        self.rm.annotate(rows)
        self.assertTrue(rows[0]["restart"]["in_progress"], "до settle failed ещё старое состояние")
        self.clock.advance(2.5)
        rows = [svc_row("failed", 0)]
        self.rm.annotate(rows)
        self.assertEqual(rows[0]["restart"]["result"], "failed")

    def test_timeout(self):
        self.rm.start(SCANNER, 100, "a")
        self.clock.advance(61)
        rows = [svc_row("activating", 0)]
        self.rm.annotate(rows)
        self.assertEqual(rows[0]["restart"]["result"], "timeout")

    def test_new_start_clears_previous_result(self):
        self.rm.start(SCANNER, 100, "a")
        self.clock.advance(3)
        self.rm.annotate([svc_row("active", 200)])
        self.assertIn("scanner", self.rm.results)
        self.rm.start(SCANNER, 200, "a")
        self.assertNotIn("scanner", self.rm.results)

    def test_other_services_untouched(self):
        self.rm.start(SCANNER, 100, "a")
        rows = [svc_row(), {"key": "vms", "state": "active", "since_mono": 1, "restart": None}]
        self.rm.annotate(rows)
        self.assertIsNone(rows[1]["restart"])


class CryptTest(unittest.TestCase):
    def test_system_crypt_sha512(self):
        out = kvm.system_crypt("password", "$6$saltsalt$")
        self.assertTrue(out.startswith("$6$saltsalt$"))
        self.assertEqual(kvm.system_crypt("password", out), out)

    @unittest.skipIf(mock is None, "mock unavailable")
    def test_ctypes_fallback_when_crypt_module_missing(self):
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "crypt":
                raise ImportError("removed in 3.13")
            return real_import(name, *args, **kwargs)

        saved = sys.modules.pop("crypt", None)
        try:
            with mock.patch("builtins.__import__", side_effect=fake_import):
                impl = kvm._load_crypt()
        finally:
            if saved is not None:
                sys.modules["crypt"] = saved
        self.assertIsNotNone(impl)
        self.assertEqual(impl("password", "$6$saltsalt$"), kvm.system_crypt("password", "$6$saltsalt$"))

    def test_yescrypt_or_skip(self):
        out = kvm.system_crypt("pw", "$y$j9T$abcdefghijklmnop$")
        if not out or not out.startswith("$y$"):
            self.skipTest("libcrypt without yescrypt")
        self.assertEqual(kvm.system_crypt("pw", out), out)


class RootAuthenticatorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def auth_for(self, **kwargs):
        return kvm.RootAuthenticator(shadow_paths=(make_shadow(self.dir, **kwargs),))

    def test_verify(self):
        auth = self.auth_for(password="S3cret!pass")
        self.assertEqual(auth.status(), "ok")
        self.assertTrue(auth.verify("S3cret!pass"))
        self.assertFalse(auth.verify("S3cret!pas"))
        self.assertFalse(auth.verify("s3cret!pass"))
        self.assertFalse(auth.verify(""))
        self.assertFalse(auth.verify(None))
        self.assertFalse(auth.verify("S3cret!pass\x00"))
        self.assertFalse(auth.verify("x" * 2000))

    def test_cyrillic_password(self):
        auth = self.auth_for(password="Пароль-123")
        self.assertTrue(auth.verify("Пароль-123"))

    def test_locked_accounts(self):
        for value in ("!", "*", "", "!$6$abc$def", "!!", "x"):
            auth = self.auth_for(hash_override=value)
            self.assertEqual(auth.status(), "locked", value)
            self.assertFalse(auth.verify("anything"))

    def test_legacy_des_hash_accepted_as_ok(self):
        self.assertEqual(self.auth_for(hash_override="abJnggxhB/yWI").status(), "ok")

    def test_unavailable(self):
        auth = kvm.RootAuthenticator(shadow_paths=(os.path.join(self.dir, "missing"),))
        self.assertEqual(auth.status(), "unavailable")
        self.assertFalse(auth.verify("x"))

    def test_no_root_line(self):
        path = make_shadow(self.dir, user="admin")
        self.assertEqual(kvm.RootAuthenticator(shadow_paths=(path,)).status(), "unavailable")

    def test_tcb_has_priority(self):
        tcb_dir = os.path.join(self.dir, "tcb")
        os.makedirs(tcb_dir)
        tcb = make_shadow(tcb_dir, password="tcb-pass")
        shadow = make_shadow(self.dir, password="shadow-pass")
        auth = kvm.RootAuthenticator(shadow_paths=(tcb, shadow))
        self.assertTrue(auth.verify("tcb-pass"))
        self.assertFalse(auth.verify("shadow-pass"))

    def test_crypt_failure(self):
        path = make_shadow(self.dir)
        auth = kvm.RootAuthenticator(shadow_paths=(path,), crypt_func=lambda w, s: None)
        self.assertFalse(auth.verify("S3cret!pass"))


class ThrottleTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.th = kvm.LoginThrottle(max_fails=3, window=60, lock=120, clock=self.clock)

    def test_lock_after_max_fails(self):
        self.assertEqual(self.th.retry_after("ip"), 0)
        self.assertEqual(self.th.fail("ip"), 2)
        self.assertEqual(self.th.fail("ip"), 1)
        self.assertEqual(self.th.fail("ip"), 0)
        self.assertGreater(self.th.retry_after("ip"), 100)
        self.assertEqual(self.th.retry_after("other"), 0)

    def test_lock_expires(self):
        for _ in range(3):
            self.th.fail("ip")
        self.clock.advance(121)
        self.assertEqual(self.th.retry_after("ip"), 0)
        self.assertEqual(self.th.fail("ip"), 2, "счётчик сброшен после блокировки")

    def test_window_slides(self):
        self.th.fail("ip")
        self.th.fail("ip")
        self.clock.advance(61)
        self.assertEqual(self.th.fail("ip"), 2)

    def test_success_resets(self):
        self.th.fail("ip")
        self.th.fail("ip")
        self.th.success("ip")
        self.assertEqual(self.th.fail("ip"), 2)


if __name__ == "__main__":
    unittest.main()
