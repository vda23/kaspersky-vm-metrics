# -*- coding: utf-8 -*-
"""Тесты install.sh: функции загружаются через source, системные команды подменяются заглушками."""
import os
import re
import shutil
import stat
import subprocess
import unittest

from helpers import ROOT, TempDir

INSTALL_SH = os.path.join(ROOT, "install.sh")
SCRIPT = os.path.join(ROOT, "kaspersky-vm-metrics.py")


def _version():
    with open(SCRIPT, encoding="utf-8") as fh:
        return re.search(r'^__version__ = "([^"]+)"', fh.read(), re.M).group(1)


NEW_VERSION = _version()
OLD_SCRIPT = "#!/usr/bin/env python3\nimport sys\nif '--version' in sys.argv:\n    print('%s')\n"


def healthz(version):
    return '{"ok":true,"version":"%s"}' % version

# Поддерживаемые ОС: содержимое /etc/os-release (сокращённо) и ожидаемый менеджер пакетов.
# Точные строки отличаются от сборки к сборке; установщик опирается на ID, а для незнакомого ID — на ID_LIKE.
OS_RELEASES = {
    "alt-workstation-11.2-arm64": ('NAME="ALT Workstation"\nID=altlinux\nVERSION_ID=11.2\n'
                                   'PRETTY_NAME="ALT Workstation 11.2"\n', "apt-get"),
    "alt-server-11.0": ('NAME="ALT Server"\nID=altlinux\nVERSION_ID=11.0\nPRETTY_NAME="ALT Server 11.0"\n', "apt-get"),
    "alt-sp-workstation-10": ('NAME="ALT SP Workstation"\nID=altlinux\nVERSION_ID=10\n'
                              'PRETTY_NAME="ALT SP Workstation 10"\n', "apt-get"),
    "alt-sp-server-10": ('NAME="ALT SP Server"\nID=altlinux\nVERSION_ID=10\nPRETTY_NAME="ALT SP Server 10"\n', "apt-get"),
    "redos-8.0": ('NAME="RED OS"\nID="redos"\nVERSION_ID="8.0"\nPRETTY_NAME="RED OS MUROM (8.0.2)"\n', "dnf"),
    "redos-8.0-certified": ('NAME="RED OS"\nID="redos"\nVERSION_ID="8.0"\n'
                            'PRETTY_NAME="RED OS MUROM (8.0.2) Certified Edition"\n', "dnf"),
    "astra-ce-2.12": ('NAME="Astra Linux (Orel)"\nID=astra\nVERSION_ID=2.12\n'
                      'PRETTY_NAME="Astra Linux (Orel 2.12.46)"\n', "apt-get"),
    "astra-se-1.8.5": ('NAME="Astra Linux"\nID=astra\nID_LIKE=debian\nVERSION_ID=1.8_x86-64\n'
                       'PRETTY_NAME="Astra Linux"\nVARIANT_ID=se\n', "apt-get"),
    "debian-13": ('NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'
                  'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n', "apt-get"),
    "sberlinux-9.6": ('NAME="SberLinux OS Server"\nID="sberlinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n'
                      'PRETTY_NAME="Platform V SberLinux OS Server 9.6"\n', "dnf"),
    "ubuntu-24.04": ('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
                     'PRETTY_NAME="Ubuntu 24.04.3 LTS"\n', "apt-get"),
    "ubuntu-26.04": ('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n'
                     'PRETTY_NAME="Ubuntu 26.04 LTS"\n', "apt-get"),
    "unknown": ('ID=foo\nPRETTY_NAME="Foo Linux"\n', "apt-get"),
}
# прежние короткие имена, которые используют тесты
OS_RELEASES["debian"] = OS_RELEASES["debian-13"]
OS_RELEASES["redos"] = OS_RELEASES["redos-8.0"]
OS_RELEASES["astra-ce"] = OS_RELEASES["astra-ce-2.12"]

STUB = """#!/bin/bash
echo "$(basename "$0") $*" >> "$STUB_LOG"
case "$(basename "$0")" in
  iptables) [ "$1" = "-C" ] && exit "${IPTABLES_CHECK_RC:-1}" ;;
  passwd) echo "root ${ROOT_PW_STATUS:-P} 01/01/2026 0 99999 7 -1" ;;
  curl) [ -n "$CURL_BODY" ] && echo "$CURL_BODY" ;;
  systemctl) [ "$1" = "is-active" ] && exit "${SVC_ACTIVE_RC:-0}" ;;
  hostname) echo "kvm.test.local" ;;
  firewall-cmd) [ "$1" = "--state" ] && exit "${FIREWALLD_RC:-1}" ;;
esac
exit 0
"""


class InstallerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.dir = self.tmp.__enter__()
        self.stubs = os.path.join(self.dir, "stubs")
        os.makedirs(self.stubs)
        self.log = os.path.join(self.dir, "calls.log")
        names = ["apt-get", "dnf", "yum", "systemctl", "iptables", "passwd", "curl", "sleep", "hostname",
                 "chcon", "semanage", "getenforce", "journalctl"]
        for name in names:
            self.stub(name)
        self.install_dir = os.path.join(self.dir, "opt")
        self.systemd_dir = os.path.join(self.dir, "systemd")
        os.makedirs(self.systemd_dir)

    def tearDown(self):
        self.tmp.__exit__(None, None, None)

    def stub(self, name, body=STUB):
        path = os.path.join(self.stubs, name)
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, 0o755)

    def unstub(self, name):
        path = os.path.join(self.stubs, name)
        if os.path.exists(path):
            os.remove(path)

    def env(self, **extra):
        env = dict(os.environ)
        # Минимальный PATH: заглушки + базовые утилиты (без ufw/firewall-cmd/getenforce хоста)
        env["PATH"] = self.stubs + ":/usr/local/bin:/usr/bin:/bin"
        if os.environ.get("KVM_TEST_COREUTILS"):  # каталог другой реализации coreutils (uutils — как в Ubuntu 26.04)
            env["PATH"] = self.stubs + ":" + os.environ["KVM_TEST_COREUTILS"] + ":/usr/local/bin:/usr/bin:/bin"
        env.update({"STUB_LOG": self.log, "INSTALL_DIR": self.install_dir, "SYSTEMD_DIR": self.systemd_dir})
        if env.get("KVM_SH_TRACE"):  # покрытие функций install.sh (tests/run_tests.sh --coverage)
            env["BASH_ENV"] = os.path.join(ROOT, "tests", "sh_trace.sh")
        env.update(extra)
        return env

    def bash(self, script, installer=INSTALL_SH, **extra):
        cmd = "set -e; source '%s'; %s" % (installer, script)
        res = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=self.env(**extra), timeout=60)
        return res.returncode, res.stdout.decode("utf-8", "replace")

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            return [line.strip() for line in fh]

    def os_release(self, text):
        path = os.path.join(self.dir, "os-release")
        with open(path, "w") as fh:
            fh.write(text)
        return path


class InstallerTest(InstallerBase):
    # ---------------------------------------------------------------- статические
    def test_syntax(self):
        res = subprocess.run(["bash", "-n", INSTALL_SH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(res.returncode, 0, res.stdout)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        res = subprocess.run(["shellcheck", "-S", "warning", INSTALL_SH], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))

    def test_sourcing_does_not_run_main(self):
        rc, out = self.bash("echo sourced")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "sourced")
        self.assertEqual(self.calls(), [])

    # ---------------------------------------------------------------- ОС и пакеты
    def test_detect_os_and_package_manager_for_all_supported_os(self):
        for name, (text, manager) in sorted(OS_RELEASES.items()):
            if os.path.exists(self.log):
                os.remove(self.log)
            rc, out = self.bash("detect_os; pkg_install python3 python3", OS_RELEASE_FILE=self.os_release(text))
            self.assertEqual(rc, 0, name + ": " + out)
            self.assertIn("ОС: ", out)
            installs = [c for c in self.calls() if " install " in c]
            self.assertTrue(installs and installs[0].startswith(manager), "%s: %s" % (name, self.calls()))

    def test_os_family_by_id_like(self):
        cases = (("ID=neworel\nID_LIKE=debian\n", "apt"), ("ID=rosa\nID_LIKE=\"rhel fedora\"\n", "dnf"),
                 ("ID=sberos\n", "dnf"), ("ID=simply\nID_LIKE=altlinux\n", "apt"), ("ID=gentoo\n", ""))
        for text, family in cases:
            rc, out = self.bash("detect_os >/dev/null; echo FAMILY=$(os_family)",
                                OS_RELEASE_FILE=self.os_release(text + 'PRETTY_NAME="X"\n'))
            self.assertEqual(rc, 0, out)
            self.assertIn("FAMILY=%s\n" % family, out, text)

    def test_architecture(self):
        for arch, warned in (("aarch64", False), ("x86_64", False), ("arm64", False), ("riscv64", True)):
            self.stub("uname", '#!/bin/bash\necho %s\n' % arch)
            rc, out = self.bash("detect_os", OS_RELEASE_FILE=self.os_release(OS_RELEASES["alt-workstation-11.2-arm64"][0]))
            self.assertEqual(rc, 0, out)
            self.assertIn("ALT Workstation 11.2 (%s)" % arch, out)
            self.assertEqual("не проверялась" in out, warned, arch)

    def zps(self, state):
        if state is None:
            self.unstub("astra-digsig-control")
        else:
            self.stub("astra-digsig-control", '#!/bin/bash\n[ "$1" = is-enabled ] && echo %s\n' % state)

    def test_astra_editions_and_closed_software_environment(self):
        cases = (
            ("astra-se-1.8.5", "ACTIVE", "замкнутая программная среда включена", False),
            ("astra-se-1.8.5", "INACTIVE", "Astra Linux SE: замкнутая программная среда выключена", False),
            ("astra-se-1.8.5", None, "Astra Linux SE: замкнутая программная среда выключена", False),
            ("astra-ce-2.12", "INACTIVE", "Astra Linux CE: замкнутая программная среда выключена", False),
            ("astra-ce-2.12", "ACTIVE", "Astra Linux CE в режиме замкнутой программной среды не поддерживается", True),
            ("debian-13", "ACTIVE", "", False),
        )
        for name, state, expected, warned in cases:
            self.zps(state)
            rc, out = self.bash("detect_os >/dev/null; configure_astra_se; echo EDITION=$(astra_edition)",
                                OS_RELEASE_FILE=self.os_release(OS_RELEASES[name][0]))
            self.assertEqual(rc, 0, out)
            if expected:
                self.assertIn(expected, out, (name, state))
            else:
                self.assertNotIn("Astra", out)
            self.assertEqual("[!!]" in out, warned, (name, state, out))
        # редакция без VERSION_ID определяется по /etc/astra/secinfo
        rc, out = self.bash("OS_ID=astra; OS_VERSION=; astra_edition")
        self.assertIn(out.strip(), ("SE", "CE"))

    def test_nftables_only_firewall(self):
        self.unstub("iptables")
        self.stub("nft")
        rc, out = self.bash("configure_firewall")
        self.assertEqual(rc, 0)
        self.assertIn("nftables", out)
        self.assertIn("8999/tcp", out)
        self.assertFalse([c for c in self.calls() if c.startswith("nft")], "правила nft не меняем сами")

    def test_full_install_on_every_supported_os(self):
        """Полная установка с заглушками systemd/пакетов для каждой поддерживаемой ОС."""
        rpm = ("redos-8.0", "redos-8.0-certified", "sberlinux-9.6")
        for name, (text, manager) in sorted(OS_RELEASES.items()):
            if name in ("unknown", "debian", "redos", "astra-ce"):
                continue
            shutil.rmtree(self.install_dir, ignore_errors=True)
            for path in os.listdir(self.systemd_dir):
                os.remove(os.path.join(self.systemd_dir, path))
            if os.path.exists(self.log):
                os.remove(self.log)
            self.stub("uname", '#!/bin/bash\necho %s\n' % ("aarch64" if "arm64" in name else "x86_64"))
            self.stub("getenforce", '#!/bin/bash\necho %s\n' % ("Enforcing" if name in rpm else "Disabled"))
            self.stub("firewall-cmd")
            self.zps("ACTIVE" if name == "astra-se-1.8.5" else None)
            env = self.env(OS_RELEASE_FILE=self.os_release(text), CURL_BODY=healthz(NEW_VERSION),
                           FIREWALLD_RC="0" if name in rpm else "1")
            res = subprocess.run(["bash", INSTALL_SH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 env=env, timeout=120)
            out = res.stdout.decode("utf-8", "replace")
            self.assertEqual(res.returncode, 0, name + "\n" + out)
            self.assertIn("Установка завершена", out, name)
            calls = self.calls()
            self.assertIn("systemctl enable kaspersky-vm-metrics", calls, name)
            if name in rpm:
                self.assertIn("semanage port -a -t http_port_t -p tcp 8999", calls, name)
                self.assertIn("firewall-cmd --add-port=8999/tcp --permanent", calls, name)
            else:
                self.assertIn("iptables -I INPUT -p tcp --dport 8999 -j ACCEPT", calls, name)
            if name == "astra-se-1.8.5":
                self.assertIn("замкнутая программная среда включена", out)
            if "arm64" in name:
                self.assertIn("(aarch64)", out)

    def test_ss_package_names(self):
        self.unstub("sleep")
        rc, _ = self.bash("OS_ID=ubuntu; command() { [ \"$2\" = ss ] && return 1; builtin command \"$@\"; }; install_ss")
        self.assertEqual(rc, 0)
        self.assertIn("apt-get install -y iproute2", self.calls())
        os.remove(self.log)
        rc, _ = self.bash("OS_ID=redos; command() { [ \"$2\" = ss ] && return 1; builtin command \"$@\"; }; install_ss")
        self.assertIn("dnf install -y iproute", self.calls())

    def test_missing_os_release(self):
        rc, out = self.bash("detect_os", OS_RELEASE_FILE=os.path.join(self.dir, "none"))
        self.assertEqual(rc, 1)
        self.assertIn("Не удалось определить ОС", out)

    def test_python_version_check(self):
        rc, out = self.bash("install_python; echo BIN=$PYTHON_BIN")
        self.assertEqual(rc, 0, out)
        self.assertIn("BIN=/", out)
        self.stub("python3", '#!/bin/bash\n[ "$1" = "--version" ] && echo "Python 3.4.10" && exit 0\nexit 1\n')
        rc, out = self.bash("install_python")
        self.assertEqual(rc, 1)
        self.assertIn("Нужен Python >= 3.5", out)

    # ---------------------------------------------------------------- файлы и служба
    def test_install_files(self):
        rc, out = self.bash("install_files")
        self.assertEqual(rc, 0, out)
        script = os.path.join(self.install_dir, "kaspersky-vm-metrics.py")
        font = os.path.join(self.install_dir, "KasperskySans-Regular.ttf")
        self.assertEqual(stat.S_IMODE(os.stat(script).st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(font).st_mode), 0o644)
        self.assertFalse(os.path.exists(os.path.join(self.install_dir, "config.example.json")))
        with open(script, "rb") as a, open(os.path.join(ROOT, "kaspersky-vm-metrics.py"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_install_without_font_does_not_abort(self):
        # В исходной версии chmod отсутствующего шрифта при set -e прерывал установку.
        src = os.path.join(self.dir, "src")
        os.makedirs(src)
        shutil.copy(INSTALL_SH, src)
        shutil.copy(os.path.join(ROOT, "kaspersky-vm-metrics.py"), src)
        rc, out = self.bash("install_files; echo DONE", installer=os.path.join(src, "install.sh"))
        self.assertEqual(rc, 0, out)
        self.assertIn("будет использован системный", out)
        self.assertIn("DONE", out)

    def test_install_without_script_fails(self):
        src = os.path.join(self.dir, "src2")
        os.makedirs(src)
        shutil.copy(INSTALL_SH, src)
        rc, out = self.bash("install_files", installer=os.path.join(src, "install.sh"))
        self.assertEqual(rc, 1)
        self.assertIn("не найден рядом с установщиком", out)

    def test_config_json_preserved_on_reinstall(self):
        os.makedirs(self.install_dir)
        cfg = os.path.join(self.install_dir, "config.json")
        with open(cfg, "w") as fh:
            fh.write('{"log_files": []}')
        rc, _ = self.bash("install_files")
        self.assertEqual(rc, 0)
        with open(cfg) as fh:
            self.assertEqual(fh.read(), '{"log_files": []}')

    def test_unit_file(self):
        rc, out = self.bash("PYTHON_BIN=/usr/bin/python3; create_service")
        self.assertEqual(rc, 0, out)
        with open(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")) as fh:
            unit = fh.read()
        for line in ("Type=simple", "ExecStart=/usr/bin/python3 %s/kaspersky-vm-metrics.py" % self.install_dir,
                     "WorkingDirectory=%s" % self.install_dir, "Restart=always", "RestartSec=5",
                     "WatchdogSec=60", "NotifyAccess=main", "WantedBy=multi-user.target", "After=network.target"):
            self.assertIn(line, unit)
        self.assertIn("systemctl daemon-reload", self.calls())

    # ---------------------------------------------------------------- сеть и безопасность
    def test_iptables_rule_not_duplicated(self):
        rc, _ = self.bash("configure_firewall", IPTABLES_CHECK_RC="1")
        self.assertEqual(rc, 0)
        self.assertIn("iptables -I INPUT -p tcp --dport 8999 -j ACCEPT", self.calls())
        os.remove(self.log)
        self.bash("configure_firewall", IPTABLES_CHECK_RC="0")
        self.assertFalse([c for c in self.calls() if c.startswith("iptables -I")])

    def test_firewalld_used_only_when_running(self):
        self.stub("firewall-cmd")
        self.bash("configure_firewall", FIREWALLD_RC="0")
        self.assertIn("firewall-cmd --add-port=8999/tcp --permanent", self.calls())
        os.remove(self.log)
        self.bash("configure_firewall", FIREWALLD_RC="1")
        self.assertFalse([c for c in self.calls() if "--add-port" in c])
        self.assertTrue([c for c in self.calls() if c.startswith("iptables")])

    def test_selinux(self):
        self.stub("getenforce", '#!/bin/bash\necho Enforcing\n')
        rc, out = self.bash("configure_selinux")
        self.assertEqual(rc, 0)
        self.assertIn("chcon -R -t bin_t %s/" % self.install_dir, self.calls())
        self.assertIn("semanage port -a -t http_port_t -p tcp 8999", self.calls())

    def test_root_password_warning(self):
        for status, warned in (("L", True), ("LK", True), ("NP", True), ("P", False), ("PS", False)):
            rc, out = self.bash("check_root_password", ROOT_PW_STATUS=status)
            self.assertEqual(rc, 0)
            self.assertEqual("passwd root" in out, warned, status)

    # ---------------------------------------------------------------- полный прогон
    def test_full_install_run(self):
        res = subprocess.run(["bash", INSTALL_SH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=self.env(OS_RELEASE_FILE=self.os_release(OS_RELEASES["debian"][0]),
                                          CURL_BODY=healthz(NEW_VERSION)), timeout=120)
        out = res.stdout.decode("utf-8", "replace")
        self.assertEqual(res.returncode, 0, out)
        self.assertIn("Установка завершена", out)
        self.assertIn("Дашборд: https://kvm.test.local:8999/", out)
        calls = self.calls()
        self.assertIn("systemctl enable kaspersky-vm-metrics", calls)
        self.assertIn("systemctl restart kaspersky-vm-metrics", calls)
        self.assertTrue(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")))
        self.assertTrue(os.path.exists(os.path.join(self.install_dir, "kaspersky-vm-metrics.py")))

    def test_full_install_service_down_warns_but_completes(self):
        res = subprocess.run(["bash", INSTALL_SH], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=self.env(OS_RELEASE_FILE=self.os_release(OS_RELEASES["redos"][0]),
                                          SVC_ACTIVE_RC="3", HEALTH_TIMEOUT="2"), timeout=120)
        out = res.stdout.decode("utf-8", "replace")
        self.assertEqual(res.returncode, 0, out)
        self.assertIn("Служба не запустилась", out)
        self.assertIn("Дашборд пока недоступен", out)

    def test_health_without_curl_uses_python(self):
        self.unstub("curl")
        rc, out = self.bash("PORT=1; health_version; echo END")
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "END", "сервис не отвечает -> пустая версия")

    def test_health_version_parsing(self):
        rc, out = self.bash("health_version", CURL_BODY='{"ok":true,"version":"2.2.0"}')
        self.assertEqual(out.strip(), "2.2.0")
        rc, out = self.bash("health_version", CURL_BODY='{"ok": true, "version": "3.0.1"}')
        self.assertEqual(out.strip(), "3.0.1")


class UpdateTest(InstallerBase):
    """Бесшовное обновление, откат, статус."""

    def setUp(self):
        InstallerBase.setUp(self)
        self.stub("ss")  # iproute2 уже есть: при обновлении пакеты не ставятся
        self.osr = self.os_release(OS_RELEASES["debian"][0])

    def install_old(self, version="0.9.0"):
        os.makedirs(self.install_dir, exist_ok=True)
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py"), "w") as fh:
            fh.write(OLD_SCRIPT % version)
        with open(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service"), "w") as fh:
            fh.write("[Unit]\nDescription=old\n")
        keep = {"cert.pem": "CERT", "key.pem": "KEY", "settings.json": '{"siem": {"host": "10.0.0.5"}}',
                "kaspersky-vm-services-state_28_10_2026.txt": "report",
                "kaspersky-vm-services-state_29_10_2026.json": "{}"}
        for name, text in keep.items():
            with open(os.path.join(self.install_dir, name), "w") as fh:
                fh.write(text)
        return keep

    def run_installer(self, *args, **env):
        installer = env.pop("installer", INSTALL_SH)
        env.setdefault("OS_RELEASE_FILE", self.osr)
        env.setdefault("HEALTH_TIMEOUT", "3")
        res = subprocess.run(["bash", installer] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=self.env(**env), timeout=120)
        return res.returncode, res.stdout.decode("utf-8", "replace")

    def installed_script(self):
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py"), encoding="utf-8") as fh:
            return fh.read()

    def backups(self):
        path = os.path.join(self.install_dir, "backup")
        return sorted(os.listdir(path)) if os.path.isdir(path) else []

    def package(self, script_text=None, checksums=None):
        src = os.path.join(self.dir, "pkg")
        os.makedirs(src, exist_ok=True)
        shutil.copy(INSTALL_SH, src)
        font = os.path.join(ROOT, "assets", "KasperskySans-Regular.ttf")
        if os.path.exists(font):
            shutil.copy(font, src)
        if script_text is None:
            shutil.copy(SCRIPT, src)
        else:
            with open(os.path.join(src, "kaspersky-vm-metrics.py"), "w") as fh:
                fh.write(script_text)
        if checksums is not None:
            with open(os.path.join(src, "SHA256SUMS"), "w") as fh:
                fh.write(checksums)
        return os.path.join(src, "install.sh")

    # ------------------------------------------------------------ обновление
    def test_update_keeps_data_and_backs_up(self):
        keep = self.install_old("0.9.0")
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Обновлено: 0.9.0 → %s" % NEW_VERSION, out)
        self.assertIn("Обновление завершено", out)
        self.assertIn("Самопроверка новой версии пройдена", out)
        with open(SCRIPT, encoding="utf-8") as fh:
            self.assertEqual(self.installed_script(), fh.read())
        for name, text in keep.items():
            with open(os.path.join(self.install_dir, name)) as fh:
                self.assertEqual(fh.read(), text, name + " должен сохраниться")
        backups = self.backups()
        self.assertEqual(len(backups), 1)
        self.assertTrue(backups[0].startswith("0.9.0_"))
        with open(os.path.join(self.install_dir, "backup", backups[0], "kaspersky-vm-metrics.py")) as fh:
            self.assertIn("0.9.0", fh.read())
        self.assertTrue(os.path.exists(os.path.join(self.install_dir, "install.sh")), "копия установщика для --rollback")
        calls = self.calls()
        self.assertIn("systemctl restart kaspersky-vm-metrics", calls)
        self.assertFalse([c for c in calls if c.startswith("iptables -I")], "файрвол при обновлении не трогаем")
        self.assertFalse([c for c in calls if " install " in c], "пакеты при обновлении не ставятся")
        with open(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")) as fh:
            self.assertIn("WatchdogSec=60", fh.read(), "unit-файл обновлён")

    def test_failed_update_rolls_back_automatically(self):
        self.install_old("0.9.0")
        # сервис после перезапуска продолжает отвечать старой версией -> новая «не поднялась»
        rc, out = self.run_installer(CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 1, out)
        self.assertIn("откат к 0.9.0", out)
        self.assertIn("восстановлена версия 0.9.0", out)
        self.assertIn("print('0.9.0')", self.installed_script())
        with open(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")) as fh:
            self.assertEqual(fh.read(), "[Unit]\nDescription=old\n", "unit-файл восстановлен")

    def test_failed_update_and_failed_rollback(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer()  # сервис не отвечает вообще
        self.assertEqual(rc, 1)
        self.assertIn("Обновление и откат не удались", out)

    def install_current_assets(self):
        """Установленные шрифт и логотипы совпадают с теми, что лежат в assets/ репозитория."""
        for name in ["KasperskySans-Regular.ttf"] + BRAND_ASSETS:
            path = os.path.join(ROOT, "assets", name)
            if os.path.exists(path):
                shutil.copy(path, self.install_dir)

    def test_same_version_is_noop(self):
        self.install_old(NEW_VERSION)
        shutil.copy(SCRIPT, os.path.join(self.install_dir, "kaspersky-vm-metrics.py"))
        self.install_current_assets()
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("обновление не требуется", out)
        self.assertEqual(self.backups(), [])

    def test_same_version_new_logo_updates_without_force(self):
        self.install_old(NEW_VERSION)
        shutil.copy(SCRIPT, os.path.join(self.install_dir, "kaspersky-vm-metrics.py"))
        self.install_current_assets()
        installer = self.package()
        with open(os.path.join(os.path.dirname(installer), "logo-dark.svg"), "w") as fh:
            fh.write("<svg/>")
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Установлена другая сборка версии %s" % NEW_VERSION, out)
        with open(os.path.join(self.install_dir, "logo-dark.svg")) as fh:
            self.assertEqual(fh.read(), "<svg/>", "логотип установлен")
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertIn("обновление не требуется", out, "повторный запуск — без изменений")

    def test_same_version_other_build_updates_without_force(self):
        keep = self.install_old(NEW_VERSION)  # промежуточная сборка 1.0.0, уже стоящая на сервере
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Установлена другая сборка версии %s" % NEW_VERSION, out)
        self.assertEqual(len(self.backups()), 1)
        with open(SCRIPT, encoding="utf-8") as fh:
            self.assertEqual(self.installed_script(), fh.read())
        for name, text in keep.items():
            with open(os.path.join(self.install_dir, name)) as fh:
                self.assertEqual(fh.read(), text, name)

    def test_force_reinstall_same_version(self):
        self.install_old(NEW_VERSION)
        rc, out = self.run_installer("--force", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.backups()), 1)

    def test_downgrade_requires_force(self):
        self.install_old("9.9.9")
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1)
        self.assertIn("старее установленной", out)
        self.assertIn("9.9.9", self.installed_script())
        rc, out = self.run_installer("--force", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)

    def test_logos_installed_backed_up_and_restored(self):
        self.install_old("0.9.4")
        installer = self.package()
        src = os.path.dirname(installer)
        os.makedirs(os.path.join(src, "assets"))
        with open(os.path.join(src, "assets", "logo-dark.svg"), "w") as fh:
            fh.write("<svg/>")
        with open(os.path.join(src, "favicon.png"), "w") as fh:
            fh.write("png")
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Логотип logo-dark.svg установлен", out)
        for name in ("logo-dark.svg", "favicon.png"):
            path = os.path.join(self.install_dir, name)
            self.assertTrue(os.path.exists(path), name)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        # следующее обновление сохраняет логотипы в резервной копии
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py"), "w") as fh:
            fh.write(OLD_SCRIPT % "0.9.4")
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        backup = [b for b in self.backups() if b.startswith("0.9.4_")][-1]
        self.assertTrue(os.path.exists(os.path.join(self.install_dir, "backup", backup, "logo-dark.svg")))
        os.remove(os.path.join(self.install_dir, "logo-dark.svg"))
        rc, out = self.run_installer("--rollback", CURL_BODY=healthz("0.9.4"))
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.exists(os.path.join(self.install_dir, "logo-dark.svg")), "логотип восстановлен")

    def test_font_from_assets_dir(self):
        rc, out = self.bash("mkdir -p '%s/a/assets'; echo f > '%s/a/assets/KasperskySans-Regular.ttf'; "
                            "SRC_DIR='%s/a'; asset_path KasperskySans-Regular.ttf" % (self.dir, self.dir, self.dir))
        self.assertEqual(out.strip(), "%s/a/assets/KasperskySans-Regular.ttf" % self.dir)

    def test_preflight_failure_leaves_installation_untouched(self):
        self.install_old("0.9.0")
        broken = "import sys\nif '--version' in sys.argv:\n    print('9.0.0')\n    sys.exit(0)\nraise SystemExit('boom')\n"
        rc, out = self.run_installer(installer=self.package(script_text=broken), CURL_BODY=healthz("9.0.0"))
        self.assertEqual(rc, 1)
        self.assertIn("Самопроверка новой версии не пройдена", out)
        self.assertIn("0.9.0", self.installed_script())
        self.assertEqual(self.backups(), [])
        self.assertNotIn("systemctl restart kaspersky-vm-metrics", self.calls())

    def test_checksum_mismatch_rejected(self):
        self.install_old("0.9.0")
        installer = self.package(checksums="0" * 64 + "  kaspersky-vm-metrics.py\n")
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1)
        self.assertIn("Пакет повреждён", out)
        self.assertIn("0.9.0", self.installed_script())

    def test_checksum_mismatch_detected_even_if_sha256sum_exits_zero(self):
        # uutils coreutils (Ubuntu 26.04) при несовпадении в режиме -c печатает FAILED, но возвращает 0
        self.install_old("0.9.0")
        installer = self.package(checksums="0" * 64 + "  kaspersky-vm-metrics.py\n")
        self.stub("sha256sum", '#!/bin/bash\necho "1111111111111111111111111111111111111111111111111111111111111111  $1"\nexit 0\n')
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1, out)
        self.assertIn("Контрольная сумма не совпадает: kaspersky-vm-metrics.py", out)
        self.assertIn("0.9.0", self.installed_script())

    def test_valid_checksums_accepted(self):
        self.install_old("0.9.0")
        installer = self.package()
        src = os.path.dirname(installer)
        sums = subprocess.run(["sha256sum", "install.sh", "kaspersky-vm-metrics.py"],
                              cwd=src, stdout=subprocess.PIPE).stdout.decode()
        with open(os.path.join(src, "SHA256SUMS"), "w") as fh:
            fh.write(sums)
        rc, out = self.run_installer(installer=installer, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Целостность пакета подтверждена", out)

    def test_old_backups_pruned(self):
        self.install_old("0.9.0")
        base = os.path.join(self.install_dir, "backup")
        for i in range(5):
            d = os.path.join(base, "1.%d_2026" % i)
            os.makedirs(d)
            os.utime(d, (1000000 + i * 100, 1000000 + i * 100))
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION), KEEP_BACKUPS="3")
        self.assertEqual(rc, 0, out)
        backups = self.backups()
        self.assertEqual(len(backups), 3)
        self.assertTrue(any(b.startswith("0.9.0_") for b in backups), "свежая копия сохраняется")
        self.assertIn("1.4_2026", backups)
        self.assertNotIn("1.0_2026", backups)

    # ------------------------------------------------------------ откат и статус
    def test_rollback_command(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        rc, out = self.run_installer("--rollback", CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 0, out)
        self.assertIn("Откат: %s → 0.9.0" % NEW_VERSION, out)
        self.assertIn("print('0.9.0')", self.installed_script())
        self.assertEqual(self.backups(), [], "использованная копия удаляется")

    def test_rollback_from_installed_copy(self):
        self.install_old("0.9.0")
        self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        rc, out = self.run_installer("--rollback", installer=os.path.join(self.install_dir, "install.sh"),
                                     CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 0, out)

    def test_rollback_without_backups(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer("--rollback")
        self.assertEqual(rc, 1)
        self.assertIn("Резервных копий нет", out)

    def test_status(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer("--status", CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 0, out)
        self.assertIn("Установлена: 0.9.0", out)
        self.assertIn("Работает:    0.9.0", out)
        self.assertIn("нет", out)

    def test_unknown_argument(self):
        rc, out = self.run_installer("--bogus")
        self.assertEqual(rc, 1)
        self.assertIn("Неизвестный параметр", out)

    def test_help(self):
        rc, out = self.run_installer("--help")
        self.assertEqual(rc, 0)
        self.assertIn("--rollback", out)

    def test_unit_rewritten_only_when_changed(self):
        rc, out = self.bash("PYTHON_BIN=/usr/bin/python3; create_service; create_service")
        self.assertEqual(rc, 0, out)
        self.assertIn("не изменилась", out)
        self.assertEqual(self.calls().count("systemctl daemon-reload"), 1)
        self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service.new")))

    def test_version_compare(self):
        for a, b, lt in (("2.1.0", "2.2.0", True), ("2.2.0", "2.10.0", True), ("2.2.0", "2.2.0", False),
                         ("3.0.0", "2.9.9", False), ("2.2", "2.2.1", True)):
            rc, _ = self.bash("version_lt %s %s" % (a, b))
            self.assertEqual(rc == 0, lt, (a, b))


BRAND_ASSETS = ["logo.svg", "logo.png", "logo-dark.svg", "logo-dark.png", "logo-light.svg", "logo-light.png",
                "favicon.svg", "favicon.png"]


class DistTest(InstallerBase):
    """tools/build_dist.sh: архив tar.gz для сервера и установка/обновление из распакованного архива."""

    def setUp(self):
        InstallerBase.setUp(self)
        self.stub("ss")

    def build(self):
        out = os.path.join(self.dir, "dist")
        res = subprocess.run(["bash", os.path.join(ROOT, "tools", "build_dist.sh")], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=dict(os.environ, OUT_DIR=out), timeout=120)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))
        self.assertEqual(sorted(os.listdir(out)), ["kaspersky-vm-metrics-%s.tar.gz" % NEW_VERSION], "ровно один файл")
        return os.path.join(out, "kaspersky-vm-metrics-%s.tar.gz" % NEW_VERSION)

    def unpack(self, archive):
        import tarfile
        dest = os.path.join(self.dir, "unpacked")
        with tarfile.open(archive) as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest, filter="data")
            else:
                tf.extractall(dest)
        return os.path.join(dest, "kaspersky-vm-metrics-%s" % NEW_VERSION)

    def run_installer_from(self, folder, *args, **env):
        env.setdefault("OS_RELEASE_FILE", self.os_release(OS_RELEASES["astra-ce"][0]))
        env.setdefault("CURL_BODY", healthz(NEW_VERSION))
        env.setdefault("HEALTH_TIMEOUT", "3")
        res = subprocess.run(["bash", os.path.join(folder, "install.sh")] + list(args), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=self.env(**env), timeout=120)
        return res.returncode, res.stdout.decode("utf-8", "replace")

    def test_archive_with_official_assets(self):
        import tarfile
        assets = os.path.join(self.dir, "assets")
        os.makedirs(assets)
        for name in ("KasperskySans-Regular.ttf", "logo-dark.svg", "logo-light.svg", "favicon.svg"):
            with open(os.path.join(assets, name), "w") as fh:
                fh.write(name)
        out = os.path.join(self.dir, "dist2")
        res = subprocess.run(["bash", os.path.join(ROOT, "tools", "build_dist.sh")], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=dict(os.environ, OUT_DIR=out, ASSETS_DIR=assets), timeout=120)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))
        with tarfile.open(os.path.join(out, "kaspersky-vm-metrics-%s.tar.gz" % NEW_VERSION)) as tf:
            names = [os.path.basename(n) for n in tf.getnames()]
            sums = tf.extractfile([m for m in tf.getmembers() if m.name.endswith("SHA256SUMS")][0]).read().decode()
        for name in ("logo-dark.svg", "logo-light.svg", "favicon.svg", "KasperskySans-Regular.ttf"):
            self.assertIn(name, names)
            self.assertIn(name, sums, "логотипы и шрифт защищены контрольной суммой")

    def test_archive_without_font_warns(self):
        out = os.path.join(self.dir, "dist3")
        empty = os.path.join(self.dir, "empty-assets")
        os.makedirs(empty)
        res = subprocess.run(["bash", os.path.join(ROOT, "tools", "build_dist.sh")], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=dict(os.environ, OUT_DIR=out, ASSETS_DIR=empty), timeout=120)
        self.assertEqual(res.returncode, 0)
        self.assertIn("не найден — архив без шрифта", res.stdout.decode("utf-8", "replace"))

    def test_archive_contents(self):
        import tarfile
        archive = self.build()
        with tarfile.open(archive) as tf:
            names = sorted(m.name for m in tf.getmembers())
            modes = dict((m.name.split("/")[-1], m.mode & 0o777) for m in tf.getmembers() if m.isfile())
            owners = set((m.uid, m.gid) for m in tf.getmembers())
        prefix = "kaspersky-vm-metrics-%s/" % NEW_VERSION
        expected = ["README.md", "SHA256SUMS", "VERSION", "install.sh", "kaspersky-vm-metrics.py"]
        for asset in ["KasperskySans-Regular.ttf"] + BRAND_ASSETS:  # шрифт и логотипы — если лежат в assets/
            if os.path.exists(os.path.join(ROOT, "assets", asset)):
                expected.append(asset)
        self.assertEqual(names, sorted([prefix.rstrip("/")] + [prefix + n for n in expected]))
        self.assertEqual(modes["install.sh"], 0o755)
        if "KasperskySans-Regular.ttf" in modes:
            self.assertEqual(modes["KasperskySans-Regular.ttf"], 0o644)
        self.assertEqual(owners, {(0, 0)})
        self.assertFalse([n for n in names if "config" in n or ".run" in n], "без config.json и .run")

    def test_install_then_rerun_then_status(self):
        folder = self.unpack(self.build())
        rc, out = self.run_installer_from(folder)
        self.assertEqual(rc, 0, out)
        self.assertIn("Целостность пакета подтверждена", out)
        self.assertIn("Установка завершена", out)
        rc, out = self.run_installer_from(folder)
        self.assertEqual(rc, 0, out)
        self.assertIn("обновление не требуется", out)
        self.assertTrue(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")))
        rc, out = self.run_installer_from(self.install_dir, "--status")
        self.assertEqual(rc, 0, out)
        self.assertIn("Установлена: %s" % NEW_VERSION, out)

    def test_update_over_old_version(self):
        UpdateTest.install_old(self, "0.9.0")
        folder = self.unpack(self.build())
        rc, out = self.run_installer_from(folder)
        self.assertEqual(rc, 0, out)
        self.assertIn("Обновлено: 0.9.0 → %s" % NEW_VERSION, out)

    def test_future_update_without_reinstall(self):
        """Чистая установка 1.0.0 из архива, затем обновление архивом следующей версии той же командой."""
        folder = self.unpack(self.build())
        rc, out = self.run_installer_from(folder)
        self.assertEqual(rc, 0, out)
        kvm_dir = self.install_dir
        with open(os.path.join(kvm_dir, "settings.json"), "w") as fh:
            fh.write('{"siem": {"enabled": true, "host": "10.0.0.5", "port": 5144, "protocol": "tcp"}}')
        # следующая версия: копия исходников с другим номером
        src = os.path.join(self.dir, "next")
        for name in ("install.sh", "kaspersky-vm-metrics.py", "README.md"):
            os.makedirs(src, exist_ok=True)
            shutil.copy(os.path.join(ROOT, name), src)
        shutil.copytree(os.path.join(ROOT, "tools"), os.path.join(src, "tools"))
        shutil.copytree(os.path.join(ROOT, "web"), os.path.join(src, "web"))
        script = os.path.join(src, "kaspersky-vm-metrics.py")
        with open(script, encoding="utf-8") as fh:
            text = fh.read().replace('__version__ = "%s"' % NEW_VERSION, '__version__ = "9.9.1"')
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(text)
        out_dir = os.path.join(self.dir, "dist-next")
        res = subprocess.run(["bash", os.path.join(src, "tools", "build_dist.sh")], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=dict(os.environ, OUT_DIR=out_dir), timeout=120)
        self.assertEqual(res.returncode, 0, res.stdout.decode("utf-8", "replace"))
        import tarfile
        dest = os.path.join(self.dir, "unpacked-next")
        with tarfile.open(os.path.join(out_dir, "kaspersky-vm-metrics-9.9.1.tar.gz")) as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest, filter="data")
            else:  # pragma: no cover (Python < 3.12)
                tf.extractall(dest)
        rc, out = self.run_installer_from(os.path.join(dest, "kaspersky-vm-metrics-9.9.1"), CURL_BODY=healthz("9.9.1"))
        self.assertEqual(rc, 0, out)
        self.assertIn("Обновлено: %s → 9.9.1" % NEW_VERSION, out)
        self.assertNotIn("--force", out.split("Обновлено")[0].split("Установлена версия")[-1])
        with open(os.path.join(kvm_dir, "settings.json")) as fh:
            self.assertIn("10.0.0.5", fh.read(), "настройки SIEM сохранены")
        self.assertTrue(any(b.startswith(NEW_VERSION + "_") for b in os.listdir(os.path.join(kvm_dir, "backup"))))
        calls = self.calls()
        self.assertFalse([c for c in calls if "disable" in c or "uninstall" in c], "служба не удаляется")

    def test_tampered_file_rejected(self):
        UpdateTest.install_old(self, "0.9.0")
        folder = self.unpack(self.build())
        with open(os.path.join(folder, "kaspersky-vm-metrics.py"), "a") as fh:
            fh.write("\n# tampered\n")
        rc, out = self.run_installer_from(folder)
        self.assertEqual(rc, 1)
        self.assertIn("Пакет повреждён", out)
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py")) as fh:
            self.assertIn("0.9.0", fh.read())


class PortTest(InstallerBase):
    """Выбор порта: --port при установке, запоминание при обновлениях, смена, откат, удаление."""

    setUp = UpdateTest.setUp
    install_old = UpdateTest.install_old
    run_installer = UpdateTest.run_installer
    package = UpdateTest.package

    def unit(self):
        with open(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")) as fh:
            return fh.read()

    def install_current(self, port=None):
        args = ["--port", str(port)] if port else []
        rc, out = self.run_installer(*args, CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        return out

    def ss_listening(self, port, process="nginx"):
        self.stub("ss", '#!/bin/bash\necho "State Recv-Q Send-Q Local Peer Process"\n'
                        'echo "LISTEN 0 128 0.0.0.0:%s 0.0.0.0:* users:((\\"%s\\",pid=7,fd=3))"\n' % (port, process))

    def test_default_port(self):
        out = self.install_current()
        self.assertIn("kaspersky-vm-metrics.py --port 8999\n", self.unit())
        self.assertIn("Дашборд: https://kvm.test.local:8999/", out)
        self.assertIn("iptables -I INPUT -p tcp --dport 8999 -j ACCEPT", self.calls())

    def test_install_with_custom_port(self):
        out = self.install_current(9443)
        self.assertIn("kaspersky-vm-metrics.py --port 9443\n", self.unit())
        self.assertIn("Дашборд: https://kvm.test.local:9443/", out)
        calls = self.calls()
        self.assertIn("iptables -I INPUT -p tcp --dport 9443 -j ACCEPT", calls)
        self.assertFalse([c for c in calls if "8999" in c and c.startswith("iptables")], "8999 не открывается")
        self.assertTrue([c for c in calls if c.startswith("curl") and "localhost:9443/healthz" in c],
                        "проверка /healthz — на выбранном порту")

    def test_equals_form_and_selinux(self):
        self.stub("getenforce", '#!/bin/bash\necho Enforcing\n')
        rc, out = self.run_installer("--port=10443", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("--port 10443", self.unit())
        self.assertIn("semanage port -a -t http_port_t -p tcp 10443", self.calls())

    def test_invalid_ports_rejected(self):
        for bad in ("abc", "0", "70000", "08999", "-1", "123456", ""):
            rc, out = self.run_installer("--port", bad)
            self.assertEqual(rc, 1, bad)
            self.assertIn("Недопустимый порт" if bad else "укажите номер порта", out, bad)
            self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")), bad)
        rc, out = self.run_installer("--port")
        self.assertEqual(rc, 1)
        self.assertIn("После --port укажите номер порта", out)

    def test_busy_port_on_install(self):
        self.ss_listening(9443)
        rc, out = self.run_installer("--port", "9443", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1)
        self.assertIn("Порт 9443 уже занят", out)

    def test_port_kept_on_update(self):
        self.install_current(9443)
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py"), "w") as fh:
            fh.write(OLD_SCRIPT % "0.9.0")  # на сервере старая версия
        os.remove(self.log)
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Обновлено: 0.9.0 → %s" % NEW_VERSION, out)
        self.assertIn("Порт сервиса: 9443 (выбран при установке)", out)
        self.assertIn("--port 9443\n", self.unit(), "порт сохранился без повторного --port")
        self.assertIn("Дашборд: https://kvm.test.local:9443/", out)
        self.assertFalse([c for c in self.calls() if c.startswith("iptables")], "межсетевой экран не трогаем")

    def test_change_port_same_version(self):
        self.install_current(9443)
        os.remove(self.log)
        rc, out = self.run_installer("--port", "9555", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Смена порта: 9443 → 9555", out)
        self.assertIn("Порт изменён: 9443 → 9555", out)
        self.assertNotIn("обновление не требуется", out)
        self.assertNotIn("Обновлено:", out, "файлы сервиса не менялись")
        self.assertIn("--port 9555\n", self.unit())
        calls = self.calls()
        self.assertIn("iptables -I INPUT -p tcp --dport 9555 -j ACCEPT", calls)
        self.assertIn("iptables -D INPUT -p tcp --dport 9443 -j ACCEPT", calls, "старый порт закрыт")
        self.assertIn("systemctl restart kaspersky-vm-metrics", calls)
        self.assertIn("Дашборд: https://kvm.test.local:9555/", out)
        # повторный запуск с тем же портом — ничего не меняется
        rc, out = self.run_installer("--port", "9555", CURL_BODY=healthz(NEW_VERSION))
        self.assertIn("обновление не требуется", out)

    def test_change_port_to_busy_port_refused(self):
        self.install_current(9443)
        self.ss_listening(8443, "kvm-privateapi")
        rc, out = self.run_installer("--port", "8443", CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1)
        self.assertIn("Порт 8443 уже занят", out)
        self.assertIn("сервис продолжает работать на 9443", out)
        self.assertIn("--port 9443\n", self.unit())

    def test_failed_port_change_rolls_back(self):
        self.install_current(9443)
        os.remove(self.log)
        # на новом порту сервис не отвечает, на прежнем — отвечает
        self.stub("curl", '#!/bin/bash\necho "curl $*" >> "$STUB_LOG"\n'
                          'case "$*" in *:9443/*) echo \'{"ok":true,"version":"%s"}\' ;; esac\n' % NEW_VERSION)
        rc, out = self.run_installer("--port", "9555", HEALTH_TIMEOUT="2")
        self.assertEqual(rc, 1, out)
        self.assertIn("восстановлена версия", out)
        self.assertIn("--port 9443\n", self.unit(), "прежний порт восстановлен")
        calls = self.calls()
        self.assertIn("iptables -D INPUT -p tcp --dport 9555 -j ACCEPT", calls, "новый порт закрыт после отката")
        self.assertNotIn("iptables -D INPUT -p tcp --dport 9443 -j ACCEPT", calls)

    def test_legacy_unit_without_port_means_8999(self):
        self.install_old("0.9.0")  # unit-файл без --port
        rc, out = self.bash("installed_port")
        self.assertEqual(out.strip(), "8999")
        rc, out = self.run_installer("--status", CURL_BODY=healthz("0.9.0"))
        self.assertIn("Порт:        8999", out)

    def test_banner_shows_action(self):
        rc, out = self.run_installer("--preflight")
        self.assertIn("Kaspersky VM Metrics — Проверка готовности", out)
        out = self.install_current()
        self.assertIn("Kaspersky VM Metrics — Установка", out)
        for args, title in ((["--status"], "Состояние"), (["--diag"], "Диагностика"),
                            ([], "Обновление"), (["--uninstall", "--purge"], "Удаление")):
            env = {"CURL_BODY": healthz(NEW_VERSION), "DIAG_DIR": self.dir}
            rc, out = self.run_installer(*args, **env)
            self.assertIn("Kaspersky VM Metrics — %s" % title, out, args)
            self.assertNotIn("— Установка", out, args)
        self.install_old("0.9.0")
        os.makedirs(os.path.join(self.install_dir, "backup", "0.8.0_2026"))
        rc, out = self.run_installer("--rollback")
        self.assertIn("Kaspersky VM Metrics — Откат", out)

    def test_status_preflight_uninstall_use_installed_port(self):
        self.install_current(9443)
        rc, out = self.run_installer("--status", CURL_BODY=healthz(NEW_VERSION))
        self.assertIn("Порт:        9443 (https://kvm.test.local:9443/)", out)
        self.assertIn("Работает:    %s" % NEW_VERSION, out)
        rc, out = self.run_installer("--preflight")
        self.assertIn("Порт 9443 свободен", out)
        rc, out = self.run_installer("--preflight", "--port", "10443")
        self.assertIn("Порт 10443 свободен", out)
        os.remove(self.log)
        rc, out = self.run_installer("--uninstall")
        self.assertEqual(rc, 0, out)
        calls = self.calls()
        self.assertIn("iptables -D INPUT -p tcp --dport 9443 -j ACCEPT", calls)
        self.assertNotIn("iptables -D INPUT -p tcp --dport 8999 -j ACCEPT", calls)

    def test_rollback_restores_port(self):
        self.install_current(9443)
        with open(os.path.join(self.install_dir, "kaspersky-vm-metrics.py"), "w") as fh:
            fh.write(OLD_SCRIPT % "0.9.0")
        rc, out = self.run_installer("--port", "9555", CURL_BODY=healthz(NEW_VERSION))  # обновление + смена порта
        self.assertEqual(rc, 0, out)
        os.remove(self.log)
        rc, out = self.run_installer("--rollback", CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 0, out)
        self.assertIn("Порт возвращён: 9555 → 9443", out)
        self.assertIn("--port 9443\n", self.unit())
        calls = self.calls()
        self.assertIn("iptables -I INPUT -p tcp --dport 9443 -j ACCEPT", calls)
        self.assertIn("iptables -D INPUT -p tcp --dport 9555 -j ACCEPT", calls)

    def test_help_mentions_port(self):
        rc, out = self.run_installer("--help")
        self.assertEqual(rc, 0)
        self.assertIn("--port 9443", out)
        self.assertIn("--rollback", out)
        self.assertNotIn("Поддерживаемые ОС", out, "справка — только раздел «Использование»")


class OperationsTest(InstallerBase):
    """--preflight, --diag, --uninstall и проверка порта при первой установке."""

    setUp = UpdateTest.setUp
    install_old = UpdateTest.install_old
    run_installer = UpdateTest.run_installer
    package = UpdateTest.package

    def ss_listening(self, process):
        self.stub("ss", '#!/bin/bash\necho "State Recv-Q Send-Q Local Peer Process"\n'
                        'echo "LISTEN 0 128 0.0.0.0:8999 0.0.0.0:* users:((\\"%s\\",pid=7,fd=3))"\n' % process)

    def test_preflight_ready_and_changes_nothing(self):
        rc, out = self.run_installer("--preflight", ROOT_PW_STATUS="P")
        self.assertEqual(rc, 0, out)
        self.assertIn("Сервер готов к установке", out)
        self.assertIn("Режим: первая установка", out)
        self.assertIn("Пароль root задан", out)
        self.assertIn("log worker: /var/log/kaspersky/vulnerability-management/worker/worker.log", out)
        self.assertFalse(os.path.exists(self.install_dir))
        self.assertEqual(os.listdir(self.systemd_dir), [])
        calls = self.calls()
        self.assertFalse([c for c in calls if " install " in c or "restart" in c or "enable" in c], calls)

    def test_preflight_reports_update_mode(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer("--preflight")
        self.assertEqual(rc, 0, out)
        self.assertIn("Режим: обновление 0.9.0 → %s" % NEW_VERSION, out)

    def test_preflight_blocking_problems(self):
        self.ss_listening("nginx")
        broken = self.package(script_text="import sys\nsys.exit(3)\n")
        rc, out = self.run_installer("--preflight", installer=broken, ROOT_PW_STATUS="L")
        self.assertEqual(rc, 1)
        self.assertIn("Сервис не запускается на этом Python", out)
        self.assertIn("Порт 8999 занят другим процессом", out)
        self.assertIn("кнопки перезапуска работать не будут", out)
        self.assertIn("Найдено блокирующих проблем: 2", out)

    def test_fresh_install_refuses_busy_port(self):
        self.ss_listening("nginx")
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 1)
        self.assertIn("Порт 8999 уже занят", out)
        self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")))

    def test_diag_archive(self):
        import tarfile
        self.install_old("0.9.0")
        diag_dir = os.path.join(self.dir, "diag")
        os.makedirs(diag_dir)
        rc, out = self.run_installer("--diag", DIAG_DIR=diag_dir, CURL_BODY=healthz("0.9.0"))
        self.assertEqual(rc, 0, out)
        archives = os.listdir(diag_dir)
        self.assertEqual(len(archives), 1)
        with tarfile.open(os.path.join(diag_dir, archives[0])) as tf:
            names = [os.path.basename(n) for n in tf.getnames()]
            status = tf.extractfile([m for m in tf.getmembers() if m.name.endswith("/status.txt")][0]).read().decode()
        for expected in ("status.txt", "self-check.txt", "journal.txt", "kvm-units.txt", "units-list.txt",
                         "kvm-log-files.txt"):
            self.assertIn(expected, names)
        self.assertNotIn("key.pem", names, "закрытый ключ в диагностику не попадает")
        self.assertIn("Установлена: 0.9.0", status)

    def test_uninstall_keeps_data(self):
        keep = self.install_old("0.9.0")
        self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        rc, out = self.run_installer("--uninstall")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.systemd_dir, "kaspersky-vm-metrics.service")))
        self.assertFalse(os.path.exists(os.path.join(self.install_dir, "kaspersky-vm-metrics.py")))
        self.assertFalse(os.path.exists(os.path.join(self.install_dir, "backup")))
        for name in keep:
            self.assertTrue(os.path.exists(os.path.join(self.install_dir, name)), name)
        calls = self.calls()
        self.assertIn("systemctl stop kaspersky-vm-metrics", calls)
        self.assertIn("systemctl disable kaspersky-vm-metrics", calls)
        self.assertIn("iptables -D INPUT -p tcp --dport 8999 -j ACCEPT", calls)

    def test_uninstall_purge(self):
        self.install_old("0.9.0")
        rc, out = self.run_installer("--uninstall", "--purge")
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(self.install_dir))

    def test_reinstall_after_uninstall_reuses_data(self):
        self.install_old("0.9.0")
        self.run_installer("--uninstall")
        rc, out = self.run_installer(CURL_BODY=healthz(NEW_VERSION))
        self.assertEqual(rc, 0, out)
        self.assertIn("Установка завершена", out)
        with open(os.path.join(self.install_dir, "cert.pem")) as fh:
            self.assertEqual(fh.read(), "CERT", "сертификат прежней установки переиспользуется")


if __name__ == "__main__":
    unittest.main()
