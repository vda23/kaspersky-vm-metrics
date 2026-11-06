# -*- coding: utf-8 -*-
"""
UI-тесты в настоящем браузере (Playwright + Chromium) против сервера с FakeSystem.
Пропускаются, если Playwright не установлен:  pip install playwright && playwright install chromium
Скриншоты: KVM_UI_SCREENSHOTS=/path python3 -m unittest test_ui
"""
import datetime
import json
import os
import re
import sys
import time
import unittest

from helpers import ServerFixture, kvm
from test_reports_siem import Listener, free_port

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

SHOTS = os.environ.get("KVM_UI_SCREENSHOTS")
JS_COVERAGE_FILE = os.environ.get("KVM_JS_COVERAGE")
JS_SOURCE = kvm.APP_JS
JS_COVERED = bytearray(len(JS_SOURCE))  # 1 — символ app.js выполнялся хотя бы в одном тесте


def merge_js_coverage(result):
    """Объединяет покрытие V8 (Profiler.takePreciseCoverage, detailed) для /static/app.js."""
    for script in result.get("result", []):
        if "/static/app.js" not in script.get("url", ""):
            continue
        local = bytearray(len(JS_SOURCE))
        for fn in script["functions"]:
            for rng in fn["ranges"]:
                start, end = rng["startOffset"], min(rng["endOffset"], len(JS_SOURCE))
                if end > start:
                    local[start:end] = (b"\x01" if rng["count"] > 0 else b"\x00") * (end - start)
        for i, flag in enumerate(local):
            if flag:
                JS_COVERED[i] = 1


def js_coverage_summary():
    total = covered = 0
    uncovered_lines = set()
    line = 1
    for i, ch in enumerate(JS_SOURCE):
        if ch == "\n":
            line += 1
            continue
        if ch.isspace():
            continue
        total += 1
        if JS_COVERED[i]:
            covered += 1
        else:
            uncovered_lines.add(line)
    return {"covered": covered, "total": total, "percent": round(covered * 100.0 / max(total, 1), 1),
            "uncovered_lines": sorted(uncovered_lines)}


@unittest.skipIf(sync_playwright is None, "playwright not installed")
class UiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as exc:  # pragma: no cover
            cls.pw.stop()
            raise unittest.SkipTest("chromium unavailable: %s" % exc)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        if JS_COVERAGE_FILE:
            with open(JS_COVERAGE_FILE, "w") as fh:
                json.dump(js_coverage_summary(), fh)

    def setUp(self):
        self.srv = ServerFixture(restart_delay=1.2, settle=0.5)
        self.srv.app.brand = {}  # логотипы из assets/ не влияют на тесты (тест логотипов задаёт их сам)
        self.srv.fake.stop("kaspersky-vm-worker.service", failed=True)
        self.errors = []
        self.ctx = self.browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        self.page = self.ctx.new_page()
        self.page.on("pageerror", lambda e: self.errors.append("pageerror: %s" % e))
        self.page.on("console", self._console)
        self.cdp = None
        if JS_COVERAGE_FILE:
            self.cdp = self.ctx.new_cdp_session(self.page)
            self.cdp.send("Profiler.enable")
            self.cdp.send("Profiler.startPreciseCoverage", {"callCount": False, "detailed": True})
            # перед навигацией сохраняем покрытие: при перезагрузке V8 отбрасывает данные старой страницы
            for name in ("reload", "goto"):
                setattr(self.page, name, self._snapping(getattr(self.page, name)))

    def _snapping(self, method):
        def wrapped(*args, **kwargs):
            self._snap_coverage()
            return method(*args, **kwargs)
        return wrapped

    def _snap_coverage(self):
        if self.cdp is not None:
            try:
                merge_js_coverage(self.cdp.send("Profiler.takePreciseCoverage"))
            except Exception:  # pragma: no cover
                pass

    def _console(self, msg):
        if msg.type == "error" and "401" not in msg.text and "429" not in msg.text:
            self.errors.append("console: %s" % msg.text)

    def tearDown(self):
        self._snap_coverage()
        self.ctx.close()
        self.srv.close()
        self.assertEqual(self.errors, [], "ошибки JS / нарушения CSP в консоли")

    def open(self, query=""):
        self.page.goto(self.srv.base + "/" + query)
        self.page.wait_for_selector(".card[data-key=scanner] .pill")
        return self.page

    def shot(self, name, full=False):
        if SHOTS:
            self.page.screenshot(path=os.path.join(SHOTS, name + ".png"), full_page=full)

    def wait_js(self, expr, timeout=5.0):
        """Аналог wait_for_function без eval (строгий CSP страницы запрещает 'unsafe-eval')."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.page.evaluate(expr):
                return
            self.page.wait_for_timeout(50)
        self.fail("timeout waiting for: " + expr)

    def card(self, key):
        return self.page.locator(".card[data-key=%s]" % key)

    def wait_logs(self):
        """Список лог-файлов загружен: у карточки scanner появилась кнопка «Лог компонента»."""
        self.page.wait_for_selector(".card[data-key=scanner] .btn-log:not([hidden])")

    # ---------------------------------------------------------------- обзор
    def test_dashboard_renders(self):
        page = self.open()
        self.assertEqual(page.locator(".card:not(.skeleton)").count(), 6)
        self.assertEqual(page.locator("#overall").get_attribute("data-state"), "bad")
        self.assertIn("1", page.locator("#overall-title").inner_text())
        self.assertEqual(page.locator("#kpi-services").inner_text(), "5 / 6")
        self.assertEqual(self.card("worker").get_attribute("data-tone"), "bad")
        self.assertEqual(self.card("worker").locator(".pill").inner_text(), "Сбой")
        self.assertEqual(self.card("scanner").locator(".pill").inner_text(), "Работает")
        self.assertIn("Запустить", self.card("worker").locator(".card-actions .btn").first.inner_text())
        self.assertIn("Перезапустить", self.card("scanner").locator(".card-actions .btn").first.inner_text())
        text = self.card("postgresql").inner_text()
        for removed in ("Подключений к БД", "Потоков", "Авто-перезапусков"):
            self.assertNotIn(removed, text)
        self.assertTrue(page.title().startswith("(1) "))
        self.assertIn("data:image/svg+xml", page.locator("#favicon").get_attribute("href"))
        font_ok = page.evaluate("document.fonts.check('12px KasperskySans')")
        self.assertTrue(font_ok, "шрифт KasperskySans должен загружаться")
        self.shot("dashboard-dark", full=True)

    def test_filter_problems(self):
        page = self.open()
        page.click("[data-filter=problems]")
        self.assertTrue(self.card("worker").is_visible())
        self.assertFalse(self.card("scanner").is_visible())
        page.reload()
        page.wait_for_selector(".card[data-key=worker] .pill")
        self.assertFalse(self.card("scanner").is_visible(), "фильтр запоминается")
        page.click("[data-filter=all]")
        self.assertTrue(self.card("scanner").is_visible())

    def test_language_and_theme_switch_without_reload(self):
        page = self.open()
        page.evaluate("window.__marker = 1")
        page.click("[data-lang=en]")
        self.assertEqual(self.card("worker").locator(".pill").inner_text(), "Failed")
        self.assertEqual(page.locator("html").get_attribute("lang"), "en")
        self.assertIn("Monitoring", page.title())
        page.click("#btn-theme")
        self.assertEqual(page.locator("html").get_attribute("data-theme"), "light")
        self.assertEqual(page.evaluate("window.__marker"), 1, "страница не перезагружалась")
        self.shot("dashboard-light-en", full=True)
        page.reload()
        page.wait_for_selector(".card .pill")
        self.assertEqual(page.locator("html").get_attribute("data-theme"), "light", "тема сохранена в cookie")
        self.assertEqual(page.locator("html").get_attribute("lang"), "en")

    def test_legacy_query_params(self):
        page = self.open("?lang=en&theme=light")
        self.assertEqual(page.locator("html").get_attribute("data-theme"), "light")
        self.assertNotIn("lang=", page.url, "параметры убираются из адресной строки")

    # ---------------------------------------------------------------- перезапуск
    def test_restart_flow_with_root_password_and_auto_refresh(self):
        page = self.open()
        self.card("worker").locator(".card-actions .btn").first.click()
        dialog = page.locator("[role=dialog]")
        self.assertIn("kaspersky-vm-worker.service", dialog.inner_text())
        self.wait_js("document.activeElement.id === 'root-pw'")  # фокус в поле пароля
        page.keyboard.press("Enter")
        self.assertIn("Введите пароль", dialog.locator(".field-error").inner_text())
        page.fill("#root-pw", "wrong")
        page.keyboard.press("Enter")
        page.wait_for_selector(".field-error:has-text('Осталось попыток: 2')")
        self.assertEqual(page.input_value("#root-pw"), "", "поле очищается после ошибки")
        self.shot("restart-dialog-error")
        page.fill("#root-pw", ServerFixture.PASSWORD)
        page.keyboard.press("Enter")
        page.wait_for_selector("[role=dialog]", state="detached")
        # автообновление: без ручного обновления карточка проходит «Перезапуск…» -> «Работает»
        page.wait_for_selector(".card[data-key=worker] .pill[data-busy=true]", timeout=5000)
        self.shot("restart-in-progress")
        page.wait_for_selector(".card[data-key=worker] .pill:text-is('Работает')", timeout=15000)
        page.wait_for_selector(".toast:has-text('Служба перезапущена')", timeout=5000)
        self.assertEqual(page.locator("#kpi-services").inner_text(), "6 / 6")
        self.assertEqual(page.locator("#overall").get_attribute("data-state"), "ok")
        self.assertIn("4242", self.card("worker").inner_text())

    def test_restart_failed_start_toast(self):
        self.srv.fake.crash_on_start.add("kaspersky-vm-vms.service")
        page = self.open()
        self.card("vms").locator(".card-actions .btn").first.click()
        self.assertIn("перезапущена", page.locator("[role=dialog] .confirm-text").inner_text())
        page.fill("#root-pw", ServerFixture.PASSWORD)
        page.click("[role=dialog] button[type=submit]")
        page.wait_for_selector(".toast:has-text('не запустилась')", timeout=15000)
        self.assertEqual(self.card("vms").locator(".pill").inner_text(), "Сбой")

    def test_postgres_restart_shows_warning(self):
        page = self.open()
        self.card("postgresql").locator(".card-actions .btn").first.click()
        self.assertIn("потеряют", page.locator("[role=dialog] .callout").inner_text())
        page.keyboard.press("Escape")
        page.wait_for_selector("[role=dialog]", state="detached")

    def test_lockout_message(self):
        page = self.open()
        self.card("scanner").locator(".card-actions .btn").first.click()
        for i in range(3):
            page.fill("#root-pw", "bad%d" % i)
            page.keyboard.press("Enter")
            self.wait_js("document.querySelector('#root-pw-err').textContent.length > 0")
            if i < 2:
                self.wait_js("!document.querySelector('#root-pw').disabled")
        page.wait_for_selector(".field-error:has-text('Слишком много')")
        self.assertTrue(page.locator("#root-pw").is_disabled())

    def test_root_locked_disables_dialog(self):
        self.srv.auth.shadow_paths = (os_shadow(self.srv.tmp, "!"),)
        page = self.open()
        self.card("scanner").locator(".card-actions .btn").first.click()
        self.assertIn("passwd root", page.locator(".field-error").inner_text())
        self.assertTrue(page.locator("[role=dialog] button[type=submit]").is_disabled())

    def test_copy_command(self):
        self.ctx.grant_permissions(["clipboard-read", "clipboard-write"])
        page = self.open()
        self.card("scanner").locator(".card-actions .btn-copy").click()
        page.wait_for_selector(".toast:has-text('Скопировано')")

    # ---------------------------------------------------------------- логи
    def test_log_file_last_50_lines(self):
        page = self.open()
        self.wait_logs()
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        lines = page.locator(".log-lines li")
        self.assertEqual(lines.count(), 50)
        self.assertIn("task 300 processed <b>&amp;", lines.last.inner_text(), "текст выводится как текст, не HTML")
        self.assertEqual(page.locator(".log-lines b").count(), 0)
        self.assertGreater(page.locator(".log-lines li.lv-error").count(), 0)
        page.fill(".log-tools input[type=search]", "ERROR")
        visible = page.locator(".log-lines li:not(.hidden)")
        self.assertEqual(visible.count(), 1)
        self.assertEqual(visible.first.get_attribute("data-n"), "50", "номер строки сохраняется при фильтре")
        self.assertEqual(page.locator(".log-lines mark").count(), 1)
        self.shot("log-viewer")
        page.select_option(".log-tools select", "200")
        self.wait_js("document.querySelectorAll('.log-lines li').length === 200")
        page.keyboard.press("Escape")
        page.wait_for_selector("[role=dialog]", state="detached")

    def test_card_log_button_runs_tail(self):
        page = self.open()
        self.wait_logs()
        btn = self.card("scanner").locator(".btn-log")
        self.wait_js("!document.querySelector('.card[data-key=scanner] .card-links button').hidden")
        self.assertFalse(self.card("vms").locator(".btn-log").is_visible(),
                         "кнопка только у служб с настроенным лог-файлом")
        btn.click()
        page.wait_for_selector(".log-lines li")
        self.assertEqual(page.locator(".log-lines li").count(), 50)
        self.assertEqual(page.locator(".modal-sub").count(), 0, "команды пользователю не показываются")
        self.assertIn(["tail", "-n", "50", "--", self.srv.log_path], self.srv.fake.calls)
        self.shot("card-log-tail")

    def test_missing_log_file_error(self):
        self.srv.app.log_files[0]["path"] = self.srv.log_path + ".gone"
        page = self.open()
        self.wait_logs()
        page.evaluate("document.querySelectorAll('.card-links button').forEach(function (b) { b.disabled = false; })")
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-empty:has-text('Файл не найден')")
        self.errors = [e for e in self.errors if "404" not in e]

    def test_journal_viewer(self):
        page = self.open()
        self.card("scanner").locator(".btn-journal").click()
        page.wait_for_selector(".log-lines li")
        self.assertEqual(page.locator(".log-lines li").count(), 50)
        self.assertIn("kaspersky-vm-scanner", page.locator(".modal-title").inner_text())
        self.assertNotIn("journalctl", page.locator("[role=dialog]").inner_text())
        with page.expect_download() as dl:
            page.click(".log-tools button:has-text('Скачать')")
        self.assertTrue(dl.value.suggested_filename.startswith("scanner-"))

    def test_focus_trap_and_restore(self):
        page = self.open()
        opener = self.card("scanner").locator(".btn-journal")
        opener.click()
        page.wait_for_selector(".log-lines li")
        for _ in range(15):
            page.keyboard.press("Tab")
            inside = page.evaluate("!!document.activeElement.closest('[role=dialog]')")
            self.assertTrue(inside, "фокус не должен покидать диалог")
        page.keyboard.press("Escape")
        self.assertTrue(page.evaluate("document.activeElement.closest('.card') !== null"), "фокус возвращается")

    def test_no_log_files_journal_realtime(self):
        self.srv.app.log_files = []
        self.srv.app.log_files_by_key = {}
        self.open()
        self.wait_js("!!window.KVM.state.logs")
        links = self.card("scanner").locator(".card-links button:visible")
        self.assertEqual(links.all_inner_texts(), ["Real-time журнала службы", "Журнал службы"])

    # ---------------------------------------------------------------- отчёты и соединения
    def test_reports_download(self):
        page = self.open()
        page.wait_for_selector("#reports-list .row")
        self.assertEqual(page.locator("#reports-list .row").count(), 3)
        self.assertTrue(page.locator("#btn-reports-dl").is_disabled())
        page.locator("#reports-list input[type=checkbox]").first.check()
        self.assertEqual(page.locator("#btn-reports-dl").inner_text(), "Скачать (1)")
        with page.expect_download() as dl:
            page.click("#btn-reports-dl")
        self.assertEqual(dl.value.suggested_filename, "kaspersky-vm-services-state_28_10_2026.json")
        page.click("#btn-reports-all")
        self.assertEqual(page.locator("#btn-reports-dl").inner_text(), "Скачать (3)")
        with page.expect_download() as dl:
            page.click("#btn-reports-dl")
        self.assertTrue(dl.value.suggested_filename.endswith(".zip"))

    def test_ports_panel(self):
        page = self.open()
        self.assertFalse(page.locator("#ports-body").is_visible())
        page.click("#ports-toggle")
        self.assertEqual(page.locator("#ports-toggle").get_attribute("aria-expanded"), "true")
        self.assertEqual(page.locator("#ports-tbody tr").count(), 7)
        page.fill("#ports-filter", "5432")
        self.assertEqual(page.locator("#ports-tbody tr").count(), 1)
        self.assertIn("postgresql", page.locator("#ports-tbody tr").inner_text())
        page.fill("#ports-filter", "")
        page.check("#ports-kvm")
        self.assertEqual(page.locator("#ports-tbody tr.kvm").count(), page.locator("#ports-tbody tr").count())
        page.reload()
        page.wait_for_selector("#ports-tbody tr")
        self.assertTrue(page.locator("#ports-body").is_visible(), "состояние панели запоминается")

    # ---------------------------------------------------------------- обновление и сбои
    def test_auto_refresh_picks_up_changes(self):
        page = self.open()
        page.select_option("#interval", "5")
        self.srv.fake.stop("kaspersky-vm-scanner.service")
        page.wait_for_selector(".card[data-key=scanner] .pill:text-is('Остановлена')", timeout=9000)
        self.assertEqual(page.locator("#kpi-services").inner_text(), "4 / 6")

    def test_manual_refresh_hotkey(self):
        page = self.open()
        self.srv.fake.stop("kaspersky-vm-publicapi.service")
        self.srv.collector.invalidate()
        page.keyboard.press("r")
        page.wait_for_selector(".card[data-key=publicapi] .pill:text-is('Остановлена')", timeout=4000)

    def test_connection_lost_banner(self):
        page = self.open()
        self.srv.fake.broken = True
        self.srv.collector.invalidate()
        self.errors_allowed = True
        page.click("#btn-refresh")
        page.wait_for_selector("#banner:not([hidden])", timeout=5000)
        self.assertIn("Нет связи", page.locator("#banner").inner_text())
        self.assertEqual(page.locator(".card:not(.skeleton)").count(), 6, "последние данные остаются на экране")
        self.srv.fake.broken = False
        page.click("#banner-retry")
        page.wait_for_selector("#banner[hidden]", state="attached", timeout=5000)
        self.errors = [e for e in self.errors if "500" not in e]

    def test_open_tabs_reload_after_service_update(self):
        import helpers
        page = self.open()
        self.assertEqual(page.locator('meta[name="app-version"]').get_attribute("content"), helpers.kvm.__version__)
        original = helpers.kvm.__version__
        helpers.kvm.__version__ = "99.0.0"   # имитация: сервис обновили, вкладка открыта со старым UI
        try:
            self.srv.collector.invalidate()
            page.click("#btn-refresh")
            page.wait_for_selector('meta[name="app-version"][content="99.0.0"]', state="attached", timeout=10000)
            page.wait_for_selector(".card[data-key=scanner] .pill")
            page.wait_for_timeout(1500)
            self.assertEqual(page.locator('meta[name="app-version"]').get_attribute("content"), "99.0.0",
                             "одна перезагрузка, без цикла")
        finally:
            helpers.kvm.__version__ = original

    # ---------------------------------------------------------------- замечания к версии 1.0
    def status_json(self):
        return self.page.evaluate("fetch('/api/status').then(function (r) { return r.json(); })")

    def test_v1_kpi_labels(self):
        page = self.open()
        self.assertEqual(page.locator("#kpi-services-sub").inner_text(), "запущены")
        labels = page.locator(".kpi-label").all_inner_texts()
        self.assertIn("ПОТРЕБЛЯЕМАЯ ПАМЯТЬ", [x.upper() for x in labels])
        self.assertNotIn("ПАМЯТЬ СЛУЖБ", [x.upper() for x in labels])
        vcpu = page.locator(".kpi-label-raw")
        self.assertEqual(vcpu.inner_text(), "vCPU", "без перевода в верхний регистр")
        self.wait_js("/^загрузка процессора: \\d/.test(document.getElementById('kpi-cpu-sub').textContent)")
        self.assertIn("от объёма ОЗУ", page.locator("#kpi-svc-mem-sub").inner_text())
        self.assertNotIn("БД", page.locator("#kpis").inner_text())
        self.assertNotIn("Нагрузка", page.locator("#kpis").inner_text())

    def test_v1_memory_parts_add_up(self):
        page = self.open()
        mem = self.status_json()["system"]["memory"]
        self.assertEqual(mem["processes"] + mem["cache"], mem["used"])
        self.assertEqual(mem["used"] + mem["free"], mem["total"])
        note = page.locator("#mem-note").inner_text()
        self.assertIn("используется из", note)
        self.assertNotIn("активно", note)
        legend = page.locator(".legend").inner_text()
        self.assertIn("Не используется", legend)
        self.assertNotIn("Свободно", legend)
        widths = page.evaluate("['mem-anon','mem-cache','mem-free'].map(function (id) {"
                               " return parseFloat(document.getElementById(id).style.width); })")
        self.assertAlmostEqual(sum(widths), 100.0, delta=0.01)
        self.assertEqual(page.locator("#kpi-ram").inner_text(),
                         page.locator("#mem-note").inner_text().split(" используется")[0],
                         "плитка ОЗУ и блок памяти показывают одно значение")

    def test_v1_no_refresh_bar_and_counter(self):
        page = self.open()
        self.assertEqual(page.locator("#refresh-bar, .refresh-progress, #updated").count(), 0)
        self.assertTrue(page.locator("#interval").is_visible(), "выбор периода обновления остаётся")

    def test_v1_cards(self):
        page = self.open()
        worker = self.card("worker")
        desc = worker.locator(".desc")
        full = [svc for svc in kvm.SERVICES if svc["key"] == "worker"][0]["desc_ru"]
        self.assertEqual(desc.inner_text(), full)
        self.assertTrue(page.evaluate("(function (el) { return el.scrollHeight <= el.clientHeight + 1; })"
                                      "(document.querySelector('.card[data-key=worker] .desc'))"),
                        "описание без обрезки и многоточия")
        for key in ("scanner", "postgresql"):
            text = self.card(key).inner_text()
            for removed in ("Потоков", "Авто-перезапусков", "Подключений к БД"):
                self.assertNotIn(removed, text)
        links = self.card("scanner").locator(".card-links").inner_text()
        self.assertIn("Лог", links)
        self.assertIn("Журнал", links)
        copy = self.card("scanner").locator(".btn-copy")
        self.assertEqual(copy.inner_text().strip(), "Копировать команду перезапуска")
        self.assertIn("sudo systemctl restart kaspersky-vm-scanner.service", copy.get_attribute("title"))
        tops = page.evaluate("['scanner','vms','worker'].map(function (k) {"
                             " return Math.round(document.querySelector('.card[data-key=' + k + '] .metrics')"
                             ".getBoundingClientRect().top); })")
        self.assertEqual(len(set(tops)), 1, "показатели карточек одного ряда на одном уровне")

    def test_v1_hero_date_without_dot(self):
        page = self.open()
        when = page.locator("#server-time")
        self.wait_js("/\\d{2}\\.\\d{2}\\.\\d{4}, \\d{2}:\\d{2}:\\d{2}/.test(document.getElementById('server-time').textContent)")
        self.assertNotIn("·", when.inner_text())
        self.assertEqual(page.evaluate("getComputedStyle(document.getElementById('server-time'), '::before').content"),
                         "none")
        self.assertEqual(page.locator(".overall-meta #server-time").count(), 0, "дата — отдельной строкой")

    def test_v1_logs_panel_and_today_download(self):
        page = self.open()
        self.wait_logs()
        self.assertEqual(page.locator("#logs-list, #logs-title").count(), 0, "раздел лог-файлов убран")
        self.assertEqual(self.card("scanner").locator(".card-links button:visible").all_inner_texts(),
                         ["Real-time лога компонента", "Лог компонента", "Журнал службы"])
        self.assertEqual(self.card("postgresql").locator(".card-links button:visible").all_inner_texts(),
                         ["Real-time журнала службы", "Журнал службы"], "у СУБД нет лог-файла — Real-time журнала")
        with page.expect_download() as dl:
            page.click("#btn-logs-today")
        self.assertTrue(dl.value.suggested_filename.startswith("kaspersky-vm-logs_kvm-test.local_"))
        self.assertTrue(dl.value.suggested_filename.endswith(".zip"))
        page.wait_for_selector(".toast:has-text('Архив формируется')")

    def test_v1_log_viewer_simplified(self):
        page = self.open()
        self.wait_logs()
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        dialog = page.locator("[role=dialog]").inner_text()
        for removed in ("tail", "journalctl", "Следить", "/tmp/"):
            self.assertNotIn(removed, dialog)
        self.assertEqual(page.locator(".log-tools input[type=checkbox]").count(), 1, "только «Перенос строк»")
        self.assertFalse(page.locator(".wrap-toggle").is_checked(), "по умолчанию перенос выключен")
        self.assertEqual(page.locator(".log-tools input[type=search]").get_attribute("placeholder"), "Поиск по файлу")
        self.wait_js("/получен \\d/.test(document.querySelector('.log-meta').textContent)")
        self.assertNotIn("получено", page.locator(".log-meta").inner_text())
        white = page.evaluate("getComputedStyle(document.querySelector('.log-lines li')).whiteSpace")
        self.assertEqual(white, "pre", "по умолчанию строка лога — одна строка")

    def test_v1_ports_sorting_and_labels(self):
        page = self.open()
        page.click("#ports-toggle")
        self.assertEqual(page.locator("#ports-filter").get_attribute("placeholder"), "Поиск по порту, адресу, процессу")
        self.assertIn("Только службы Kaspersky VM", page.locator(".table-tools").inner_text())
        self.assertNotIn("KVM", page.locator("#ports-panel").inner_text().replace("Kaspersky VM", ""))
        self.assertNotIn("ss -tulnp", page.locator("#ports-panel").inner_text())

        def column(index):
            return page.locator("#ports-tbody tr td:nth-child(%d)" % index).all_inner_texts()

        def port(text):
            return int(text.rsplit(":", 1)[1])

        original = column(3)
        page.click(".th-sort[data-sort=local]")
        asc = [port(x) for x in column(3)]
        self.assertEqual(asc, sorted(asc))
        self.assertEqual(page.locator("th:has(.th-sort[data-sort=local])").get_attribute("aria-sort"), "ascending")
        page.click(".th-sort[data-sort=local]")
        desc = [port(x) for x in column(3)]
        self.assertEqual(desc, sorted(desc, reverse=True))
        self.assertEqual(page.locator("th:has(.th-sort[data-sort=local])").get_attribute("aria-sort"), "descending")
        page.click(".th-sort[data-sort=local]")
        self.assertEqual(column(3), original, "третий щелчок — исходный порядок")
        page.click(".th-sort[data-sort=process]")
        procs = [x.lower() for x in column(4)]
        self.assertEqual(procs, sorted(procs))
        page.click(".th-sort[data-sort=service]")
        services = column(5)
        self.assertTrue(services[0].strip(), "строки служб Kaspersky VM — первыми")
        page.fill("#ports-filter", "postgres")
        self.assertEqual(page.locator("#ports-tbody tr").count(), 1)
        self.shot("ports-sorted")

    def test_v1_official_logo_and_static_favicon(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#0a8"/></svg>'
        item = {"data": svg, "type": "image/svg+xml", "etag": kvm.etag_for(svg)}
        self.srv.app.brand = {"logo": item, "favicon": item}
        page = self.open()
        self.assertEqual(page.locator(".brand-mark").count(), 0)
        self.assertTrue(page.locator(".brand-logo-dark").is_visible())
        self.assertFalse(page.locator(".brand-logo-light").is_visible())
        self.assertEqual(page.evaluate("document.querySelector('.brand-logo-dark').naturalWidth > 0"), True)
        page.click("#btn-theme")
        self.assertTrue(page.locator(".brand-logo-light").is_visible())
        # worker остановлен: поверх значка рисуется красная точка (картинка PNG через canvas)
        self.wait_js("document.getElementById('favicon').href.indexOf('data:image/png') === 0")
        self.srv.fake.set("kaspersky-vm-worker.service", ActiveState="active", SubState="running", MainPID=99)
        page.wait_for_timeout(400)  # кэш состояния на сервере (0,2 с в тестах) устарел
        page.click("#btn-refresh")
        self.wait_js("document.getElementById('favicon').getAttribute('href') === '/brand/favicon'")

    def test_v1_english_labels(self):
        page = self.open("?lang=en")
        self.assertEqual(page.locator("#kpi-services-sub").inner_text(), "running")
        self.assertIn("Not used", page.locator(".legend").inner_text())
        self.wait_logs()
        self.assertEqual(self.card("scanner").locator(".card-links button:visible").all_inner_texts(),
                         ["Real-time component log", "Component log", "Service journal"])
        self.assertIn("Logs for another day", page.locator("#btn-logs-day").inner_text())
        self.assertIn("Download today", page.locator("#btn-logs-today").inner_text())
        self.assertIn("Copy restart command", self.card("scanner").locator(".btn-copy").inner_text())

    def test_v1_js_helpers(self):
        page = self.open()
        self.assertEqual(page.evaluate("KVM.fmtServerTime('2026-11-03T16:41:50')"), "03.11.2026, 16:41:50")
        self.assertEqual(page.evaluate("KVM.fmtServerTime('garbage')"), "garbage")
        self.assertEqual(page.evaluate("KVM.fmtBytes(1536)"), "1,5\u00a0КБ")
        self.assertEqual(page.evaluate("KVM.fmtDuration(90061)"), "1д 1ч")
        self.assertEqual(page.evaluate("KVM.classify('2026 ERROR boom')"), "error")
        self.assertEqual(page.evaluate("KVM.escapeRe('a.b*c')"), "a\\.b\\*c")
        page.click("[data-lang=en]")
        self.assertEqual(page.evaluate("KVM.fmtServerTime('2026-11-03T16:41:50')"), "2026-11-03 16:41:50")

    @staticmethod
    def _fulfill(status, body):
        import json as _json

        def handler(route, request=None):
            route.fulfill(status=status, content_type="application/json", body=_json.dumps(body))
        return handler

    def test_v1_restart_dialog_error_messages(self):
        page = self.open()
        responses = [
            (409, {"ok": False, "error": "in_progress"}, "уже выполняется"),
            (500, {"ok": False, "error": "systemctl_failed", "message": "Access denied"}, "Access denied"),
            (403, {"ok": False, "error": "csrf"}, "недопустимый источник"),
            (403, {"ok": False, "error": "insecure_transport"}, "без HTTPS"),
            (503, {"ok": False, "error": "auth_unavailable"}, "/etc/shadow"),
            (403, {"ok": False, "error": "root_locked"}, "passwd root"),
            (418, {"ok": False, "error": "teapot"}, "Ошибка: teapot"),
        ]
        for status, body, expected in responses:
            page.route("**/api/services/*/restart", self._fulfill(status, body))
            self.card("scanner").locator(".card-actions .btn").first.click()
            page.locator("#root-pw").fill("x")
            toggle = page.locator(".pw-wrap .btn")
            toggle.click()
            self.assertEqual(page.locator("#root-pw").get_attribute("type"), "text", "показать пароль")
            toggle.click()
            page.keyboard.press("Enter")
            page.wait_for_selector(".field-error:has-text('%s')" % expected)
            page.unroute("**/api/services/*/restart")
            page.keyboard.press("Escape")
            page.wait_for_selector("[role=dialog]", state="detached")
        page.route("**/api/services/*/restart", lambda route: route.abort())
        self.card("scanner").locator(".card-actions .btn").first.click()
        page.locator("#root-pw").fill("x")
        page.click("[role=dialog] button[type=submit]")
        page.wait_for_selector(".field-error:has-text('Сервер недоступен')")
        page.click("[role=dialog] .modal-foot .btn:has-text('Отмена')")
        page.wait_for_selector("[role=dialog]", state="detached")
        self.errors = [e for e in self.errors if "Failed to load resource" not in e and "ERR_FAILED" not in e]

    def test_v1_log_viewer_errors_and_tools(self):
        import json as _json
        page = self.open()
        self.wait_logs()
        page.route("**/api/logs/file/scanner*", lambda route: route.fulfill(
            status=403, content_type="application/json", body=_json.dumps({"ok": False, "error": "permission_denied"})))
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-empty:has-text('Нет прав на чтение файла')")
        page.unroute("**/api/logs/file/scanner*")
        page.route("**/api/logs/file/scanner*", lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=_json.dumps({"ok": True, "kind": "file", "key": "scanner", "lines": [], "size": 0, "mtime": 1})))
        page.click(".log-tools button:has-text('Обновить')")
        page.wait_for_selector(".log-empty:has-text('Журнал пуст')")
        page.unroute("**/api/logs/file/scanner*")
        page.click(".log-tools button:has-text('Обновить')")
        page.wait_for_selector(".log-lines li")
        page.fill(".log-tools input[type=search]", "no-such-text-anywhere")
        page.wait_for_selector(".log-empty:has-text('Нет строк')")
        page.fill(".log-tools input[type=search]", "")
        page.click(".log-tools button:has-text('Копировать')")
        page.wait_for_selector(".toast")
        page.keyboard.press("Escape")
        self.errors = [e for e in self.errors if "403" not in e]

    def test_v1_misc_controls(self):
        page = self.open()
        page.click("#btn-theme")
        page.click("#btn-theme")
        self.assertEqual(page.locator("html").get_attribute("data-theme"), "dark")
        page.click("[data-lang=ru]")  # уже выбран — ничего не меняется
        page.click("#ports-toggle")
        page.check("#ports-kvm")
        page.uncheck("#ports-kvm")
        page.keyboard.press("r")
        page.select_option("#interval", "0")
        page.wait_for_timeout(200)
        page.select_option("#interval", "10")
        # фон: вкладка скрыта и снова видна
        page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
        # диалог закрывается щелчком по фону
        self.card("postgresql").locator(".card-actions .btn").first.click()
        page.mouse.click(5, 5)
        page.wait_for_selector("[role=dialog]", state="detached")
        # отчёты: выбрать и снять выбор
        page.wait_for_selector("#reports-list .row")
        box = page.locator("#reports-list input[type=checkbox]").first
        box.check()
        box.uncheck()
        page.click("#btn-reports-all")
        page.click("#btn-reports-all")
        self.assertEqual(page.locator("#btn-reports-dl").inner_text(), "Скачать")

    def test_v1_clipboard_fallback(self):
        page = self.open()
        self.card("scanner").locator(".card-actions .btn-copy").click()
        page.wait_for_selector(".toast")

    # ---------------------------------------------------------------- отчёты и SIEM
    def test_report_now_and_report_list(self):
        with open(os.path.join(self.srv.tmp, kvm.REPORT_PREFIX + "29_10_2026.json"), "w") as fh:
            fh.write("{}")
        page = self.open()
        page.wait_for_selector("#reports-list .row")
        names = page.locator("#reports-list .row .mono").all_inner_texts()
        self.assertEqual(names[0], kvm.REPORT_PREFIX + "29_10_2026.json", "новые сверху")
        self.assertEqual(len(names), 4)
        self.assertIn("JSON · ежедневно в 19:00", page.locator("#reports-title + .panel-note").inner_text())
        with page.expect_download() as dl:
            page.click("#btn-report-now")
        page.wait_for_selector(".toast:has-text('Отчёт формируется')")
        self.assertRegex(dl.value.suggested_filename, r"^kaspersky-vm-services-state_\d{2}_\d{2}_\d{4}_\d{6}\.json$")
        with open(dl.value.path(), encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["kind"], "on-demand")
        self.assertEqual(report["summary"]["status"], "critical", "worker остановлен в фикстуре")
        self.shot("reports", full=True)

    def test_siem_configure_test_and_save(self):
        lst = Listener("tcp")
        self.srv.app.siem.start()
        try:
            page = self.open()
            page.wait_for_selector("#siem-pill:has-text('Выключено')")
            self.assertIn("CEF по syslog", page.locator("#siem-body .hint").inner_text())
            page.click("#btn-siem")
            dialog = page.locator("[role=dialog]")
            self.assertIn("Рекомендуется: TCP, порт 5144", dialog.locator(".callout-accent").inner_text())
            self.assertEqual(page.input_value("#siem-port"), "5144")
            tcp = dialog.locator("[data-proto=tcp]")
            self.assertEqual(tcp.get_attribute("aria-pressed"), "true")
            self.assertIn("рекомендуется", tcp.inner_text().lower())
            self.assertTrue(dialog.locator(".callout:has-text('UDP не подтверждает')").is_hidden())
            dialog.locator("[data-proto=udp]").click()
            self.assertTrue(dialog.locator(".callout:has-text('UDP не подтверждает')").is_visible())
            page.fill("#siem-port", "1")
            dialog.locator(".field-hint button").click()  # подставить рекомендуемые порт и протокол
            self.assertEqual(page.input_value("#siem-port"), "5144")
            self.assertEqual(tcp.get_attribute("aria-pressed"), "true")
            dialog.locator("summary").click()
            self.assertEqual(dialog.locator(".table-compact tbody tr").count(), len(kvm.EVENT_TYPES))
            page.fill("#siem-host", "127.0.0.1")
            page.fill("#siem-port", str(lst.port))
            dialog.locator(".modal-foot .btn:has-text('тестовое')").click()
            page.wait_for_selector("#siem-pw-err:has-text('Введите пароль root')")
            page.fill("#siem-pw", ServerFixture.PASSWORD)
            self.shot("siem-dialog")
            dialog.locator(".modal-foot .btn:has-text('тестовое')").click()
            page.wait_for_selector(".toast:has-text('Тестовое событие отправлено')")
            self.assertTrue(lst.wait(1))
            self.assertTrue(dialog.is_visible(), "после теста окно остаётся открытым")
            page.click("[role=dialog] button[type=submit]")
            page.wait_for_selector(".toast:has-text('Настройки SIEM сохранены')")
            page.wait_for_selector("[role=dialog]", state="detached")
            self.assertIn("127.0.0.1:%d" % lst.port, page.locator(".siem-target").inner_text())
            self.assertTrue(lst.wait(2), "событие о смене настроек доставлено")
            page.click("#btn-refresh")
            page.wait_for_selector("#siem-pill:has-text('Работает')")
            page.wait_for_selector(".events .event")
            self.assertIn("SIEM forwarding enabled", page.locator(".events").inner_text())
            self.shot("siem-panel", full=True)
            # выключение
            page.click("#btn-siem")
            self.assertEqual(page.input_value("#siem-host"), "127.0.0.1")
            page.uncheck("#siem-enabled")
            page.fill("#siem-pw", ServerFixture.PASSWORD)
            page.click("[role=dialog] button[type=submit]")
            page.wait_for_selector(".toast:has-text('выключена')")
            page.wait_for_selector("#siem-pill:has-text('Выключено')")
        finally:
            lst.close()

    def test_siem_events_expand_wrap_and_all_events(self):
        lst = Listener("tcp")
        app = self.srv.app
        app.siem.start()
        app.siem.configure({"enabled": True, "host": "127.0.0.1", "port": lst.port, "protocol": "tcp"})
        try:
            for i in range(10):
                app.events.emit("log_errors", "Worker: %d new error record(s). Last: %s" % (i + 1, "очень\tдлинная   ошибка " * 20),
                                key="worker", file="/var/log/w.log", count=i + 1)
            self.assertTrue(lst.wait(10))
            app.siem.configure({"enabled": False, "host": "127.0.0.1", "port": lst.port, "protocol": "tcp"})
            app.events.emit("service_failed", "Service x failed (was active)", unit="x.service", key="worker", state="failed")
            page = self.open()
            page.wait_for_selector(".events .event")
            self.assertIn("ОТПРАВЛЯЕМЫЕ СОБЫТИЯ", page.locator(".events-head").inner_text().upper())
            self.assertEqual(page.locator(".events .event").count(), 5, "в панели — 5 последних")
            self.assertEqual(page.locator(".events-all").inner_text().strip(), "Все события (11)")
            first = page.locator(".events .event").first
            self.assertEqual(first.locator(".event-st").inner_text(), "SIEM выключена")
            self.assertEqual(first.locator(".sev").get_attribute("data-tone"), "bad", "важность 5 — красная")
            second = page.locator(".events .event").nth(1)
            self.assertEqual(second.locator(".event-st").inner_text(), "отправлено")
            self.assertEqual(second.locator(".sev").get_attribute("data-tone"), "warn", "важность 3 — жёлтая")
            self.assertNotIn("  ", second.locator(".event-msg").inner_text(), "по одному пробелу")
            # раскрытие: строка в SIEM целиком
            self.assertFalse(second.locator(".event-raw").is_visible())
            second.locator("summary").click()
            raw = second.locator(".event-raw").inner_text()
            self.assertIn("CEF:0|Kaspersky|Kaspersky VM Metrics|", raw)
            self.assertIn(raw.strip(), lst.text(), "показана ровно отправленная строка")
            self.assertNotIn("  ", raw)
            self.assertIn("ID 500", second.locator(".event-meta").inner_text())
            white = "getComputedStyle(document.querySelectorAll('.event-raw')[1]).whiteSpace"
            self.assertEqual(page.evaluate(white), "pre")
            self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('.event-msg')).whiteSpace"), "nowrap")
            page.check(".siem-wrap")
            self.assertEqual(page.evaluate(white), "pre-wrap", "перенос строк в отправленной строке")
            self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('.event-msg')).whiteSpace"), "normal")
            self.shot("siem-events-expanded")
            # выбор переноса строк запоминается
            page.reload()
            page.wait_for_selector(".events .event")
            self.assertTrue(page.locator(".siem-wrap").is_checked())
            self.assertIn("wrap", page.locator("ul.events").get_attribute("class"))
            page.uncheck(".siem-wrap")
            self.assertNotIn("wrap", page.locator("ul.events").get_attribute("class"))
            page.evaluate("KVM.state.siem.recent[0].siem = 'queued'; KVM.state.siem.recent[1].siem = 'dropped'")
            page.click("[data-lang=en]")
            self.assertEqual(page.locator(".events .event-st").first.inner_text(), "queued")
            self.assertEqual(page.locator(".events .event-st").nth(1).inner_text(), "not sent")
            self.assertIn("FORWARDED EVENTS", page.locator(".events-head").inner_text().upper())
            self.assertEqual(page.locator(".events-all").inner_text().strip(), "All events (11)")
        finally:
            lst.close()

    def test_siem_all_events_viewer(self):
        app = self.srv.app
        for i in range(30):
            app.events.emit("auth_failed", "Wrong root password (restart), attempts left: %d" % i, client="10.0.0.1")
        app.events.emit("service_failed", "Service x failed (was active)", unit="x.service", key="worker", state="failed")
        app.events.emit("monitor_started", "Kaspersky VM Metrics 1.0.0 started")
        page = self.open()
        page.click(".events-all")
        page.wait_for_selector(".log-lines li")
        self.assertEqual(page.locator(".modal-title").inner_text(), "Отправляемые события")
        lines = page.locator(".log-lines li")
        self.assertEqual(lines.count(), 32)
        self.assertIn("|Kaspersky VM Metrics|", lines.first.inner_text())
        self.assertIn("lv-warn", lines.first.get_attribute("class"), "важность 3 — предупреждение")
        self.assertIn("lv-error", lines.nth(30).get_attribute("class"), "важность 5 — ошибка")
        self.assertIsNone(lines.last.get_attribute("class"), "важность 1 — без подсветки")
        self.assertEqual(page.locator(".log-tools select").input_value(), "200")
        self.assertIn("Событий: 500", page.locator(".log-tools select").inner_text())
        self.assertEqual(page.locator(".log-tools input[type=search]").get_attribute("placeholder"), "Поиск по событиям")
        self.assertIn("событий: 32 из 32", page.locator(".log-meta").inner_text())
        page.fill(".log-tools input[type=search]", "attempts left: 7")
        self.assertEqual(page.locator(".log-lines li:not(.hidden)").count(), 1)
        page.check(".wrap-toggle")
        self.assertIn("wrap", page.locator(".log-view").get_attribute("class"))
        with page.expect_download() as dl:
            page.click(".log-tools button:has-text('Скачать')")
        self.assertTrue(dl.value.suggested_filename.startswith("siem-events-"))
        with open(dl.value.path(), encoding="utf-8") as fh:
            self.assertEqual(fh.read().count("\n"), 32)
        # новые события подгружаются в открытое окно вместе с циклом обновления
        app.events.emit("disk_high", "Filesystem /var is 94.1% full", path="/var", percent=94.1)
        page.evaluate("KVM.refresh()")
        self.wait_js("document.querySelectorAll('.log-lines li').length === 33", timeout=10)
        page.select_option(".log-tools select", "50")
        self.wait_js("document.querySelector('.log-meta').textContent.indexOf('из 33') !== -1", timeout=10)
        page.keyboard.press("Escape")
        page.wait_for_selector("[role=dialog]", state="detached")
        self.assertIsNone(page.evaluate("KVM.state.siemViewer"), "после закрытия окно не обновляется")

    def test_siem_panel_refreshes_without_reload(self):
        page = self.open()
        page.wait_for_selector("#siem-pill")
        before = page.locator(".events .event").count()
        self.srv.app.events.emit("disk_high", "Filesystem /var is 94.1% full", path="/var", percent=94.1)
        page.evaluate("KVM.refresh()")
        page.wait_for_selector(".events .event-msg:has-text('Filesystem /var')")
        self.assertEqual(page.locator(".events .event").count(), min(before + 1, 5))
        page.locator(".events .event").first.locator("summary").click()
        page.evaluate("KVM.refresh()")
        page.wait_for_timeout(600)
        self.assertIsNotNone(page.locator(".events .event").first.get_attribute("open"),
                             "без изменений панель не перерисовывается — раскрытое событие остаётся")

    def test_logs_for_day_dialog(self):
        page = self.open()
        page.click("#btn-logs-day")
        dialog = page.locator("[role=dialog]")
        self.assertIn("Логи компонентов за день", dialog.inner_text())
        value = page.locator("#logs-day").input_value()
        self.assertEqual(value, (datetime.date.today() - datetime.timedelta(days=1)).isoformat(), "по умолчанию — вчера")
        page.fill("#logs-day", "2099-01-01")
        page.click("[role=dialog] button[type=submit]")
        self.assertTrue(page.locator("[role=dialog] .field-error").is_visible())
        page.fill("#logs-day", value)
        with page.expect_download() as dl:
            page.click("[role=dialog] button[type=submit]")
        self.assertTrue(dl.value.suggested_filename.startswith("kaspersky-vm-logs_kvm-test.local_"))
        page.wait_for_selector("[role=dialog]", state="detached")
        page.click("#btn-logs-day")
        page.click("[role=dialog] .modal-foot .btn:not(.btn-primary)")
        page.wait_for_selector("[role=dialog]", state="detached")

    def test_reports_empty_text_left_aligned(self):
        self.srv.app.log_dir = self.srv.tmp + "/empty-reports"
        os.makedirs(self.srv.app.log_dir, exist_ok=True)
        page = self.open()
        page.wait_for_selector("#reports-list .empty")
        empty = page.locator("#reports-list .empty")
        self.assertEqual(empty.inner_text(), "Ежедневных отчётов пока нет: отчёт формируется в 19:00. Чтобы сформировать "
                                             "отчёт на текущий момент, нажмите кнопку «Сформировать отчёт сейчас».")
        self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('#reports-list .empty')).textAlign"), "left")

    def test_siem_dialog_short_recommendation_and_white_badge(self):
        page = self.open()
        page.wait_for_selector("#siem-pill")
        page.click("#btn-siem")
        text = page.locator(".callout-accent").inner_text()
        self.assertIn("TCP подтверждает доставку и не обрезает длинные события; пока SIEM недоступна, события копятся в очереди.", text)
        self.assertNotIn("KUMA", text, "рекомендация — одно предложение")
        self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('.reco-badge')).color"), "rgb(255, 255, 255)")
        page.keyboard.press("Escape")

    def test_siem_error_state_and_dialog_errors(self):
        page = self.open()
        page.wait_for_selector("#siem-pill:has-text('Выключено')")
        siem = self.srv.app.siem
        siem.configure({"enabled": True, "host": "127.0.0.1", "port": free_port(), "protocol": "udp"})
        siem.stats.update({"failed": 3, "last_error": "Connection refused", "last_error_time": time.time()})
        page.evaluate("KVM.refresh()")
        page.wait_for_selector("#siem-pill:has-text('Ошибка отправки')")
        self.assertIn("Connection refused", page.locator(".callout-bad").inner_text())
        page.click("#btn-siem")
        dialog = page.locator("[role=dialog]")
        self.assertEqual(dialog.locator("[data-proto=udp]").get_attribute("aria-pressed"), "true")

        def post_only(status, body):
            fulfill = self._fulfill(status, body)

            def handler(route, request=None):
                req = request or route.request
                if req.method == "POST":
                    fulfill(route)
                else:
                    route.continue_()
            return handler
        cases = [
            ("**/api/siem", 400, {"ok": False, "error": "bad_port"}, "submit", "от 1 до 65535", "siem-port"),
            ("**/api/siem", 400, {"ok": False, "error": "bad_host"}, "submit", "Недопустимый адрес", "siem-host"),
            ("**/api/siem", 401, {"ok": False, "error": "bad_password", "attempts_left": 2}, "submit", "Осталось попыток: 2", "siem-pw"),
            ("**/api/siem", 500, {"ok": False, "error": "save_failed", "message": "ro"}, "submit", "Не удалось сохранить настройки: ro", None),
            ("**/api/siem/test", 502, {"ok": False, "error": "send_failed", "message": "refused"}, "test", "Не удалось отправить событие: refused", None),
        ]
        for pattern, status, body, button, expected, focus in cases:
            page.route(pattern, post_only(status, body))
            page.fill("#siem-pw", "x")
            if button == "submit":
                page.click("[role=dialog] button[type=submit]")
            else:
                dialog.locator(".modal-foot .btn:has-text('тестовое')").click()
            page.wait_for_selector("#siem-pw-err:has-text('%s')" % expected)
            if focus:
                self.wait_js("document.activeElement.id === '%s'" % focus)
            page.unroute(pattern)
        page.route("**/api/siem", post_only(429, {"ok": False, "error": "locked", "retry_after": 60}))
        page.fill("#siem-pw", "x")
        page.click("[role=dialog] button[type=submit]")
        page.wait_for_selector("#siem-pw-err:has-text('Повторите через')")
        self.assertTrue(page.locator("[role=dialog] button[type=submit]").is_disabled(), "блокировка — кнопки недоступны")
        self.assertFalse(dialog.locator(".modal-foot .btn:has-text('Отмена')").is_disabled())
        page.unroute("**/api/siem")
        page.keyboard.press("Escape")
        page.wait_for_selector("[role=dialog]", state="detached")
        self.errors = [e for e in self.errors if not re.search(r"\b(400|401|429|500|502)\b", e)]

    def test_siem_dialog_disabled_without_root_password(self):
        self.srv.app.auth.shadow_paths = (os_shadow(self.srv.tmp, "!"),)
        page = self.open()
        page.wait_for_selector("#siem-pill")
        page.click("#btn-siem")
        page.wait_for_selector("#siem-pw-err:has-text('passwd root')")
        self.assertTrue(page.locator("#siem-pw").is_disabled())
        self.assertTrue(page.locator("[role=dialog] .modal-foot .btn:has-text('тестовое')").is_disabled())

    def test_siem_english_and_helpers(self):
        page = self.open()
        page.wait_for_selector("#siem-pill")
        page.click("[data-lang=en]")
        self.assertEqual(page.locator("#siem-title").inner_text().upper(), "SIEM EVENT FORWARDING")
        self.assertEqual(page.locator("#siem-pill").inner_text(), "Off")
        self.assertEqual(page.locator("#btn-report-now").inner_text().strip(), "Create report now")
        self.assertEqual(page.locator("#kpi-cpu-sub").inner_text().split(":")[0], "CPU load")
        self.assertEqual(page.evaluate("KVM.fmtIso('garbage')"), "garbage")
        self.assertEqual(page.evaluate("KVM.fmtIso(null)"), "—")
        self.assertEqual(page.evaluate("KVM.authErrorText({status: 400, data: {error: 'host_required'}})"),
                         "Enter the SIEM address.")
        self.assertEqual(page.evaluate("KVM.authErrorText({status: 400, data: {error: 'bad_protocol'}})"),
                         "Invalid protocol.")
        self.assertEqual(page.evaluate("KVM.authErrorText({status: 0, data: null})"),
                         "Server is unreachable. Check the connection.")
        # JSON-логи KVM: уровень берётся из поля level
        self.assertEqual(page.evaluate("KVM.classify('{\"level\":\"error\",\"message\":\"x\"}')"), "error")
        self.assertEqual(page.evaluate("KVM.classify('{\"level\":\"info\",\"message\":\"no error here\"}')"), "")
        self.assertEqual(page.evaluate("KVM.classify('{\"level\":\"warning\"}')"), "warn")
        self.assertEqual(page.evaluate("KVM.classify('{\"level\":\"debug\"}')"), "debug")
        self.assertEqual(page.evaluate("KVM.classify('{\"level\":\"notice\"}')"), "")
        page.evaluate("KVM.state.siem = null")
        page.click("#btn-siem")  # данных ещё нет — окно не открывается
        self.assertEqual(page.locator("[role=dialog]").count(), 0)

    def test_log_viewer_single_line_and_error_highlight(self):
        with open(self.srv.log_path, "a") as fh:
            fh.write('{"level":"error","timestamp":"2026-10-28T12:10:00","message":"%s"}\n' % ("very long " * 80))
        page = self.open()
        self.wait_logs()
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        last = page.locator(".log-lines li").last
        self.assertIn("lv-error", last.get_attribute("class"))
        self.assertEqual(page.evaluate("getComputedStyle(document.querySelector('.log-lines li')).whiteSpace"), "pre",
                         "строки лога не переносятся")
        box = last.bounding_box()
        self.assertLess(box["height"], 30, "длинная строка — одна строка с горизонтальной прокруткой")
        page.keyboard.press("Escape")

    # ---------------------------------------------------------------- Real-time
    def append_log(self, *lines):
        with open(self.srv.log_path, "a") as fh:
            for line in lines:
                fh.write(line + "\n")

    def test_realtime_stream_filter_stop_resume(self):
        page = self.open()
        self.wait_logs()
        self.card("scanner").locator(".btn-live").click()
        page.wait_for_selector(".live-status[data-state=running]")
        page.wait_for_selector(".log-lines li")
        self.assertEqual(page.locator(".log-lines li").count(), 50, "сначала 50 последних строк")
        self.assertIn("Real-time", page.locator(".modal-sub").inner_text())
        self.append_log('{"level":"error","message":"live failure 1"}', '{"level":"info","message":"live ok"}')
        page.wait_for_selector(".log-lines li:has-text('live ok')")
        self.assertIn("lv-error", page.locator(".log-lines li:has-text('live failure 1')").get_attribute("class"))
        page.fill(".log-tools input[type=search]", "failure")
        self.append_log('{"level":"error","message":"live failure 2"}', "plain line")
        page.wait_for_selector(".log-lines li:has-text('live failure 2')")
        self.assertEqual(page.locator(".log-lines li:not(.hidden)").count(), 2, "поиск применяется и к новым строкам")
        self.assertEqual(page.locator(".log-lines mark").count(), 2)
        self.assertIn("совпадений: 2", page.locator(".log-meta").inner_text())
        self.assertIn("получено строк: 54", page.locator(".log-meta").inner_text())
        self.shot("realtime")
        page.click(".live-toggle")
        page.wait_for_selector(".live-status[data-state=stopped]")
        self.assertEqual(page.locator(".live-toggle").inner_text().strip(), "Продолжить")
        self.wait_js("!document.querySelector('.log-view') || true")
        self.append_log('{"level":"error","message":"while stopped failure"}')
        page.wait_for_timeout(700)
        self.assertEqual(page.locator(".log-lines li:has-text('while stopped')").count(), 0, "после «Стоп» строки не приходят")
        page.click(".live-toggle")
        page.wait_for_selector(".live-status[data-state=running]")
        self.append_log('{"level":"error","message":"after resume failure"}')
        page.wait_for_selector(".log-lines li:has-text('after resume')")
        self.assertEqual(page.locator(".log-lines li:has-text('task 300')").count(), 1, "при продолжении без повторов")
        page.fill(".log-tools input[type=search]", "")
        page.click(".log-tools button:has-text('Очистить')")
        self.assertEqual(page.locator(".log-lines li").count(), 0)
        self.assertTrue(page.locator(".log-view .log-empty").is_visible())
        page.keyboard.press("Escape")
        page.wait_for_selector("[role=dialog]", state="detached")
        self.wait_js("true")
        deadline = time.time() + 3
        while self.srv.app.live_slots._value != kvm.LIVE_MAX_STREAMS and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.srv.app.live_slots._value, kvm.LIVE_MAX_STREAMS, "закрытие окна останавливает tail")

    def test_realtime_jump_copy_download_and_card_buttons(self):
        self.ctx.grant_permissions(["clipboard-read", "clipboard-write"])
        page = self.open()
        self.wait_logs()
        live = self.card("scanner").locator(".card-links .btn-live")
        self.assertEqual(live.inner_text().strip(), "Real-time лога компонента")
        self.assertEqual(self.card("scanner").locator(".card-links .btn:not([hidden])").count(), 3, "Real-time, Лог, Журнал")
        live.click()
        page.wait_for_selector(".log-lines li")
        page.evaluate("document.querySelector('.log-view').scrollTop = 0")
        self.append_log(*["more %d" % i for i in range(5)])
        page.wait_for_selector(".live-jump:not([hidden])")
        page.click(".live-jump")
        self.wait_js("document.querySelector('.live-jump').hidden")
        page.click(".log-tools button:has-text('Копировать')")
        page.wait_for_selector(".toast:has-text('Скопировано')")
        with page.expect_download() as dl:
            page.click(".log-tools button:has-text('Скачать')")
        self.assertTrue(dl.value.suggested_filename.startswith("scanner-realtime-"))
        page.keyboard.press("Escape")
        # у службы без лог-файла — журнал systemd
        calls = []
        self.srv.app.spawn = lambda args: calls.append(args) or kvm.spawn_process(
            [sys.executable, "-c", "import time; print('journal line', flush=True); time.sleep(30)"])
        self.card("postgresql").locator(".btn-live").click()
        page.wait_for_selector(".log-lines li:has-text('journal line')")
        self.assertEqual(calls[0][:3], ["journalctl", "-u", "postgresql.service"])
        self.assertIn("Журнал systemd", page.locator(".modal-title").inner_text())
        page.keyboard.press("Escape")

    def test_realtime_end_and_errors(self):
        page = self.open()
        self.wait_logs()
        # сервер закрывает поток (сервис перезапускается)
        page.evaluate("KVM.openLiveViewer({kind: 'file', key: 'scanner', title: 'S'})")
        page.wait_for_selector(".live-status[data-state=running]")
        self.srv.app.stopping.set()
        page.wait_for_selector(".live-notice:has-text('перезапускается')")
        self.assertEqual(page.locator(".live-status").get_attribute("data-state"), "stopped")
        page.keyboard.press("Escape")
        self.srv.app.stopping.clear()
        # ошибки подключения: файла нет, слишком много окон
        page.evaluate("KVM.openLiveViewer({kind: 'file', key: 'missing', title: 'M'})")
        page.wait_for_selector(".live-notice:has-text('Файл не найден на сервере')")
        page.keyboard.press("Escape")
        for _ in range(kvm.LIVE_MAX_STREAMS):
            self.srv.app.live_slots.acquire()
        try:
            page.evaluate("KVM.openLiveViewer({kind: 'file', key: 'scanner', title: 'S'})")
            page.wait_for_selector(".live-notice:has-text('не больше 8')")
            page.keyboard.press("Escape")
        finally:
            for _ in range(kvm.LIVE_MAX_STREAMS):
                self.srv.app.live_slots.release()
        page.route("**/api/logs/live/**", lambda route: route.fulfill(status=500, content_type="text/plain", body="x"))
        page.evaluate("KVM.openLiveViewer({kind: 'file', key: 'scanner', title: 'S'})")
        page.wait_for_selector(".live-notice:has-text('HTTP 500')")
        page.keyboard.press("Escape")
        page.unroute("**/api/logs/live/**")
        # обрыв связи после начала — переподключение без повтора строк; новый файл по маске; конец по времени
        body = ('event: meta\ndata: {"kind":"file","key":"scanner","path":"/x"}\n\n'
                'event: lines\ndata: ["first chunk"]\n\n'
                'event: switch\ndata: {"path":"/var/log/vms_2.log"}\n\n')
        state = {"n": 0}

        def handler(route):
            state["n"] += 1
            if state["n"] == 1:
                route.fulfill(status=200, headers={"Content-Type": "text/event-stream"}, body=body)
            else:
                self.assertIn("lines=0", route.request.url, "после обрыва — без начальных строк")
                route.fulfill(status=200, headers={"Content-Type": "text/event-stream"},
                              body='event: meta\ndata: {}\n\nevent: lines\ndata: ["second"]\n\n'
                                   'event: end\ndata: {"reason":"time_limit","rc":null}\n\n')
        page.route("**/api/logs/live/**", handler)
        page.evaluate("KVM.openLiveViewer({kind: 'file', key: 'scanner', title: 'S'})")
        page.wait_for_selector(".log-lines li.live-sep:has-text('vms_2.log')")
        page.wait_for_selector(".log-lines li:has-text('second')", timeout=8000)
        page.wait_for_selector(".live-notice:has-text('через час')")
        self.assertEqual(page.locator(".log-lines li:has-text('first chunk')").count(), 1)
        page.keyboard.press("Escape")
        page.unroute("**/api/logs/live/**")
        self.errors = [e for e in self.errors if "404" not in e and "429" not in e and "500" not in e]

    # ---------------------------------------------------------------- перенос строк
    def wrap_state(self):
        return self.page.evaluate("""() => {
          const view = document.querySelector('.log-view');
          const long = [...document.querySelectorAll('.log-lines li')].filter(li => li.textContent.indexOf('LONG-') !== -1)[0];
          const visible = [...document.querySelectorAll('.log-lines li')].filter(li => li.offsetParent !== null).length;
          return {white: getComputedStyle(long).whiteSpace, hscroll: view.scrollWidth > view.clientWidth + 1,
                  height: long.getBoundingClientRect().height, visible: visible,
                  numberLeft: Math.round(long.getBoundingClientRect().left) < Math.round(view.getBoundingClientRect().left) + 70};
        }""")

    def test_wrap_lines_toggle(self):
        self.append_log("2026-10-28 12:10:00 ERROR scanner: LONG-" + "x" * 3000 + " end-of-long-line")
        page = self.open()
        self.wait_logs()
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        off = self.wrap_state()
        self.assertEqual(off["white"], "pre")
        self.assertTrue(off["hscroll"], "без переноса — горизонтальная прокрутка")
        self.assertLess(off["height"], 30)
        page.check(".wrap-toggle")
        on = self.wrap_state()
        self.assertEqual(on["white"], "pre-wrap")
        self.assertFalse(on["hscroll"], "с переносом прокрутки по горизонтали нет")
        self.assertGreater(on["height"], 60, "длинная строка занимает несколько строк")
        self.assertTrue(on["numberLeft"], "номер строки остаётся слева")
        page.fill(".log-tools input[type=search]", "LONG-")
        self.assertEqual(self.wrap_state()["visible"], 1, "поиск работает и с переносом")
        self.assertEqual(page.locator(".log-lines li.lv-error mark").count(), 2,
                         "подсветка ошибки и совпадений сохраняется (поиск без учёта регистра: LONG- и long-)")
        page.fill(".log-tools input[type=search]", "")
        self.shot("log-viewer-wrap")
        page.keyboard.press("Escape")
        # выбор запоминается: и для следующего окна, и после перезагрузки, и в Real-time
        page.reload()
        self.wait_logs()
        self.card("scanner").locator(".btn-live").click()
        page.wait_for_selector(".log-lines li:has-text('LONG-')")
        self.assertTrue(page.locator(".wrap-toggle").is_checked())
        self.assertEqual(self.wrap_state()["white"], "pre-wrap")
        page.uncheck(".wrap-toggle")
        self.assertEqual(self.wrap_state()["white"], "pre")
        self.assertTrue(self.wrap_state()["hscroll"])
        page.keyboard.press("Escape")
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        self.assertFalse(page.locator(".wrap-toggle").is_checked())
        page.keyboard.press("Escape")

    def test_wrap_lines_english_label(self):
        page = self.open()
        page.click("[data-lang=en]")
        self.wait_logs()
        self.card("scanner").locator(".btn-log").click()
        page.wait_for_selector(".log-lines li")
        self.assertEqual(page.locator(".log-tools label.check").inner_text().strip(), "Wrap lines")
        page.keyboard.press("Escape")

    # ---------------------------------------------------------------- разрешения экранов
    def test_layout_popular_resolutions(self):
        # 10 самых распространённых разрешений настольных мониторов + 800×600 (консоль ВМ) и телефон
        sizes = [(1920, 1080), (1536, 864), (1366, 768), (1280, 720), (2560, 1440), (1440, 900), (1600, 900),
                 (1280, 1024), (1680, 1050), (3840, 2160), (800, 600), (390, 844)]
        probe = """() => {
          const cards = [...document.querySelectorAll('.card:not(.skeleton)')];
          const top = Math.round(cards[0].getBoundingClientRect().top);
          const wrapped = cards.filter(c => new Set([...c.querySelectorAll('.card-actions .btn')]
              .map(b => Math.round(b.getBoundingClientRect().top))).size > 1).length;
          const clipped = [...document.querySelectorAll('.btn, .kpi-label, .kpi-sub, .metric-label, .desc, .overall-title')]
              .filter(e => e.offsetParent && e.scrollWidth > e.clientWidth + 1).length;
          return {scroll: document.documentElement.scrollWidth, perRow: cards.filter(c => Math.round(c.getBoundingClientRect().top) === top).length,
                  wrapped: wrapped, clipped: clipped};
        }"""
        for width, height in sizes:
            page = self.browser.new_page(viewport={"width": width, "height": height})
            page.goto(self.srv.base + "/")
            page.wait_for_selector(".card[data-key=postgresql] .pill")
            page.wait_for_timeout(300)
            r = page.evaluate(probe)
            self.assertLessEqual(r["scroll"], width, (width, height))
            self.assertEqual(r["clipped"], 0, (width, height))
            if width >= 1100:
                self.assertEqual(r["perRow"], 3, "службы в два ряда: 3 + 3 (%dx%d)" % (width, height))
                self.assertEqual(r["wrapped"], 0, "кнопки карточки в одну строку (%dx%d)" % (width, height))
            elif width >= 600:
                self.assertEqual(r["perRow"], 2)
            else:
                self.assertEqual(r["perRow"], 1)
            page.close()

    def test_mobile_layout_no_horizontal_scroll(self):
        page = self.browser.new_page(viewport={"width": 390, "height": 844})
        page.goto(self.srv.base + "/")
        page.wait_for_selector(".card .pill")
        self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
        page.wait_for_timeout(600)
        clipped = page.evaluate("Array.prototype.filter.call(document.querySelectorAll("
                                "'.kpi-label, .kpi-sub, .metric-label, .desc, .overall-title'),"
                                " function (el) { return el.scrollWidth > el.clientWidth + 1; }).length")
        self.assertEqual(clipped, 0, "на телефоне подписи не обрезаются многоточием")
        if SHOTS:
            page.screenshot(path=os.path.join(SHOTS, "mobile.png"), full_page=True)
        page.close()

    def test_csp_header_blocks_inline(self):
        resp = self.page.goto(self.srv.base + "/")
        csp = resp.headers.get("content-security-policy", "")
        self.assertTrue(re.search(r"script-src 'self'(;|$)", csp))


def os_shadow(directory, value):
    from helpers import make_shadow
    return make_shadow(directory, hash_override=value)


if __name__ == "__main__":
    unittest.main()
