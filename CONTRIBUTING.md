# Участие в разработке

## Окружение

```bash
git clone https://github.com/OWNER/kaspersky-vm-metrics.git
cd kaspersky-vm-metrics
pip install coverage playwright vermin pyflakes   # для разработки
playwright install chromium                        # для UI-тестов
python3 tests/demo_server.py                       # демо: http://127.0.0.1:<порт>, пароль root: S3cret!pass
```

Шрифт и логотипы не хранятся в git. Для внешнего вида как в поставке положите их в `assets/` (см. [assets/README.md](assets/README.md)).

## Правила кода

- **Python 3.5+, только стандартная библиотека.** Штатный Python на Astra Linux CE 2.12 — 3.5, на SberLinux 8 — 3.6. Поэтому нельзя использовать:
  - f-строки и аннотации переменных;
  - `subprocess.run(capture_output=..., text=...)`;
  - `ThreadingHTTPServer` и `secrets`;
  - `async`.

  Это проверяют `vermin -t=3.5-` и тест `CompatibilityTest`. Ветки для новых версий Python оформляются через `hasattr` с пометкой `# novermin`.
- **Сервис — один файл.** Интерфейс правится в `web/`, затем встраивается командой `python3 tools/embed_assets.py`. Тест `test_assets` проверяет, что скрипт и `web/` совпадают.
- **Интерфейс работает под строгим CSP.** В `index.html` нельзя использовать inline-скрипты, атрибуты `style=` и `onclick=`. В JS запрещены `innerHTML` и `eval`. DOM строится функцией `h()`, а строки выводятся только через `textContent`.
- **Внешние команды** запускаются через `run_cmd()` списком аргументов, без оболочки и с таймаутом. Пути к файлам и имена служб берутся из кода, а не из запроса.
- **`install.sh`** должен проходить `shellcheck -S warning`. Каждая функция должна вызываться в тестах: это проверяет покрытие функций.
- Тексты интерфейса задаются в словаре `I18N` (`web/app.js`) на обоих языках; тест проверяет, что ключи совпадают.

## Тесты

```bash
bash tests/run_tests.sh                 # все тесты
bash tests/run_tests.sh --coverage      # + покрытие: Python ≥95%, JS ≥90%, функции install.sh 100%
python3 -m unittest tests.test_http     # один модуль (из корня: cd tests && python3 -m unittest test_http)
KVM_UI_SCREENSHOTS=/tmp/shots python3 -m unittest test_ui   # UI-тесты со скриншотами
```

| Модуль | Что проверяет |
|---|---|
| `test_parsers`, `test_logs`, `test_today_logs` | разбор вывода systemctl, ss и /proc; чтение логов; архив за день |
| `test_collector`, `test_restart_auth` | сбор состояния и кэш; перезапуск служб; проверка пароля root и блокировка |
| `test_http`, `test_edge_cases` | HTTP API, TLS, CSRF, запуск `main()`, фоновые задачи, обработка ошибок |
| `test_system`, `test_branding_cpu` | сертификат, watchdog, самопроверка, логотипы, загрузка ЦП |
| `test_installer` | все сценарии `install.sh` на заглушках: установка, обновление, откат, архив |
| `test_assets` | синхронизация интерфейса, CSP, i18n, совместимость с Python 3.5 |
| `test_ui` | браузерные сценарии в Chromium и покрытие JS |

Системные команды (`systemctl`, `ss`, `journalctl`) в тестах заменяет `FakeSystem` из `tests/helpers.py`. Сервер поднимается на `127.0.0.1` со случайным портом.

## Выпуск версии

1. Увеличьте `__version__` в `kaspersky-vm-metrics.py` по [SemVer](https://semver.org/lang/ru/); при необходимости обновите README.md.
2. Прогоните `bash tests/run_tests.sh --coverage`.
3. Создайте тег `vX.Y.Z` и отправьте его в репозиторий. Workflow `release` соберёт архив и опубликует релиз:
   ```bash
   git tag v1.1.0 && git push origin v1.1.0
   ```
4. В архиве релиза на GitHub нет шрифта и логотипов. Для поставки с фирменным оформлением соберите архив локально: `bash tools/build_dist.sh` с файлами в `assets/`.

## Pull request

- Одна задача — один PR, описание по шаблону.
- CI должен быть зелёным, покрытие не должно падать ниже порогов.
- Изменения, видимые пользователю, отражаются в README.md.
