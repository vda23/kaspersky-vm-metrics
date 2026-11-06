# События для SIEM: формат и поля

Описание всего, что Kaspersky VM Metrics отправляет в SIEM, — для написания парсера (нормализатора). Полный образец со всеми типами событий: [siem-events-sample.log](siem-events-sample.log). Он получен функциями самого сервиса, поэтому совпадает с тем, что приходит в SIEM, байт в байт.

## Транспорт

| | TCP (рекомендуется) | UDP |
|---|---|---|
| Кадрирование | одно событие — одна строка, разделитель `\n` (LF, 0x0A) | одно событие — одна датаграмма, без `\n` в конце |
| Длина события | до 16 384 байт, длиннее — обрезается и заканчивается на `...` | до 2048 байт, длиннее — обрезается и заканчивается на `...` |
| Кодировка | UTF-8 (текст сообщений бывает на русском) | UTF-8 |
| Соединение | постоянное; при обрыве — переподключение, событие повторяется | — |

Переводов строк внутри события не бывает, пробелы везде одиночные: табуляции, переводы строк и повторяющиеся пробелы в значениях заменяются одним пробелом.

## Строка целиком

```
<PRI>Mmm dd hh:mm:ss HOST CEF:0|Kaspersky|Kaspersky VM Metrics|VERSION|SIGNATURE|NAME|SEVERITY|EXTENSION
```

Пример:

```
<131>Nov 6 12:04:19 kasperskyvm.sales.lab CEF:0|Kaspersky|Kaspersky VM Metrics|1.0.0|212|Service restart failed|4|rt=1793955859875 dvchost=kasperskyvm.sales.lab cat=service msg=Restart of kaspersky-vm-worker.service: service failed to start after 4 s src=10.60.250.129 suser=root act=restart outcome=failure cs1Label=unit cs1=kaspersky-vm-worker.service cs2Label=state cs2=failed cs3Label=component cs3=worker
```

### Заголовок syslog (RFC 3164)

| Часть | Значение |
|---|---|
| `<PRI>` | facility `local0` (16) × 8 + severity syslog: `<130>`…`<134>` (таблица ниже) |
| Дата и время | `Mmm d hh:mm:ss` — месяц по-английски, день без ведущего пробела и нуля (`Nov 6`, `Nov 16`), **местное время сервера**, без года и часового пояса. Точное время — в поле `rt` |
| `HOST` | полное имя сервера Kaspersky VM (FQDN), без пробелов |
| Тег приложения | нет: сразу после имени хоста идёт `CEF:0` |

| PRI | Severity syslog | CEF Severity |
|---|---|---|
| `<130>` | 2 — critical | 5 |
| `<131>` | 3 — error | 4 |
| `<132>` | 4 — warning | 3 |
| `<133>` | 5 — notice | 2 |
| `<134>` | 6 — informational | 1 |

Регулярное выражение для заголовка:

```
^<(?<pri>\d{1,3})>(?<month>[A-Z][a-z]{2}) {1,2}(?<day>\d{1,2}) (?<time>\d{2}:\d{2}:\d{2}) (?<host>\S+) (?<cef>CEF:0\|.*)$
```

### Заголовок CEF

| № | Поле CEF | Значение | Поле KUMA |
|---|---|---|---|
| 1 | Version | `CEF:0` | — |
| 2 | Device Vendor | `Kaspersky` | DeviceVendor |
| 3 | Device Product | `Kaspersky VM Metrics` | DeviceProduct |
| 4 | Device Version | версия сервиса, например `1.0.0` | DeviceVersion |
| 5 | Signature ID | код события, 100–900 (каталог ниже) | DeviceEventClassID |
| 6 | Name | название события по-английски | Name |
| 7 | Severity | 1–5: 1 — информация, 2 — низкая, 3 — средняя, 4 — высокая, 5 — критическая | Severity |

В заголовке экранируются `\` → `\\` и `|` → `\|`. Сейчас ни в одном названии этих символов нет.

### Расширение (extension)

Пары `ключ=значение` через пробел. Значения сами могут содержать пробелы, поэтому граница значения — следующий ` ключ=` из таблицы ниже, а не первый пробел. Пустые поля не отправляются; порядок ключей фиксирован: `rt dvchost cat msg`, затем остальные по таблице.

| Ключ | Тип | Есть в событиях | Значение | Поле KUMA |
|---|---|---|---|---|
| `rt` | число | всех | время события, мс с 01.01.1970 UTC | DeviceReceiptTime / Timestamp |
| `dvchost` | строка | всех | FQDN сервера Kaspersky VM | DeviceHostName |
| `cat` | строка | всех | категория: `monitor`, `service`, `auth`, `config`, `system`, `log`, `report`, `test` | DeviceEventCategory |
| `msg` | строка | всех | текст события (английский; цитаты из логов — как есть, в том числе по-русски) | Message |
| `src` | IPv4/IPv6 | 210–213, 300–302, 310, 900 | IP-адрес браузера, из которого выполнено действие | SourceAddress |
| `suser` | строка | 210–213, 300, 301, 310 | всегда `root` (действие подтверждено паролем root) | SourceUserName |
| `act` | строка | 210–213, 300–302, 310 | `restart` или `siem_settings` | DeviceAction |
| `outcome` | строка | 210–213, 300–302, 310, 600 | `success` / `failure`; для 600 — статус отчёта `ok` / `warning` / `critical` | EventOutcome |
| `filePath` | строка | 500, 600 | путь к лог-файлу или к файлу отчёта | FilePath |
| `cnt` | целое | 203, 500 | 203 — сколько раз systemd перезапустил службу с прошлой проверки; 500 — число новых записей с ошибками | BaseEventCount |
| `cs1Label`, `cs1` | строка | 200–203, 210–213 | `unit` — имя службы systemd | DeviceCustomString1(Label) |
| `cs2Label`, `cs2` | строка | 200–203, 211–213 | `state` — состояние службы: `active`, `inactive`, `failed`, `activating`… | DeviceCustomString2(Label) |
| `cs3Label`, `cs3` | строка | 200–203, 210–213, 500 | `component` — ключ службы: `scanner`, `vms`, `worker`, `privateapi`, `publicapi`, `postgresql` | DeviceCustomString3(Label) |
| `cs4Label`, `cs4` | строка | 402, 403 | `path` — точка монтирования файловой системы | DeviceCustomString4(Label) |
| `cs5Label`, `cs5` | строка | 310, 900 | `target` — адрес SIEM: `хост:порт/протокол`, при выключении `-` | DeviceCustomString5(Label) |
| `cfp1Label`, `cfp1` | дробное | 400–403 | `percent` — занято, % (одна цифра после точки) | DeviceCustomFloatingPoint1(Label) |

Названия полей KUMA — по модели данных, совпадающей со словарём ArcSight CEF; проверьте их в своей версии KUMA. Готовый нормализатор [OOTB] Syslog-CEF разбирает этот формат без доработки.

### Экранирование в расширении

| Символ в значении | Передаётся как |
|---|---|
| `\` | `\\` |
| `=` | `\=` |
| табуляция, перевод строки, несколько пробелов подряд | один пробел |

`|` и пробелы в расширении не экранируются. Пример из образца — исходный текст `query a=b; path C:\Temp\scan | rc=1` + перевод строки + `second line`:

```
msg=Scanner: 2 new error record(s). Last: query a\=b; path C:\\Temp\\scan | rc\=1 second line filePath=...
```

## Каталог событий

| ID | Name | CEF Sev. | PRI | `cat` | Поля, кроме `rt dvchost cat msg` | Когда |
|---|---|---|---|---|---|---|
| 100 | Monitoring service started | 1 | 134 | monitor | — | сервис мониторинга запущен |
| 101 | Monitoring service stopped | 2 | 133 | monitor | — | сервис остановлен (`systemctl stop`, обновление) |
| 200 | Service is running | 1 | 134 | service | cs1 cs2 cs3 | служба Kaspersky VM снова работает |
| 201 | Service stopped | 4 | 131 | service | cs1 cs2 cs3 | служба остановилась |
| 202 | Service failed | 5 | 130 | service | cs1 cs2 cs3 | служба завершилась сбоем |
| 203 | Service restarted by systemd | 3 | 132 | service | cnt cs1 cs2 cs3 | systemd перезапустил службу после сбоя |
| 210 | Service restart requested | 2 | 133 | service | src suser act outcome cs1 cs3 | перезапуск из дашборда запрошен |
| 211 | Service restart completed | 1 | 134 | service | src suser act outcome cs1 cs2 cs3 | перезапуск завершён успешно |
| 212 | Service restart failed | 4 | 131 | service | src suser act outcome cs1 [cs2] cs3 | служба не запустилась, либо `systemctl` вернул ошибку (тогда без `cs2`, причина — в `msg`) |
| 213 | Service restart timed out | 4 | 131 | service | src suser act outcome cs1 cs2 cs3 | перезапуск не завершился за 180 с |
| 300 | Wrong root password | 3 | 132 | auth | src suser act outcome | неверный пароль root; в `msg` — сколько попыток осталось |
| 301 | Client blocked after failed root password attempts | 4 | 131 | auth | src suser act outcome | 5 ошибок за 10 мин — IP заблокирован на 5 мин |
| 302 | Request from foreign origin rejected | 4 | 131 | auth | src act outcome | запрос с чужого сайта (CSRF) отклонён |
| 310 | SIEM forwarding settings changed | 3 | 132 | config | src suser act outcome cs5 | включена, выключена или изменена отправка в SIEM |
| 400 | High memory usage | 3 | 132 | system | cfp1 | занято ≥ 90 % ОЗУ |
| 401 | Memory usage back to normal | 1 | 134 | system | cfp1 | ОЗУ снова < 85 % |
| 402 | Low disk space | 4 | 131 | system | cs4 cfp1 | файловая система заполнена ≥ 90 % |
| 403 | Disk space back to normal | 1 | 134 | system | cs4 cfp1 | снова < 85 % |
| 500 | Errors in component log | 3 | 132 | log | filePath cnt cs3 | новые записи с ошибками в логе компонента; не чаще раза в минуту на файл; в `msg` — последняя ошибка |
| 600 | Daily state report created | 1 | 134 | report | outcome filePath | сформирован ежедневный отчёт (19:00) |
| 900 | Test event | 1 | 134 | test | src cs5 | кнопка «Отправить тестовое событие» |

### Шаблоны `msg`

| ID | Шаблон |
|---|---|
| 100 | `Kaspersky VM Metrics <версия> started (<https|http>://<хост>:<порт>)` |
| 101 | `Kaspersky VM Metrics <версия> stopped` |
| 200 | `Service <unit> is running (was <прежнее состояние>)` |
| 201 | `Service <unit> is <состояние>` |
| 202 | `Service <unit> failed (was <прежнее состояние>)` |
| 203 | `Service <unit> was restarted by systemd (<N> times since boot)` |
| 210 | `Restart of <unit> requested` |
| 211 | `Restart of <unit>: completed after <N> s` |
| 212 | `Restart of <unit>: service failed to start after <N> s` или `Restart of <unit> failed: <ошибка systemctl>` |
| 213 | `Restart of <unit>: not finished after <N> s` |
| 300 | `Wrong root password (<restart|siem_settings|siem_test>), attempts left: <N>` |
| 301 | `Client <IP> blocked for <N> s after failed root password attempts` |
| 302 | `<действие> request from foreign origin rejected` |
| 310 | `SIEM forwarding <enabled|disabled>: <хост:порт/протокол или ->` |
| 400, 401 | `Memory usage <N.N>%` |
| 402, 403 | `Filesystem <путь> is <N.N>% full` |
| 500 | `<компонент>: <N> new error record(s). Last: <текст последней ошибки>` |
| 600 | `Daily state report: <ok|warning|critical>, services running <N> of <M>, log errors today <N>` |
| 900 | `Kaspersky VM Metrics test event` |

Компоненты в событии 500: `Worker`, `Vulnerability scanning module` (scanner), `Vulnerability detection module` (vms), `Private API`, `Public API`.

## Что учесть в парсере

- Год в заголовке syslog отсутствует (RFC 3164): время события берите из `rt`.
- Одна строка — одно событие; многострочных событий нет.
- `msg` событий 500 цитирует логи компонентов: там могут быть кавычки, кириллица, `|`, а также экранированные `\=` и `\\`.
- `src` есть только у действий из браузера; у событий мониторинга (200–203, 400–403, 500) источника нет.
- Корреляция: перезапуск из дашборда — 210, затем 211, 212 или 213 с тем же `cs1`; подбор пароля — серия 300 с одного `src`, затем 301.
