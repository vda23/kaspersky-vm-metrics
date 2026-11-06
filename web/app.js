/* Kaspersky VM Metrics — web UI. Без внешних зависимостей; работает под строгим CSP. */
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
