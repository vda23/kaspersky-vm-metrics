#!/bin/bash
#
# Kaspersky VM Metrics — установщик
# Поддерживаемые ОС (64-разрядные):
#   - Альт Рабочая станция 11.2 (ARM64), Альт Сервер 11.0
#   - Альт СП Рабочая станция 10, Альт СП Сервер 10
#   - РЕД ОС 8.0, в том числе сертифицированная редакция
#   - Astra Linux Common Edition 2.12 (режим замкнутой программной среды не поддерживается)
#   - Astra Linux Special Edition РУСБ.10015-01 1.8.5, в том числе в режиме замкнутой программной среды
#   - Debian 13.0
#   - Platform V SberLinux OS Server (SLO) 9.6
#   - Ubuntu Server 24.04 LTS, Ubuntu Server 26.04 LTS
#
# Использование:
#   sudo bash install.sh              установка, а если сервис уже установлен — обновление
#   sudo bash install.sh --port 9443  установка или обновление с другим портом (по умолчанию 8999);
#                                     порт запоминается, при следующих обновлениях указывать не нужно
#   sudo bash install.sh --force      переустановить ту же или более старую версию
#   sudo bash install.sh --cert server.crt --key server.key
#                                     сертификат организации вместо самоподписанного (PEM, ключ без пароля);
#                                     --chain ca.crt — промежуточные сертификаты, если они в отдельном файле
#   sudo bash install.sh --self-signed  вернуть самоподписанный сертификат
#   sudo bash install.sh --rollback   вернуть предыдущую версию из резервной копии
#   sudo bash install.sh --status     установленная и работающая версии
#   sudo bash install.sh --preflight  проверка готовности сервера (ничего не меняет)
#   sudo bash install.sh --diag       архив диагностики для разбора замечаний
#   sudo bash install.sh --uninstall  удалить службу (сертификат и отчёты сохраняются)
#   sudo bash install.sh --uninstall --purge   удалить полностью
#
# Обновление бесшовное: служба не удаляется; сертификат (в том числе сертификат организации) и отчёты
# сохраняются; перед заменой файлов создаётся резервная копия; после перезапуска
# проверяется /healthz, при неудаче выполняется автоматический откат.
#

set -e

SCRIPT_NAME="kaspersky-vm-metrics.py"
FONT_NAME="KasperskySans-Regular.ttf"
# Свои логотипы вместо встроенного (необязательно): кладутся рядом с install.sh или в assets/
BRAND_FILES="logo.svg logo.png logo-dark.svg logo-dark.png logo-light.svg logo-light.png favicon.svg favicon.png"
SERVICE_NAME="kaspersky-vm-metrics"
INSTALL_DIR="${INSTALL_DIR:-/opt/kaspersky-vm-metrics}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
BACKUP_DIR="${BACKUP_DIR:-$INSTALL_DIR/backup}"
KEEP_BACKUPS="${KEEP_BACKUPS:-3}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"
DEFAULT_PORT=8999
PORT="$DEFAULT_PORT"     # уточняется в resolve_port: --port, порт установленного сервиса или 8999
REQUESTED_PORT=""
PORT_GIVEN=0
OLD_PORT=""
PYTHON_MIN="3.5"
FORCE=0
PURGE=0
CERT_SRC=""       # --cert: сертификат организации
KEY_SRC=""        # --key: его закрытый ключ
CHAIN_SRC=""      # --chain: промежуточные сертификаты отдельным файлом
CERT_RESET=0      # --self-signed: вернуть самоподписанный сертификат
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Цвета
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

# Проверка прав
check_root() {
    if [ "$EUID" -ne 0 ]; then
        err "Запустите от root: sudo bash install.sh"
    fi
}

# Определение ОС и архитектуры
detect_os() {
    local os_release="${OS_RELEASE_FILE:-/etc/os-release}"
    if [ -f "$os_release" ]; then
        # shellcheck disable=SC1090
        . "$os_release"
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_VERSION="${VERSION_ID:-}"
        OS_NAME="${PRETTY_NAME:-${NAME:-$OS_ID}}"
    else
        err "Не удалось определить ОС"
    fi
    OS_ARCH="$(uname -m 2>/dev/null || echo unknown)"
    log "ОС: $OS_NAME ($OS_ARCH)"
    case "$OS_ARCH" in
        x86_64|amd64|aarch64|arm64) ;;
        *) warn "Архитектура $OS_ARCH не проверялась (поддерживаются x86_64 и ARM64); сервис написан на Python и, скорее всего, заработает" ;;
    esac
}

# Семейство пакетного менеджера: apt (Альт, Astra, Debian, Ubuntu) или dnf (РЕД ОС, SberLinux);
# для неизвестного ID — по ID_LIKE из /etc/os-release
os_family() {
    case "$OS_ID" in
        altlinux|alt|astra|astra-linux|debian|ubuntu) echo apt; return ;;
        redos|redoslinux|sberlinux|slo|sberos) echo dnf; return ;;
    esac
    case " $OS_ID_LIKE " in
        *" debian "*|*" ubuntu "*|*" altlinux "*) echo apt ;;
        *" rhel "*|*" fedora "*|*" centos "*) echo dnf ;;
    esac
}

# Установка пакета штатным менеджером ОС: pkg_install <deb/alt/astra-пакет> <rpm-пакет>
pkg_install() {
    local deb_pkg="$1" rpm_pkg="${2:-$1}"
    case "$(os_family)" in
        apt)
            apt-get update -y && apt-get install -y "$deb_pkg"
            ;;
        dnf)
            dnf install -y "$rpm_pkg" || yum install -y "$rpm_pkg"
            ;;
        *)
            warn "Неизвестная ОС, пробую универсальную установку..."
            if command -v apt-get &>/dev/null; then
                apt-get update -y && apt-get install -y "$deb_pkg"
            elif command -v dnf &>/dev/null; then
                dnf install -y "$rpm_pkg"
            elif command -v yum &>/dev/null; then
                yum install -y "$rpm_pkg"
            else
                return 1
            fi
            ;;
    esac
}

# Установка Python3
install_python() {
    if ! command -v python3 &>/dev/null; then
        warn "Python3 не найден, устанавливаю..."
        pkg_install python3 python3 || err "Не удалось установить Python3"
        log "Python3 установлен"
    fi
    PYTHON_BIN="$(command -v python3)"
    if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 5) else 1)'; then
        err "Нужен Python >= $PYTHON_MIN, найден: $("$PYTHON_BIN" --version 2>&1)"
    fi
    log "Python3: $("$PYTHON_BIN" --version 2>&1) ($PYTHON_BIN)"
}

# Установка openssl (для HTTPS)
install_openssl() {
    if command -v openssl &>/dev/null; then
        log "OpenSSL: $(openssl version | awk '{print $1, $2}')"
        return
    fi
    warn "OpenSSL не найден, устанавливаю..."
    pkg_install openssl openssl || err "Не удалось установить OpenSSL"
    log "OpenSSL установлен"
}

# Утилита ss (iproute2) — для панели «Статус соединений» и счётчика подключений к БД
install_ss() {
    if command -v ss &>/dev/null; then
        return
    fi
    warn "Утилита ss не найдена, устанавливаю iproute2..."
    pkg_install iproute2 iproute || warn "Не удалось установить iproute2 — панель соединений будет пустой"
}

# Атомарная замена файла: копия во временный файл + rename.
# Работающий процесс не затрагивается, «полузаписанного» файла не бывает.
atomic_copy() {
    cp "$1" "$2.new"
    mv -f "$2.new" "$2"
}

# Путь к файлу оформления в пакете (рядом с install.sh или в assets/); пусто — файла нет
asset_path() {
    if [ -f "$SRC_DIR/$1" ]; then
        echo "$SRC_DIR/$1"
    elif [ -f "$SRC_DIR/assets/$1" ]; then
        echo "$SRC_DIR/assets/$1"
    fi
}

# Копирование файлов
install_files() {
    local font name src
    mkdir -p "$INSTALL_DIR"

    if [ -f "$SRC_DIR/$SCRIPT_NAME" ]; then
        atomic_copy "$SRC_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$SCRIPT_NAME"
    else
        err "Файл $SCRIPT_NAME не найден рядом с установщиком"
    fi

    font="$(asset_path "$FONT_NAME")"
    if [ -n "$font" ]; then
        atomic_copy "$font" "$INSTALL_DIR/$FONT_NAME"
        log "Шрифт $FONT_NAME установлен"
    elif [ -f "$INSTALL_DIR/$FONT_NAME" ]; then
        log "Шрифт $FONT_NAME уже установлен"
    else
        warn "Шрифт $FONT_NAME не найден — будет использован системный"
    fi

    for name in $BRAND_FILES; do
        src="$(asset_path "$name")"
        if [ -n "$src" ]; then
            atomic_copy "$src" "$INSTALL_DIR/$name"
            chmod 644 "$INSTALL_DIR/$name"
            log "Логотип $name установлен"
        fi
    done

    # Файлы прежних версий, которые больше не нужны
    rm -f "$INSTALL_DIR/config.example.json"

    # Копия установщика остаётся в каталоге сервиса: для --rollback и --status
    if [ "$SRC_DIR" != "$INSTALL_DIR" ] && [ -f "$SRC_DIR/install.sh" ]; then
        atomic_copy "$SRC_DIR/install.sh" "$INSTALL_DIR/install.sh"
        chmod 755 "$INSTALL_DIR/install.sh"
    fi

    chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"
    # «|| true»: при set -e отсутствие шрифта не должно прерывать установку
    chmod 644 "$INSTALL_DIR/$FONT_NAME" 2>/dev/null || true
    chown root:root "$INSTALL_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$FONT_NAME" 2>/dev/null || true
    log "Файлы установлены в $INSTALL_DIR"
}

# Создание systemd-службы. Файл заменяется и daemon-reload выполняется только при изменениях.
create_service() {
    local unit="${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    cat > "${unit}.new" << EOF
[Unit]
Description=Kaspersky VM Metrics Service
After=network.target

[Service]
Type=simple
ExecStart=${PYTHON_BIN:-/usr/bin/python3} ${INSTALL_DIR}/${SCRIPT_NAME} --port ${PORT}
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
TimeoutStartSec=10
TimeoutStopSec=10
# Сервис сам отправляет WATCHDOG=1 (sd_notify), пока его HTTP-цикл жив
WatchdogSec=60
NotifyAccess=main

[Install]
WantedBy=multi-user.target
EOF

    if [ -f "$unit" ] && cmp -s "${unit}.new" "$unit"; then
        rm -f "${unit}.new"
        log "Служба ${SERVICE_NAME}.service не изменилась"
        return
    fi
    mv -f "${unit}.new" "$unit"
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload
    fi
    log "Служба ${SERVICE_NAME}.service создана"
}

# SELinux
configure_selinux() {
    if command -v getenforce &>/dev/null && [ "$(getenforce)" != "Disabled" ]; then
        warn "Настраиваю SELinux..."
        chcon -R -t bin_t "$INSTALL_DIR/" 2>/dev/null || true
        semanage port -a -t http_port_t -p tcp "$PORT" 2>/dev/null \
            || semanage port -m -t http_port_t -p tcp "$PORT" 2>/dev/null || true
        log "SELinux настроен"
    fi
}

# Файрвол
configure_firewall() {
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        firewall-cmd --add-port=${PORT}/tcp --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        log "Порт $PORT открыт (firewalld)"
    elif command -v ufw &>/dev/null; then
        ufw allow $PORT/tcp 2>/dev/null || true
        log "Порт $PORT открыт (ufw)"
    elif command -v iptables &>/dev/null; then
        # -C: не дублировать правило при повторной установке
        iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || true
        log "Порт $PORT открыт (iptables)"
    elif command -v nft &>/dev/null; then
        # Debian 13 и др.: только nftables; имена таблиц у всех разные — правило не добавляем сами
        warn "Межсетевой экран nftables: если входящие соединения ограничены, откройте порт $PORT/tcp"
    fi
}

# Закрыть порт в межсетевом экране (удаление, смена порта, откат)
close_firewall_port() {
    local port="$1"
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        firewall-cmd --remove-port="${port}/tcp" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    elif command -v ufw &>/dev/null; then
        ufw delete allow "$port/tcp" 2>/dev/null || true
    elif command -v iptables &>/dev/null; then
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------- порт

valid_port() {
    case "$1" in
        ''|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# Порт установленного сервиса: из ExecStart unit-файла (--port N); без него — 8999
installed_port() {
    local unit="${SYSTEMD_DIR}/${SERVICE_NAME}.service" port=""
    if [ -f "$unit" ]; then
        port="$(sed -n 's/^ExecStart=.* --port \([0-9][0-9]*\).*/\1/p' "$unit" | head -n 1)"
    fi
    echo "${port:-$DEFAULT_PORT}"
}

# Порт для этого запуска: --port, иначе порт уже установленного сервиса, иначе 8999
resolve_port() {
    OLD_PORT=""
    if is_installed; then
        OLD_PORT="$(installed_port)"
    fi
    if [ -n "$REQUESTED_PORT" ]; then
        PORT="$REQUESTED_PORT"
    else
        PORT="${OLD_PORT:-$DEFAULT_PORT}"
    fi
}

# Редакция Astra Linux: SE (VERSION_ID 1.x, например 1.8_x86-64) или CE (2.x, Orel 2.12)
astra_edition() {
    [ "$OS_ID" = "astra" ] || return 0
    case "$OS_VERSION" in
        1.*) echo SE ;;
        2.*) echo CE ;;
        *) if [ -f /etc/astra/secinfo ]; then echo SE; else echo CE; fi ;;
    esac
}

# Замкнутая программная среда (ЗПС) Astra Linux: включена ли проверка подписи исполняемых файлов
astra_zps_active() {
    command -v astra-digsig-control &>/dev/null || return 1
    [ "$(astra-digsig-control is-enabled 2>/dev/null)" = "ACTIVE" ]
}

# Astra Linux: сервис не содержит собственных исполняемых файлов — только скрипт Python, который
# запускается подписанными программами ОС (python3, systemctl, ss, openssl, tail, journalctl).
configure_astra_se() {
    local edition
    edition="$(astra_edition)"
    [ -n "$edition" ] || return 0
    if ! astra_zps_active; then
        log "Astra Linux $edition: замкнутая программная среда выключена"
        return 0
    fi
    if [ "$edition" = "CE" ]; then
        warn "Astra Linux CE в режиме замкнутой программной среды не поддерживается"
        return 0
    fi
    log "Astra Linux SE: замкнутая программная среда включена — сервис использует только подписанные программы ОС"
    log "Подпись файлов сервиса не требуется, пока ЗПС не контролирует подписи скриптов в расширенных атрибутах"
}

# Кнопки перезапуска в интерфейсе требуют пароль root
check_root_password() {
    local status
    status="$(passwd -S root 2>/dev/null | awk '{print $2}')"
    case "$status" in
        L|LK|NP)
            warn "У root не задан пароль или учётная запись заблокирована."
            warn "Чтобы перезапускать службы из интерфейса, задайте пароль: passwd root"
            ;;
    esac
}

# Запуск
start_service() {
    systemctl enable "$SERVICE_NAME" 2>/dev/null || warn "Не удалось включить автозагрузку"
    systemctl restart "$SERVICE_NAME" 2>/dev/null || warn "Не удалось запустить службу"

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Служба запущена"
    else
        warn "Служба не запустилась: systemctl status $SERVICE_NAME"
    fi
}

# Версия, которую отдаёт работающий сервис (/healthz); пусто, если он не отвечает
health_version() {
    local body=""
    if command -v curl &>/dev/null; then
        body="$(curl -sk --max-time 3 "https://localhost:$PORT/healthz" 2>/dev/null || true)"
    else
        body="$("${PYTHON_BIN:-python3}" -c '
import ssl, sys, urllib.request
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    print(urllib.request.urlopen("https://localhost:%s/healthz" % sys.argv[1], context=ctx, timeout=3).read().decode())
except Exception:
    pass
' "$PORT" 2>/dev/null || true)"
    fi
    echo "$body" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p'
}

# Ждать, пока сервис ответит ожидаемой версией (или любой, если версия не задана)
wait_healthy() {
    local expected="$1" waited=0 got=""
    while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
        got="$(health_version)"
        if [ -n "$got" ] && { [ -z "$expected" ] || [ "$got" = "$expected" ]; }; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Проверка после установки
check() {
    if wait_healthy ""; then
        FQDN=$(hostname -f 2>/dev/null || hostname)
        log "Дашборд: https://$FQDN:$PORT/"
    else
        warn "Дашборд пока недоступен"
    fi
}

# ---------------------------------------------------------------- сертификат организации

# Файлы указываются относительно текущего каталога — запоминаем абсолютный путь
abs_path() {
    case "$1" in
        /*) echo "$1" ;;
        *) echo "$PWD/$1" ;;
    esac
}

cert_end() {
    openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2
}

cert_fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

# Отпечаток сертификата, который сейчас отдаёт сервис (пусто — не удалось подключиться)
served_fingerprint() {
    echo | openssl s_client -connect "localhost:$PORT" 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

# Хеш открытого ключа: у сертификата и у закрытого ключа из одной пары он одинаковый
cert_pubkey_hash() {
    openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}'
}

key_pubkey_hash() {
    openssl pkey -in "$1" -pubout -passin pass: 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}'
}

# DNS-имена из расширения Subject Alternative Name, по одному в строке
cert_dns_names() {
    openssl x509 -in "$1" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -n 1 \
        | tr ',' '\n' | sed -n 's/^ *DNS: *\(.*\)$/\1/p' | tr '[:upper:]' '[:lower:]'
}

# true, если имя сервера есть в сертификате (в том числе по маске *.domain)
host_in_cert() {
    local host name
    host="$(echo "$2" | tr '[:upper:]' '[:lower:]')"
    while read -r name; do
        [ -n "$name" ] || continue
        [ "$name" = "$host" ] && return 0
        case "$name" in
            \*.*) [ "$host" != "${host#*.}" ] && [ "${host#*.}" = "${name#\*.}" ] && return 0 ;;
        esac
    done <<< "$(cert_dns_names "$1")"
    return 1
}

# Проверка сертификата организации до любых изменений: формат, ключ без пароля, пара, срок, имя
validate_cert() {
    local cert="$1" key="$2" chain="$3" host subject issuer
    { [ -f "$cert" ] && [ -r "$cert" ]; } || err "Файл сертификата не найден: $cert"
    { [ -f "$key" ] && [ -r "$key" ]; } || err "Файл ключа не найден: $key"
    # OpenSSL 3 сам распознаёт DER, а сервису нужен PEM — проверяем заголовок явно
    if ! grep -q -- "-----BEGIN CERTIFICATE-----" "$cert" 2>/dev/null || ! openssl x509 -in "$cert" -noout 2>/dev/null; then
        if openssl x509 -inform DER -in "$cert" -noout 2>/dev/null; then
            err "Сертификат в формате DER. Преобразуйте его в PEM: openssl x509 -inform DER -in $cert -out cert.pem"
        fi
        err "$cert — не сертификат в формате PEM. Как получить PEM из .pfx/.p12 — в README, раздел «Сертификат организации»"
    fi
    if ! grep -q -- "PRIVATE KEY-----" "$key" 2>/dev/null || ! openssl pkey -in "$key" -noout -passin pass: 2>/dev/null; then
        if grep -q "ENCRYPTED" "$key" 2>/dev/null; then
            err "Ключ зашифрован паролем: при запуске службы ввести его некому. Снимите пароль: openssl pkey -in $key -out key-nopass.pem"
        fi
        err "$key — не закрытый ключ в формате PEM"
    fi
    if [ "$(cert_pubkey_hash "$cert")" != "$(key_pubkey_hash "$key")" ]; then
        err "Ключ не подходит к сертификату: они из разных пар"
    fi
    if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        err "Срок действия сертификата истёк: $(cert_end "$cert")"
    fi
    if ! openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
        warn "Сертификат истекает меньше чем через 30 дней: $(cert_end "$cert")"
    fi
    if [ -n "$chain" ]; then
        { grep -q -- "-----BEGIN CERTIFICATE-----" "$chain" 2>/dev/null && openssl x509 -in "$chain" -noout 2>/dev/null; } \
            || err "$chain — не файл с сертификатами в формате PEM"
    else
        subject="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
        issuer="$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')"
        if [ "$(grep -c "BEGIN CERTIFICATE" "$cert")" -lt 2 ] && [ "$subject" != "$issuer" ]; then
            warn "В файле только сертификат сервера. Если браузер не доверяет ему, добавьте промежуточные сертификаты: --chain <файл>"
        fi
    fi
    host="$(hostname -f 2>/dev/null || hostname)"
    if ! host_in_cert "$cert" "$host"; then
        warn "В сертификате (SAN) нет имени $host: браузер покажет предупреждение, если дашборд открывают по этому имени"
    fi
    log "Сертификат проверен: $(openssl x509 -in "$cert" -noout -subject 2>/dev/null), действует до $(cert_end "$cert")"
}

# Прежние cert.pem, key.pem и метку — в *.prev (для отката)
save_prev_cert() {
    local name
    for name in cert.pem key.pem cert.org; do
        rm -f "$INSTALL_DIR/$name.prev"
        if [ -f "$INSTALL_DIR/$name" ]; then cp -p "$INSTALL_DIR/$name" "$INSTALL_DIR/$name.prev"; fi
    done
}

restore_prev_cert() {
    local name
    for name in cert.pem key.pem cert.org; do
        if [ -f "$INSTALL_DIR/$name.prev" ]; then
            mv -f "$INSTALL_DIR/$name.prev" "$INSTALL_DIR/$name"
        else
            rm -f "${INSTALL_DIR:?}/$name"
        fi
    done
}

# Установить сертификат организации, перезапустить службу и убедиться, что она отдаёт именно его;
# если нет — вернуть прежний сертификат
install_org_cert() {
    local cert="$1" key="$2" chain="$3" fp served
    mkdir -p "$INSTALL_DIR"
    save_prev_cert
    {
        cat "$cert"
        if [ -n "$chain" ]; then echo; cat "$chain"; fi
    } | sed '/^[[:space:]]*$/d' > "$INSTALL_DIR/cert.pem.new"
    cp "$key" "$INSTALL_DIR/key.pem.new"
    chmod 644 "$INSTALL_DIR/cert.pem.new"
    chmod 600 "$INSTALL_DIR/key.pem.new"
    chown root:root "$INSTALL_DIR/cert.pem.new" "$INSTALL_DIR/key.pem.new" 2>/dev/null || true
    mv -f "$INSTALL_DIR/key.pem.new" "$INSTALL_DIR/key.pem"
    mv -f "$INSTALL_DIR/cert.pem.new" "$INSTALL_DIR/cert.pem"
    fp="$(cert_fingerprint "$INSTALL_DIR/cert.pem")"
    printf 'installed=%s\nsource=%s\nsha256=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$cert" "$fp" > "$INSTALL_DIR/cert.org"
    chmod 644 "$INSTALL_DIR/cert.org"
    configure_selinux
    log "Перезапуск службы с сертификатом организации..."
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    if wait_healthy ""; then
        served="$(served_fingerprint)"
        if [ "$served" = "$fp" ]; then
            rm -f "$INSTALL_DIR"/cert.pem.prev "$INSTALL_DIR"/key.pem.prev "$INSTALL_DIR"/cert.org.prev
            log "Сервис работает с сертификатом организации (действует до $(cert_end "$INSTALL_DIR/cert.pem"))"
            return 0
        fi
        if [ -z "$served" ]; then
            warn "Не удалось проверить, какой сертификат отдаёт сервис: откройте дашборд и проверьте сертификат в браузере"
            return 0
        fi
    fi
    warn "Сервис не принял сертификат организации — возвращаю прежний"
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null | grep -i "certificate\|TLS" || true
    restore_prev_cert
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    wait_healthy "" || true
    err "Сертификат организации не установлен, сервис работает с прежним. Подробности: journalctl -u $SERVICE_NAME"
}

# Вернуть самоподписанный сертификат (сервис создаст его сам при запуске)
reset_cert() {
    if [ ! -f "$INSTALL_DIR/cert.org" ]; then
        log "Сертификат организации не установлен — уже используется самоподписанный"
        return 0
    fi
    save_prev_cert
    rm -f "$INSTALL_DIR/cert.pem" "$INSTALL_DIR/key.pem" "$INSTALL_DIR/cert.org"
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    if wait_healthy ""; then
        log "Возвращён самоподписанный сертификат: браузер один раз попросит подтвердить исключение"
        log "Прежний сертификат организации сохранён: $INSTALL_DIR/cert.pem.prev, key.pem.prev"
        return 0
    fi
    warn "Сервис не ответил после смены сертификата — возвращаю сертификат организации"
    restore_prev_cert
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    err "Не удалось перейти на самоподписанный сертификат. Подробности: journalctl -u $SERVICE_NAME"
}

# Строка для --status
cert_status() {
    local file="$INSTALL_DIR/cert.pem"
    if [ ! -f "$file" ]; then
        echo "нет (будет создан самоподписанный)"
    elif ! command -v openssl &>/dev/null; then
        echo "есть (openssl не найден, подробности недоступны)"
    elif [ -f "$INSTALL_DIR/cert.org" ]; then
        echo "организации, $(openssl x509 -in "$file" -noout -subject 2>/dev/null | sed 's/^subject= *//'), до $(cert_end "$file")"
    else
        echo "самоподписанный, до $(cert_end "$file")"
    fi
}

# ---------------------------------------------------------------- обновление и откат

script_version() {
    [ -f "$1" ] || return 0
    "${PYTHON_BIN:-python3}" "$1" --version 2>/dev/null || true
}

# true, если версия $1 строго меньше $2
version_lt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]
}

is_installed() {
    [ -f "$INSTALL_DIR/$SCRIPT_NAME" ] && [ -f "${SYSTEMD_DIR}/${SERVICE_NAME}.service" ]
}

# Целостность пакета: SHA256SUMS создаётся tools/build_dist.sh
verify_checksums() {
    if [ ! -f "$SRC_DIR/SHA256SUMS" ]; then
        warn "SHA256SUMS не найден — проверка целостности пакета пропущена"
        return
    fi
    if ! command -v sha256sum &>/dev/null; then
        warn "sha256sum не найден — проверка целостности пакета пропущена"
        return
    fi
    # Суммы сравниваются здесь, а не по коду возврата «sha256sum -c»: некоторые реализации
    # coreutils (uutils, Ubuntu 26.04) при несовпадении печатают FAILED, но возвращают 0.
    local sum name actual bad=0
    while read -r sum name; do
        [ -n "$sum" ] || continue
        name="${name#\*}"
        actual="$(sha256sum "$SRC_DIR/$name" 2>/dev/null | awk '{print $1}')"
        if [ "$actual" != "$sum" ]; then
            warn "Контрольная сумма не совпадает: $name"
            bad=1
        fi
    done < "$SRC_DIR/SHA256SUMS"
    [ "$bad" = 0 ] || err "Пакет повреждён: контрольные суммы не совпадают"
    log "Целостность пакета подтверждена"
}

# Самопроверка нового скрипта до замены файлов: запуск на этом Python, сборка интерфейса
preflight() {
    local out line
    if ! out="$("$PYTHON_BIN" "$SRC_DIR/$SCRIPT_NAME" --check 2>&1)"; then
        err "Самопроверка новой версии не пройдена, установленная версия не изменена:
$out"
    fi
    while read -r line; do
        case "$line" in WARN\ *) warn "${line#WARN }" ;; esac
    done <<< "$out"
    log "Самопроверка новой версии пройдена"
}

# Резервная копия текущей версии; печатает путь к ней
backup_current() {
    local version stamp dest name
    version="$(script_version "$INSTALL_DIR/$SCRIPT_NAME")"
    stamp="$(date +%Y%m%d-%H%M%S)"
    dest="$BACKUP_DIR/${version:-unknown}_$stamp"
    mkdir -p "$dest"
    cp -p "$INSTALL_DIR/$SCRIPT_NAME" "$dest/"
    for name in "$FONT_NAME" install.sh $BRAND_FILES; do
        if [ -f "$INSTALL_DIR/$name" ]; then cp -p "$INSTALL_DIR/$name" "$dest/"; fi
    done
    if [ -f "${SYSTEMD_DIR}/${SERVICE_NAME}.service" ]; then
        cp -p "${SYSTEMD_DIR}/${SERVICE_NAME}.service" "$dest/"
    fi
    echo "$dest"
}

list_backups() {
    # shellcheck disable=SC2012
    ls -1dt "$BACKUP_DIR"/*/ 2>/dev/null | sed 's:/$::' || true
}

# Оставить только KEEP_BACKUPS последних копий
prune_backups() {
    local old
    list_backups | tail -n +"$((KEEP_BACKUPS + 1))" | while read -r old; do
        [ -n "$old" ] && rm -rf "$old"
    done
}

# Восстановить файлы из резервной копии и перезапустить службу
restore_backup() {
    local src="$1" name
    atomic_copy "$src/$SCRIPT_NAME" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"
    for name in "$FONT_NAME" install.sh $BRAND_FILES; do
        if [ -f "$src/$name" ]; then atomic_copy "$src/$name" "$INSTALL_DIR/$name"; fi
    done
    if [ -f "$src/${SERVICE_NAME}.service" ]; then
        atomic_copy "$src/${SERVICE_NAME}.service" "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
        systemctl daemon-reload 2>/dev/null || true
    fi
    configure_selinux
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
}

# true, если в пакете есть файл, отличающийся от установленного (скрипт, шрифт, логотипы)
package_differs() {
    local name src
    cmp -s "$SRC_DIR/$SCRIPT_NAME" "$INSTALL_DIR/$SCRIPT_NAME" || return 0
    for name in "$FONT_NAME" $BRAND_FILES; do
        src="$(asset_path "$name")"
        if [ -n "$src" ] && ! cmp -s "$src" "$INSTALL_DIR/$name"; then
            return 0
        fi
    done
    return 1
}

do_update() {
    local old new backup owner port_changed=0 files_changed=0
    old="$(script_version "$INSTALL_DIR/$SCRIPT_NAME")"
    new="$(script_version "$SRC_DIR/$SCRIPT_NAME")"
    [ -n "$new" ] || err "Не удалось определить версию нового $SCRIPT_NAME"
    log "Установлена версия: ${old:-неизвестна}, в пакете: $new"
    if [ -n "$OLD_PORT" ] && [ "$OLD_PORT" != "$PORT" ]; then
        port_changed=1
        owner="$(port_owner)"
        if [ -n "$owner" ]; then
            err "Порт $PORT уже занят: $owner. Выберите другой порт; сервис продолжает работать на $OLD_PORT"
        fi
        log "Смена порта: $OLD_PORT → $PORT"
    fi

    if [ "$old" = "$new" ] && [ "$FORCE" != 1 ] && [ "$port_changed" = 0 ]; then
        if ! package_differs; then
            log "Уже установлена версия $new — обновление не требуется (переустановить: --force)"
            systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null || start_service
            return 0
        fi
        # другая сборка с тем же номером версии — обновляем без --force
        log "Установлена другая сборка версии $new — обновление до сборки из пакета"
    fi
    if [ "$old" != "$new" ] || [ "$FORCE" = 1 ] || package_differs; then
        files_changed=1
    fi
    if [ -n "$old" ] && version_lt "$new" "$old" && [ "$FORCE" != 1 ]; then
        err "Версия в пакете ($new) старее установленной ($old). Понизить: --force, вернуть предыдущую: --rollback"
    fi

    verify_checksums
    preflight

    backup="$(backup_current)"
    log "Резервная копия: $backup"

    install_files
    create_service
    configure_selinux
    if [ "$port_changed" = 1 ]; then
        configure_firewall
    fi
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true

    log "Перезапуск службы (1–2 секунды; открытые дашборды переподключатся и обновятся сами)..."
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true

    if wait_healthy "$new"; then
        prune_backups
        if [ "$port_changed" = 1 ]; then
            close_firewall_port "$OLD_PORT"
            log "Порт изменён: $OLD_PORT → $PORT (новый адрес дашборда — ниже)"
        fi
        if [ "$files_changed" = 1 ]; then
            log "Обновлено: ${old:-?} → $new"
        fi
        return 0
    fi

    warn "Новая версия не ответила за ${HEALTH_TIMEOUT} с — откат к ${old:-предыдущей версии}"
    journalctl -u "$SERVICE_NAME" -n 20 --no-pager 2>/dev/null || true
    restore_backup "$backup"
    if [ "$port_changed" = 1 ]; then
        close_firewall_port "$PORT"
    fi
    PORT="$(installed_port)"  # прежний unit-файл — прежний порт
    if wait_healthy "$old"; then
        err "Обновление не удалось, восстановлена версия ${old:-предыдущая}. Подробности: journalctl -u $SERVICE_NAME"
    fi
    err "Обновление и откат не удались. Резервная копия: $backup. Подробности: journalctl -u $SERVICE_NAME"
}

do_rollback() {
    local backup version current
    backup="$(list_backups | head -n 1)"
    [ -n "$backup" ] || err "Резервных копий нет: $BACKUP_DIR"
    current="$(script_version "$INSTALL_DIR/$SCRIPT_NAME")"
    version="$(script_version "$backup/$SCRIPT_NAME")"
    log "Откат: ${current:-?} → ${version:-?} (из $backup)"
    restore_backup "$backup"
    local before="$PORT"
    PORT="$(installed_port)"  # порт из восстановленного unit-файла
    if [ "$PORT" != "$before" ]; then
        configure_firewall
        close_firewall_port "$before"
        log "Порт возвращён: $before → $PORT"
    fi
    if wait_healthy "$version"; then
        rm -rf "$backup"
        log "Откат выполнен, работает версия $version"
    else
        err "После отката сервис не отвечает. Подробности: journalctl -u $SERVICE_NAME"
    fi
}

do_status() {
    local installed running backups
    installed="$(script_version "$INSTALL_DIR/$SCRIPT_NAME")"
    HEALTH_TIMEOUT=1
    running="$(health_version)"
    backups="$(list_backups)"
    echo "  Установлена: ${installed:-нет}"
    echo "  Работает:    ${running:-не отвечает}"
    echo "  Служба:      $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
    echo "  Порт:        $PORT (https://$(hostname -f 2>/dev/null || hostname):$PORT/)"
    echo "  Сертификат:  $(cert_status)"
    echo "  Резервные копии (для --rollback):"
    if [ -n "$backups" ]; then echo "$backups" | sed 's:^:    :'; else echo "    нет"; fi
}

usage() {
    sed -n '/^# Использование:/,/^#$/p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'
}

# Кто слушает порт (пусто — свободен)
port_owner() {
    command -v ss &>/dev/null || return 0
    ss -tlnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $NF}' | head -n 1
}

# ---------------------------------------------------------------- готовность, диагностика, удаление

# Проверка готовности сервера: только чтение, ничего не устанавливает и не меняет
do_preflight() {
    local fails=0 out line owner installed pw
    echo "Проверка готовности (система не изменяется):"
    if [ -f "$SRC_DIR/$SCRIPT_NAME" ]; then
        if out="$("$PYTHON_BIN" "$SRC_DIR/$SCRIPT_NAME" --check 2>&1)"; then
            log "Сервис запускается на $("$PYTHON_BIN" --version 2>&1): $(echo "$out" | grep '^OK' | head -n 1)"
        else
            warn "Сервис не запускается на этом Python:"
            echo "$out"
            fails=$((fails + 1))
        fi
        while read -r line; do
            case "$line" in
                WARN\ *) warn "${line#WARN }" ;;
                INFO\ *) echo "    ${line#INFO }" ;;
            esac
        done <<< "$out"
    else
        warn "$SCRIPT_NAME не найден рядом с установщиком"
        fails=$((fails + 1))
    fi
    command -v systemctl &>/dev/null || { warn "systemctl не найден: нужен systemd"; fails=$((fails + 1)); }
    command -v openssl &>/dev/null || warn "openssl не найден — будет установлен из репозитория"
    command -v ss &>/dev/null || warn "ss не найден — будет установлен iproute2"

    installed="$(script_version "$INSTALL_DIR/$SCRIPT_NAME")"
    owner="$(port_owner)"
    if [ -n "$owner" ] && ! echo "$owner" | grep -q "python"; then
        warn "Порт $PORT занят другим процессом: $owner"
        fails=$((fails + 1))
    elif [ -n "$owner" ]; then
        log "Порт $PORT занят этим сервисом (установлена версия ${installed:-?})"
    else
        log "Порт $PORT свободен"
    fi
    if [ -n "$installed" ]; then
        log "Режим: обновление ${installed} → $(script_version "$SRC_DIR/$SCRIPT_NAME")"
    else
        log "Режим: первая установка"
    fi
    pw="$(passwd -S root 2>/dev/null | awk '{print $2}')"
    case "$pw" in
        L|LK|NP) warn "У root нет пароля — кнопки перезапуска работать не будут (passwd root)" ;;
        "") ;;
        *) log "Пароль root задан — перезапуск служб из интерфейса доступен" ;;
    esac
    if command -v getenforce &>/dev/null; then echo "    SELinux: $(getenforce 2>/dev/null)"; fi
    configure_astra_se
    echo ""
    if [ "$fails" -gt 0 ]; then
        err "Найдено блокирующих проблем: $fails"
    fi
    log "Сервер готов к установке"
}

# Архив диагностики: версии, состояние служб, журнал сервиса, самопроверка
do_diag() {
    local stamp dir archive
    stamp="$(date +%Y%m%d-%H%M%S)"
    dir="$(mktemp -d)/kvm-metrics-diag-$stamp"
    mkdir -p "$dir"
    {
        echo "date: $(date)"
        echo "host: $(hostname -f 2>/dev/null || hostname)"
        echo "os: $OS_NAME"
        echo "python: $("$PYTHON_BIN" --version 2>&1)"
        do_status
    } > "$dir/status.txt" 2>&1
    "$PYTHON_BIN" "$INSTALL_DIR/$SCRIPT_NAME" --check > "$dir/self-check.txt" 2>&1 || true
    journalctl -u "$SERVICE_NAME" -n 1000 --no-pager > "$dir/journal.txt" 2>&1 || true
    systemctl status "$SERVICE_NAME" --no-pager > "$dir/systemctl-status.txt" 2>&1 || true
    systemctl show kaspersky-vm-scanner.service kaspersky-vm-vms.service kaspersky-vm-worker.service \
        kaspersky-vm-privateapi.service kaspersky-vm-publicapi.service postgresql.service \
        --property=Id,LoadState,ActiveState,SubState,MainPID,MemoryCurrent > "$dir/kvm-units.txt" 2>&1 || true
    systemctl list-units --all --type=service --no-pager 'postgres*' 'kaspersky*' > "$dir/units-list.txt" 2>&1 || true
    ls -laR /var/log/kaspersky/vulnerability-management > "$dir/kvm-log-files.txt" 2>&1 || true
    if [ -f "${SYSTEMD_DIR}/${SERVICE_NAME}.service" ]; then cp "${SYSTEMD_DIR}/${SERVICE_NAME}.service" "$dir/"; fi
    archive="${DIAG_DIR:-/tmp}/kvm-metrics-diag-$stamp.tar.gz"
    tar -C "$(dirname "$dir")" -czf "$archive" "$(basename "$dir")"
    rm -rf "$(dirname "$dir")"
    log "Диагностика собрана: $archive (пароли и ключи в архив не попадают)"
}

do_uninstall() {
    local name
    PORT="${OLD_PORT:-$(installed_port)}"  # закрываем порт, на котором сервис работал
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    log "Служба $SERVICE_NAME остановлена и удалена"
    close_firewall_port "$PORT"

    [ -d "$INSTALL_DIR" ] || return 0
    if [ "$PURGE" = 1 ]; then
        rm -rf "$INSTALL_DIR"
        log "Каталог $INSTALL_DIR удалён полностью"
        return 0
    fi
    for name in "$SCRIPT_NAME" "$FONT_NAME" config.example.json install.sh $BRAND_FILES; do
        rm -f "${INSTALL_DIR:?}/$name"
    done
    rm -rf "${BACKUP_DIR:?}"
    log "Программные файлы удалены; сертификат, отчёты и настройки SIEM (settings.json) оставлены в $INSTALL_DIR"
    log "Удалить полностью: sudo bash install.sh --uninstall --purge"
}

do_install() {
    local owner
    verify_checksums
    preflight
    owner="$(port_owner)"
    if [ -n "$owner" ]; then
        err "Порт $PORT уже занят: $owner. Освободите порт и повторите установку"
    fi
    install_ss
    install_files
    create_service
    configure_selinux
    configure_firewall
    configure_astra_se
    check_root_password
    start_service
    check
}

# Заголовок по выбранному действию
action_title() {
    case "$1" in
        uninstall) echo "Удаление" ;;
        rollback) echo "Откат" ;;
        status) echo "Состояние" ;;
        preflight) echo "Проверка готовности" ;;
        diag) echo "Диагностика" ;;
        cert) echo "Сертификат" ;;
        *)
            local title="Установка" suffix=""
            if is_installed; then title="Обновление"; fi
            if [ -n "$CERT_SRC" ]; then suffix=" · сертификат организации"; fi
            if [ "$CERT_RESET" = 1 ]; then suffix=" · самоподписанный сертификат"; fi
            echo "$title$suffix"
            ;;
    esac
}

# Главная
main() {
    local action="auto"
    while [ $# -gt 0 ]; do
        case "$1" in
            --force) FORCE=1 ;;
            --purge) PURGE=1 ;;
            --port)
                [ $# -gt 1 ] || err "После --port укажите номер порта, например: --port 9443"
                REQUESTED_PORT="$2"
                PORT_GIVEN=1
                shift
                ;;
            --port=*) REQUESTED_PORT="${1#--port=}"; PORT_GIVEN=1 ;;
            --cert|--key|--chain)
                [ $# -gt 1 ] && [ -n "$2" ] || err "После $1 укажите путь к файлу"
                case "$1" in
                    --cert) CERT_SRC="$(abs_path "$2")" ;;
                    --key) KEY_SRC="$(abs_path "$2")" ;;
                    --chain) CHAIN_SRC="$(abs_path "$2")" ;;
                esac
                shift
                ;;
            --self-signed) CERT_RESET=1 ;;
            --rollback) action="rollback" ;;
            --status|--version) action="status" ;;
            --preflight) action="preflight" ;;
            --diag) action="diag" ;;
            --uninstall) action="uninstall" ;;
            -h|--help) usage; return 0 ;;
            *) err "Неизвестный параметр: $1 (см. --help)" ;;
        esac
        shift
    done
    if [ "$PORT_GIVEN" = 1 ] && [ -z "$REQUESTED_PORT" ]; then
        err "После --port укажите номер порта, например: --port 9443"
    fi
    if [ "$PORT_GIVEN" = 1 ] && ! valid_port "$REQUESTED_PORT"; then
        err "Недопустимый порт: $REQUESTED_PORT (нужно число от 1 до 65535)"
    fi
    if [ -n "$CERT_SRC$KEY_SRC$CHAIN_SRC" ] && { [ -z "$CERT_SRC" ] || [ -z "$KEY_SRC" ]; }; then
        err "Укажите и сертификат, и ключ: --cert <файл> --key <файл>"
    fi
    if [ -n "$CERT_SRC" ] && [ "$CERT_RESET" = 1 ]; then
        err "--cert и --self-signed нельзя указывать вместе"
    fi
    if [ -n "$CERT_SRC" ] || [ "$CERT_RESET" = 1 ]; then
        [ "$action" = "auto" ] || err "Параметры сертификата нельзя совмещать с --$action"
        # установщик из каталога сервиса: только смена сертификата, без обновления
        if is_installed && [ "$SRC_DIR" = "$INSTALL_DIR" ] && [ "$PORT_GIVEN" = 0 ]; then action="cert"; fi
    fi

    check_root

    echo ""
    echo "============================================"
    echo "  Kaspersky VM Metrics — $(action_title "$action")"
    echo "============================================"
    echo ""

    detect_os
    install_python
    resolve_port
    if [ -n "$OLD_PORT" ] && [ -z "$REQUESTED_PORT" ] && [ "$action" = "auto" ] && [ "$PORT" != "$DEFAULT_PORT" ]; then
        log "Порт сервиса: $PORT (выбран при установке)"
    fi

    case "$action" in
        status) PORT="${OLD_PORT:-$PORT}"; do_status; return 0 ;;
        rollback) do_rollback; return 0 ;;
        preflight) do_preflight; return 0 ;;
        diag) do_diag; return 0 ;;
        uninstall) do_uninstall; return 0 ;;
    esac

    install_openssl
    if [ -n "$CERT_SRC" ]; then
        validate_cert "$CERT_SRC" "$KEY_SRC" "$CHAIN_SRC"
    fi
    if [ "$action" = "cert" ]; then
        PORT="${OLD_PORT:-$PORT}"
        if [ -n "$CERT_SRC" ]; then install_org_cert "$CERT_SRC" "$KEY_SRC" "$CHAIN_SRC"; else reset_cert; fi
        echo ""
        echo "  Дашборд: https://$(hostname -f 2>/dev/null || hostname):$PORT/"
        echo ""
        return 0
    fi
    if is_installed; then
        install_ss
        do_update
        check_root_password
        echo ""
        log "Обновление завершено"
    else
        do_install
        echo ""
        log "Установка завершена"
    fi
    if [ -n "$CERT_SRC" ]; then
        install_org_cert "$CERT_SRC" "$KEY_SRC" "$CHAIN_SRC"
    elif [ "$CERT_RESET" = 1 ]; then
        reset_cert
    fi

    echo ""
    echo "  Дашборд: https://$(hostname -f 2>/dev/null || hostname):$PORT/"
    echo "  Статус:  sudo bash $INSTALL_DIR/install.sh --status"
    echo "  Откат:   sudo bash $INSTALL_DIR/install.sh --rollback"
    echo "  Логи:    journalctl -u $SERVICE_NAME -f"
    echo "  Файлы:   $INSTALL_DIR/"
    echo ""
}

# Запуск только при прямом вызове (при source — для тестов — функции просто загружаются)
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    main "$@"
fi
