#!/usr/bin/env bash
#
# xray-auto-install — native (no Docker, no panel) VLESS + XHTTP + Reality + Vision
# + VLESS Encryption (mlkem768x25519plus: hybrid ML-KEM-768 + X25519 key
# exchange; the short variant with X25519 server authentication — see the
# comment above VLESSENC_X25519 below), on a fresh Debian 12+ / Ubuntu 22.04+ box.
#
# Usage:
#   ./install.sh
# It asks for exactly two things: server IP and the root password issued by the
# provider. Everything else (packages, BBR, Xray-core, keys, external Reality
# target picked and TLS-checked from the server, SSH hardening, firewall) is
# automatic.
#
# What it deliberately does NOT do (evaluated and rejected as low-value for this
# threat model — see project README): create a separate sudo user, install
# fail2ban, or set an SSH key passphrase. (A swap file sized by RAM IS created —
# see project README; this used to be on the same "skip" list but was
# reconsidered after a live 130.17.21.198 low-RAM incident on 2026-09-22.)
#
# Robustness patterns below (dpkg-lock handling, ssh.socket detection, nft
# syntax-check + timed auto-rollback) are ported from
# github.com/RamDll/ovpn-stack's install/bootstrap.sh, where they were added
# after real failures on fresh VPS images.

set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Input
# ---------------------------------------------------------------------------

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$1" >&2; exit 1; }

command -v sshpass >/dev/null 2>&1 || die "sshpass is required on this machine (apt install sshpass)."
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required on this machine."

read -rp "Server IP: " SERVER_IP
[ -n "$SERVER_IP" ] || die "IP не может быть пустым."
# Ровно 4 октета 0–255 без ведущих нулей: inet_aton читает «010» как
# восьмеричное 8, и ssh ушёл бы не на тот адрес. IP идёт в имена файлов,
# ссылку и summary, поэтому hostname и IPv6 не принимаем вовсе.
IPV4_OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
if [[ ! "$SERVER_IP" =~ ^${IPV4_OCTET}(\.${IPV4_OCTET}){3}$ ]]; then
  case "$SERVER_IP" in
    *:*)       die "IPv6 не поддерживается — нужен IPv4-адрес сервера." ;;
    *[A-Za-z]*) die "Нужен IPv4-адрес, а не имя хоста (сервер создаётся под конкретный IP)." ;;
    *)         die "Некорректный IPv4-адрес: '${SERVER_IP}' (нужно 4 числа 0–255 через точку, без ведущих нулей)." ;;
  esac
fi

read -rsp "Root password (от провайдера): " ROOT_PASSWORD
echo
[ -n "$ROOT_PASSWORD" ] || die "Пароль не может быть пустым."
# sshpass -e берёт пароль из окружения; с -p он виден в аргументах процесса
# (ps, /proc/*/cmdline) всё время работы ssh.
export SSHPASS="$ROOT_PASSWORD"
unset ROOT_PASSWORD

# Тестовые флаги: намеренно ломают доступ после рискованного шага, чтобы одной
# командой проверить цепочку «сломали → таймер → доступ вернулся → reboot →
# доступ есть». FW — убрать SSH-порт из ruleset, SSH — сломать вход по ключу
# после lockdown.
XAI_TEST_BREAK_FW="${XAI_TEST_BREAK_FW:-0}"
XAI_TEST_BREAK_SSH="${XAI_TEST_BREAK_SSH:-0}"
[[ "$XAI_TEST_BREAK_FW" =~ ^[01]$ && "$XAI_TEST_BREAK_SSH" =~ ^[01]$ ]] \
  || die "XAI_TEST_BREAK_FW / XAI_TEST_BREAK_SSH принимают только 0 или 1."
# Ручной выбор Reality SNI (иначе — случайно из пула на сервере). Нужен, когда
# провайдер клиента режет конкретный домен: серверная TLS-проверка этого не
# видит. Строгий формат hostname — значение уходит в команду на сервере,
# в конфиг и в ссылку.
XAI_REALITY_SNI="${XAI_REALITY_SNI:-}"
if [[ -n "$XAI_REALITY_SNI" ]]; then
  [[ "$XAI_REALITY_SNI" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] \
    || die "XAI_REALITY_SNI='${XAI_REALITY_SNI}' — не похоже на имя домена (строчные буквы, цифры, дефис, точки; например www.hp.com)."
  echo "  Reality SNI задан вручную: ${XAI_REALITY_SNI} (будет проверен с сервера)"
fi
if [[ "$XAI_TEST_BREAK_FW$XAI_TEST_BREAK_SSH" != 00 ]]; then
  warn "ТЕСТОВЫЙ РЕЖИМ: XAI_TEST_BREAK_FW=${XAI_TEST_BREAK_FW} XAI_TEST_BREAK_SSH=${XAI_TEST_BREAK_SSH} — установка специально сломает доступ и упадёт; доступ вернёт страховочный таймер."
fi

SSH_PORT=22
# Reality SNI/target выбирается на сервере (bootstrap, после NTP), а не здесь:
# годность target проверяется TLS-хендшейком С САМОГО VPS — важна его сеть,
# его DNS и его часы, а не домашней машины.
FP="firefox"                     # fp=chrome не заработал на реальном мобильном клиенте, firefox — заработал
IP_SLUG="$(echo "$SERVER_IP" | tr '.:' '_')"
KEY_PATH="$HOME/.ssh/xray-auto-install-${IP_SLUG}"
SUMMARY_FILE="$HOME/xray-auto-install-${IP_SLUG}-summary.txt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Скрипт рассчитан на свежий/переустановленный сервер — новый образ = новый
# хост-ключ, это норма, а не MITM. Поэтому у каждого сервера свой known_hosts,
# который пересоздаётся при каждом запуске: основной ~/.ssh/known_hosts не
# трогаем вообще, а после установки этот файл закрепляет ключ сервера для
# StrictHostKeyChecking=yes (см. команду в summary).
KNOWN_HOSTS="$HOME/.ssh/xray-auto-install-${IP_SLUG}.known_hosts"
install -d -m 700 "$HOME/.ssh"
rm -f "$KNOWN_HOSTS"
install -m 600 /dev/null "$KNOWN_HOSTS"

# ServerAlive* — чтобы оборванное соединение (долгий apt на слабом VPS, NAT
# провайдера) падало через ~1 мин, а не висело бесконечно.
SSH_COMMON_OPTS=(-o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
  -o "UserKnownHostsFile=$KNOWN_HOSTS" -o StrictHostKeyChecking=accept-new)
# BatchMode=yes — только в ключевых обёртках: он запрещает любой интерактивный
# запрос, включая пароль, и sshpass с ним перестаёт работать.
SSH_PW_OPTS=("${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=password -o PubkeyAuthentication=no)
SSH_KEY_OPTS=("${SSH_COMMON_OPTS[@]}" -o BatchMode=yes -o PasswordAuthentication=no -o IdentitiesOnly=yes -i "$KEY_PATH")

ssh_pw()  { sshpass -e ssh "${SSH_PW_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }
scp_pw()  { sshpass -e scp "${SSH_PW_OPTS[@]}" -P "$SSH_PORT" "$@"; }
ssh_key() { ssh "${SSH_KEY_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }
scp_key() { scp "${SSH_KEY_OPTS[@]}" -P "$SSH_PORT" "$@"; }

log "Проверяю парольный доступ к ${SERVER_IP}..."
ssh_pw "echo ok" >/dev/null || die "Не удалось подключиться по паролю. Проверь IP и пароль — либо на этом сервере
парольный вход уже отключён (в т.ч. этим же скриптом ранее): повторно так не поставить, нужен свежий root-пароль
от провайдера — переустанови ОС в его панели и запусти скрипт заново."
echo "  OK"

# ---------------------------------------------------------------------------
# 1. Remote bootstrap: packages, BBR, Reality target, Xray-core, keys, config.json
# ---------------------------------------------------------------------------

log "Собираю удалённый bootstrap-скрипт..."

cat > "$WORKDIR/bootstrap.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

log()  { printf '[bootstrap] %s\n' "$*"; }
die()  { printf '[bootstrap] ОШИБКА: %s\n' "$*" >&2; exit 1; }
# Любая неожиданная ошибка — с номером строки, а не молчаливый выход по set -e.
# Только $LINENO, без $BASH_COMMAND: упавшая команда может содержать тайны
# (например, sed внутри redact() с приватным ключом в шаблоне). set -E
# наследует ловушку в функции; в условиях (if, ||, &&) она не срабатывает.
trap 'die "неожиданная ошибка в строке $LINENO bootstrap.sh (вывод выше)"' ERR

# Поддерживаются Debian 12+ и Ubuntu 22.04+. Проверка SSH по `sshd -T`
# строгая, а OpenSSH < 8.7 (Debian 11, Ubuntu 20.04) печатает там другие
# имена директив — отказываемся сразу, до установки чего-либо, а не падаем
# на середине с полунастроенным сервером.
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian) OS_MIN=12 ;;
  ubuntu) OS_MIN=22.04 ;;
  *) die "поддерживаются только Debian 12+ и Ubuntu 22.04+, а тут: ${PRETTY_NAME:-${ID:-неизвестно}}" ;;
esac
if [[ -z "${VERSION_ID:-}" || "$(printf '%s\n' "$OS_MIN" "$VERSION_ID" | sort -V | sed -n 1p)" != "$OS_MIN" ]]; then
  die "поддерживаются только Debian 12+ и Ubuntu 22.04+, а тут: ${PRETTY_NAME:-$ID ${VERSION_ID:-}}"
fi

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a   # иначе needrestart на Debian может повиснуть на интерактивном списке служб

APT_OPTS=(-o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold)

# Свежий VPS в первые минуты держит dpkg-lock под cloud-init/apt-daily/
# unattended-upgrades. Останавливаем их таймеры — наш apt берёт lock сразу.
stop_apt_daily() {
  systemctl stop --no-block \
    apt-daily.timer apt-daily-upgrade.timer \
    apt-daily.service apt-daily-upgrade.service \
    unattended-upgrades.service >/dev/null 2>&1 || true
}
wait_dpkg_lock() {
  local w=0 max=180
  while pgrep -x 'apt|apt-get|dpkg|aptitude|unattended-upgr|packagekitd' >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if (( w >= max )); then log "dpkg-lock ещё занят после ${max}с — пробую всё равно"; return 0; fi
    if (( w % 20 == 0 )); then log "dpkg-lock занят (cloud-init?) — жду... ${w}/${max}с"; fi
    sleep 5; w=$((w + 5))
  done
  return 0
}
apt_do() {
  local try
  for try in 1 2 3; do
    wait_dpkg_lock
    if apt-get "${APT_OPTS[@]}" "$@"; then return 0; fi
    log "apt-get $* — попытка $try не удалась, жду 20с и повторяю"
    sleep 20
  done
  die "apt-get $* не прошёл после 3 попыток (dpkg-lock/сеть?)"
}

# Своп по объёму RAM: < 2 GiB → 2 GiB, 2–4 GiB → 1 GiB, > 4 GiB → не нужен.
# Первым шагом, ДО apt: dist-upgrade — самый тяжёлый по памяти шаг установки,
# и на ~1 GB VPS он должен идти уже с подушкой. Нужны только coreutils/
# util-linux из базового образа.
# Это подушка от OOM-killer'а на маленьких VPS (130.17.21.198: 967MB без
# свопа), а не рабочая память. MemTotal у «2GB»-тарифа чуть меньше 2 GiB
# (ядро резервирует часть) — такой VPS честно попадает в первую ступень.
# В LXC/OpenVZ swapon запрещён — это предупреждение, не ошибка: без свопа
# сервис работает, просто без подушки.
MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
if   (( MEM_KB < 2 * 1024 * 1024 )); then SWAP_MB=2048
elif (( MEM_KB <= 4 * 1024 * 1024 )); then SWAP_MB=1024
else SWAP_MB=0
fi
# `grep >/dev/null`, а не `grep -q`: -q закрывает канал на первом совпадении,
# и левая команда может получить SIGPIPE — под pipefail это ложный отказ.
if swapon --show | grep . >/dev/null; then
  log "своп уже есть — пропускаю"
elif (( SWAP_MB == 0 )); then
  log "RAM $((MEM_KB / 1024))MB > 4 GiB — своп не создаю"
else
  log "своп ${SWAP_MB}MB (RAM $((MEM_KB / 1024))MB)"
  # fallocate не везде даёт файл, годный для свопа (не поддерживается ФС) —
  # тогда честная запись нулями через dd.
  rm -f /swapfile
  if ! fallocate -l "${SWAP_MB}M" /swapfile 2>/dev/null; then
    log "fallocate не сработал — создаю своп через dd"
    rm -f /swapfile
    dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_MB" status=none
  fi
  chmod 600 /swapfile
  if mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile 2>/dev/null; then
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
    sysctl -qp /etc/sysctl.d/99-swappiness.conf
  else
    log "ПРЕДУПРЕЖДЕНИЕ: swapon не разрешён (LXC/OpenVZ?) — продолжаю без свопа"
    rm -f /swapfile
  fi
fi

log "останавливаю apt-daily/unattended-upgrades, чтобы не воевали за dpkg-lock"
stop_apt_daily
wait_dpkg_lock
dpkg --configure -a >/dev/null 2>&1 || true
# dpkg --configure дожимает распакованные пакеты, но не чинит сломанные
# зависимости после прерванного apt — это делает только -f install.
apt-get "${APT_OPTS[@]}" -f install -y >/dev/null 2>&1 || true

log "apt update"
apt_do update -qq
log "apt dist-upgrade"
apt_do -y dist-upgrade -qq >/dev/null
log "устанавливаю пакеты"
apt_do -y install -qq curl unzip openssl nftables ca-certificates >/dev/null
systemctl start apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true

log "ограничиваю journald (SystemMaxUse=100M), иначе на слабом VPS лог xray может забить диск"
# Drop-in, а не правка journald.conf: пакетный файл остаётся нетронутым
# (обновления systemd не спрашивают про конфликт), а наш лимит — отдельный
# файл, который видно в `systemd-analyze cat-config systemd/journald.conf`.
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=100M\n' > /etc/systemd/journald.conf.d/00-xray-auto-install.conf
systemctl restart systemd-journald

# Reality/TLS чувствителен к рассинхронизации часов — сертификаты и хендшейк
# зависят от текущего времени. Если NTP уже синхронизирован или есть живой
# демон — не трогаем, иначе включаем/ставим systemd-timesyncd.
log "проверяю синхронизацию времени"
ntp_ok() { [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]]; }
ntp_daemon_up() {
  local s
  for s in systemd-timesyncd chrony chronyd ntpsec ntpd openntpd; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then return 0; fi
  done
  return 1
}
if ntp_ok || ntp_daemon_up; then
  log "время уже синхронизировано"
elif systemctl list-unit-files systemd-timesyncd.service >/dev/null 2>&1; then
  systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || log "не удалось включить timesyncd, продолжаю"
else
  apt_do -y install -qq systemd-timesyncd >/dev/null 2>&1 \
    && systemctl enable --now systemd-timesyncd >/dev/null 2>&1 \
    || log "не удалось поднять синхронизацию времени, продолжаю"
fi
# До ~60с: только что включённый timesyncd синхронизируется не мгновенно, а
# проверка Reality target ниже (-verify_return_error) без точного времени
# отбросит все домены. Если время уже в порядке — цикл выходит сразу.
for _ in $(seq 1 30); do ntp_ok && break; sleep 2; done
ntp_ok || log "предупреждение: время ещё не синхронизировано, продолжаю всё равно"

# Reality target — настоящий внешний сайт: неавторизованный клиент (сканер,
# браузер) получает его подлинный сертификат и ответ, а не самоподписанную
# заглушку. Проверка идёт ПОСЛЕ NTP: -verify_return_error валит хендшейк при
# сбитых часах, и хороший кандидат был бы отброшен зря.
# Без apple/icloud: Xray-core сам предупреждает в логе «Choosing apple,
# icloud, etc. as the target may get your IP blocked by the GFW». Без
# cloudflare/jsdelivr: это CDN-фронты, их сертификат и поведение слишком
# сильно зависят от точки входа.
# Порядок перемешиваем: один и тот же SNI у всех установок этого скрипта —
# лишний признак для массового сканирования.
# Без www.lenovo.com: проходил все проверки с сервера, но у клиента трафик
# резал провайдер (2026-09-22, 138.124.71.35; с www.hp.com на том же сервере
# и тех же ключах — работало). Серверная проверка такого не видит — для
# этого есть ручной выбор XAI_REALITY_SNI.
REALITY_POOL=(
  www.microsoft.com www.bing.com   www.samsung.com www.nvidia.com
  www.amd.com       www.intel.com  www.tesla.com   www.sap.com
  www.oracle.com    www.dell.com   www.cisco.com   www.qualcomm.com
  www.hp.com
)
# Кандидат годен, только если с ЭТОГО сервера проходит TLS 1.3 + X25519 +
# валидный для домена сертификат И реально согласован h2. Код возврата
# s_client h2 не подтверждает (0 и без ALPN), а с -brief строка ALPN не
# печатается — поэтому grep по полному выводу.
reality_target_ok() {
  local d="$1" out
  out="$(timeout 10 openssl s_client -connect "${d}:443" -servername "$d" \
    -tls1_3 -groups X25519 -alpn h2 \
    -verify_return_error -verify_hostname "$d" </dev/null 2>&1)" || return 1
  grep -q '^ALPN protocol: h2$' <<<"$out"
}
log "выбираю Reality target (TLS 1.3 + X25519 + h2 + валидный сертификат)"
REALITY_SNI=""
XAI_REALITY_SNI="${XAI_REALITY_SNI:-}"
if [[ -n "$XAI_REALITY_SNI" ]]; then
  # Домен задан вручную — проверяем только его. Не прошёл → стоп, а не тихая
  # подмена на случайный: человек выбрал его не просто так (проверен у его
  # провайдера), и неожиданный SNI в ссылке хуже явной ошибки.
  reality_target_ok "$XAI_REALITY_SNI" \
    || die "заданный XAI_REALITY_SNI=${XAI_REALITY_SNI} не прошёл TLS-проверку с этого сервера
(нужны TLS 1.3 + X25519 + h2 + валидный сертификат). Выбери другой домен или запусти без переменной."
  REALITY_SNI="$XAI_REALITY_SNI"
  log "  задан вручную: ${REALITY_SNI} — проверку прошёл"
else
  mapfile -t _pool < <(printf '%s\n' "${REALITY_POOL[@]}" | shuf)
  for d in "${_pool[@]}"; do
    if reality_target_ok "$d"; then REALITY_SNI="$d"; break; fi
    log "  $d — не подходит, следующий"
  done
  [[ -n "$REALITY_SNI" ]] || die "ни один домен из пула не прошёл TLS-проверку с этого сервера.
Проверь на сервере: DNS (getent hosts www.microsoft.com), время (timedatectl),
исходящий 443 (не режет ли провайдер/хостинг)."
fi
REALITY_TARGET="${REALITY_SNI}:443"
log "Reality target: ${REALITY_TARGET}"

log "включаю BBR + fq qdisc"
modprobe tcp_bbr 2>/dev/null || true
if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  echo tcp_bbr > /etc/modules-load.d/bbr.conf
  cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -qp /etc/sysctl.d/99-bbr.conf
else
  log "BBR недоступен в этом ядре — остаюсь на cubic"
fi

log "Xray-core (официальный установщик, latest stable release)"
XRAY_INSTALL_OK=0
# Сначала в файл, потом запуск — два отдельных кода возврата. Старый вариант
# `bash -c "$(curl …)"` при падении curl выполнял `bash -c ""` с кодом 0, и
# неудачная загрузка выглядела как успешная установка.
for try in 1 2 3; do
  if curl --fail --location --silent --show-error --retry 3 \
       -o /root/xray-install.sh \
       https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh; then
    if bash /root/xray-install.sh install >/dev/null 2>&1; then
      XRAY_INSTALL_OK=1
      break
    fi
    log "установщик Xray-core завершился с ошибкой (попытка $try)"
  else
    log "не удалось скачать установщик Xray-core (попытка $try)"
  fi
  log "жду 10с и повторяю"
  sleep 10
done
rm -f /root/xray-install.sh
[[ "$XRAY_INSTALL_OK" == 1 ]] || die "не удалось установить Xray-core после 3 попыток"
[ -x /usr/local/bin/xray ] || die "установщик отработал, но /usr/local/bin/xray не найден"
/usr/local/bin/xray version   # печатает 2 строки; НЕ пайпить в head — xray version | head -1
                               # ловит SIGPIPE (head закрывает трубу после 1-й строки, xray
                               # падает на второй write) => exit 141 под set -o pipefail,
                               # воспроизведено вживую на 95.128.157.141

XRAY_VER="$(/usr/local/bin/xray version 2>/dev/null | sed -n '1s/^Xray \([^ ]*\).*/\1/p')"

log "генерирую ключи"
UUID=$(/usr/local/bin/xray uuid)
SHORT_ID=$(openssl rand -hex 8)

# Сырой вывод `xray x25519` / `xray vlessenc` содержит приватные ключи —
# захватываем вместе со stderr и НИКОГДА не печатаем, даже при ошибке.
X25519_OUT="$(/usr/local/bin/xray x25519 2>&1)" \
  || die "xray x25519 завершился с ошибкой (Xray ${XRAY_VER:-?}); вывод не печатаю — в нём ключи"
# `|| true`: если формат вывода сменился и grep ничего не нашёл, под pipefail
# подстановка упала бы и set -e завершил бы скрипт ДО понятной проверки ниже.
PRIVATE_KEY=$(grep -iE '^Private ?key' <<<"$X25519_OUT" | sed -E 's/^[^:]+:\s*//' || true)
PUBLIC_KEY=$(grep -iE '^Public ?key|^Password' <<<"$X25519_OUT" | sed -n '1s/^[^:]*:[[:space:]]*//p' || true)

# `xray vlessenc` печатает ДВА варианта. В ОБОИХ обмен ключами один и тот же —
# гибридный ML-KEM-768 + X25519, эфемерный (отсюда "Ephemeral key exchange is
# Post-Quantum safe anyway" в его выводе): записанный сегодня трафик не
# расшифровать и будущим квантовым компьютером (harvest-now-decrypt-later).
# Различается только АУТЕНТИФИКАЦИЯ СЕРВЕРА:
#   "X25519, not Post-Quantum"  — короткие значения (~44 символа);
#   "ML-KEM-768, Post-Quantum"  — длинные (~1600+ символов).
# Берём короткий: аутентификация на X25519 не защищена от будущего АКТИВНОГО
# квантового MITM (подделать сервер в реальном времени), но это угроза
# другого порядка, чем пассивная запись, а длинный вариант превращает
# ссылку/QR в кирпич текста. Подпись "постквантовое шифрование" у ранней
# конфигурации 138.124.71.35 была верной в части конфиденциальности.
# Внешний TLS Reality — классический; постквантовость даёт именно этот
# внутренний слой VLESS Encryption.
# Оба варианта используют одинаковый строковый префикс mlkem768x25519plus.native,
# поэтому явно обрезаем вывод ДО заголовка ML-KEM-768, чтобы не выхватить его.
VLESSENC_OUT="$(/usr/local/bin/xray vlessenc 2>&1)" \
  || die "xray vlessenc завершился с ошибкой (Xray ${XRAY_VER:-?}); вывод не печатаю — в нём ключи"
VLESSENC_X25519=$(awk '/ML-KEM-768/{exit} {print}' <<<"$VLESSENC_OUT")
DECRYPTION=$(grep -oE 'mlkem768x25519plus\.native\.[0-9]+s\.[A-Za-z0-9_-]+' <<<"$VLESSENC_X25519" | sed -n 1p || true)
ENCRYPTION=$(grep -oE 'mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]+' <<<"$VLESSENC_X25519" | sed -n 1p || true)
unset X25519_OUT VLESSENC_OUT VLESSENC_X25519

[ -n "$UUID" ] && [ -n "$SHORT_ID" ] && [ -n "$PRIVATE_KEY" ] && [ -n "$PUBLIC_KEY" ] \
  && [ -n "$DECRYPTION" ] && [ -n "$ENCRYPTION" ] \
  || die "не удалось распарсить ключи из xray x25519/vlessenc (Xray ${XRAY_VER:-?} — сменился формат вывода?)"

# Маскирует серверные тайны (приватный ключ Reality и decryption VLESS
# Encryption) в диагностике, которую печатаем при ошибке. Заглушка @@ на
# случай пустой переменной: иначе sed получил бы "s|||g" и упал бы прямо
# в аварийном пути. Точки экранируем — decryption содержит их.
redact() {
  local pk="${PRIVATE_KEY:-@@}" dc="${DECRYPTION:-@@}"
  sed -e "s|${pk//./\\.}|<redacted>|g" -e "s|${dc//./\\.}|<redacted>|g"
}

# Группа, под которой xray читает конфиг, — из юнита (Xray-install ставит
# User=nobody без Group=). Два отдельных вызова: у `-p User,Group --value`
# вывод — две строки без имён, на их порядок не опираемся.
XRAY_USER="$(systemctl show -p User --value xray)"
XRAY_GROUP="$(systemctl show -p Group --value xray)"
[[ -n "$XRAY_GROUP" ]] || XRAY_GROUP="$(id -gn "${XRAY_USER:-root}")" \
  || die "не удалось определить группу пользователя xray (${XRAY_USER:-?})"

log "config.json (640 root:${XRAY_GROUP})"
mkdir -p /usr/local/etc/xray
# outbounds: freedom первым — он остаётся выходом по умолчанию; blackhole +
# правило geoip:private — чтобы клиенты не ходили через сервер в его локальную
# сеть/loopback (сеть провайдера, 127.0.0.1-сервисы, метаданные облака).
# domainStrategy IPIfNonMatch обязателен: в дефолтном AsIs ip-правило видит
# только запросы прямо по IP, и его обходит любой домен, резолвящийся в
# приватный адрес (localhost, *.nip.io), а также подмена IP на домен через
# sniffing destOverride. С IPIfNonMatch домен резолвится для маршрутизации.
# Во временный файл (mktemp создаёт его 600) и затем install: `cat >` в уже
# существующий config.json сохранил бы его старые права.
CFG_TMP="$(mktemp)"
cat > "$CFG_TMP" <<EOF
{
  "log": {"loglevel": "warning", "access": "none"},
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "${UUID}", "flow": "xtls-rprx-vision"}],
      "decryption": "${DECRYPTION}"
    },
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {"path": "/", "host": "", "mode": "auto"},
      "security": "reality",
      "realitySettings": {
        "show": false,
        "target": "${REALITY_TARGET}",
        "xver": 0,
        "serverNames": ["${REALITY_SNI}"],
        "privateKey": "${PRIVATE_KEY}",
        "shortIds": ["${SHORT_ID}"]
      }
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
  }],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]
  }
}
EOF
install -m 640 -o root -g "$XRAY_GROUP" "$CFG_TMP" /usr/local/etc/xray/config.json
rm -f "$CFG_TMP"

# Битый конфиг ловим до рестарта: иначе xray падает уже в systemd, и причина
# видна только в journalctl.
if ! XRAY_TEST_OUT="$(/usr/local/bin/xray run -test -c /usr/local/etc/xray/config.json 2>&1)"; then
  printf '%s\n' "$XRAY_TEST_OUT" | redact >&2
  die "xray run -test не принял config.json — xray не перезапускаю"
fi
systemctl enable xray >/dev/null 2>&1
systemctl restart xray
sleep 1
if ! systemctl is-active --quiet xray; then
  journalctl -u xray --no-pager -n 40 2>&1 | redact >&2
  die "xray не запустился (журнал выше, тайны замаскированы)"
fi
ss -ltnp | grep ':443 ' >/dev/null || die "порт 443 не слушается"

# Домой уходит только то, что нужно для ссылки. PRIVATE_KEY и DECRYPTION —
# серверные тайны, они остаются только в config.json.
printf '%s\n' "===XRAY_AUTO_INSTALL_VARS===" \
  "UUID=${UUID}" "REALITY_SNI=${REALITY_SNI}" "SHORT_ID=${SHORT_ID}" \
  "PUBLIC_KEY=${PUBLIC_KEY}" "ENCRYPTION=${ENCRYPTION}" "XRAY_VERSION=${XRAY_VER:-}" "===END==="
REMOTE_EOF

log "Заливаю и запускаю bootstrap на сервере (это займёт минуту-две)..."
scp_pw "$WORKDIR/bootstrap.sh" "root@${SERVER_IP}:/root/bootstrap.sh"
BOOTSTRAP_OUT="$(ssh_pw "XAI_REALITY_SNI='${XAI_REALITY_SNI}' bash /root/bootstrap.sh && rm -f /root/bootstrap.sh" 2>&1)" || {
  # Блок VARS (если bootstrap успел его напечатать) вырезаем до печати.
  sed '/^===XRAY_AUTO_INSTALL_VARS===$/,/^===END===$/d' <<<"$BOOTSTRAP_OUT" >&2
  die "Bootstrap упал (полный вывод выше).
Если в выводе нет ошибки, а оборвалось соединение — просто запусти скрипт
повторно: пароль на этом этапе ещё не отключён."
}

# Без eval: вывод сервера — данные, а не код. Берём только ключи из белого
# списка; всё прочее в блоке молча игнорируется.
UUID="" REALITY_SNI="" SHORT_ID="" PUBLIC_KEY="" ENCRYPTION="" XRAY_VERSION=""
while IFS='=' read -r key value; do
  case "$key" in
    UUID|REALITY_SNI|SHORT_ID|PUBLIC_KEY|ENCRYPTION|XRAY_VERSION) printf -v "$key" '%s' "$value" ;;
  esac
done < <(sed -n '/^===XRAY_AUTO_INSTALL_VARS===$/,/^===END===$/p' <<<"$BOOTSTRAP_OUT")
for v in UUID REALITY_SNI SHORT_ID PUBLIC_KEY ENCRYPTION; do
  [ -n "${!v:-}" ] || die "Не получил значение $v от сервера."
done
# XRAY_VERSION — справочная (в summary и финальный вывод): её отсутствие не
# ошибка, поэтому в цикл обязательных значений выше она не входит.
XRAY_VERSION="${XRAY_VERSION:-неизвестна}"
echo "  OK — Xray ${XRAY_VERSION} активен, порт 443 слушается, Reality target: ${REALITY_SNI}:443"

# ---------------------------------------------------------------------------
# 2. SSH key: generate, install, verify via a brand-new connection
# ---------------------------------------------------------------------------

log "Генерирую SSH-ключ (${KEY_PATH})..."
if [ -f "$KEY_PATH" ]; then rm -f "$KEY_PATH" "$KEY_PATH.pub"; fi
ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -C "xray-auto-install-${SERVER_IP}" >/dev/null

PUBKEY_CONTENT="$(cat "${KEY_PATH}.pub")"
# Повторный запуск (после сбоя/отката) создаёт новый ключ — старый ключ этого
# же скрипта для этого же сервера (комментарий xray-auto-install-<IP>) убираем,
# чтобы в authorized_keys не копились записи без парного приватного ключа.
# Чужие ключи не трогаем.
ssh_pw "mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch /root/.ssh/authorized_keys \
  && sed -i '/ xray-auto-install-${SERVER_IP//./\\.}\$/d' /root/.ssh/authorized_keys \
  && echo '${PUBKEY_CONTENT}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"

log "Проверяю ключевой доступ НОВЫМ соединением (пароль ещё не трогали)..."
ssh_key "echo ok" >/dev/null || die "Ключевой доступ не заработал — пароль НЕ отключаю, разбирайся руками."
echo "  OK"
# Дальше только ключ — пароль больше не держим в окружении дочерних ssh/scp.
unset SSHPASS

# ---------------------------------------------------------------------------
# 3. SSH hardening. Один загружаемый скрипт, три стадии:
#    "prep"     — наш drop-in только с безвредным hardening (пароль ещё
#                 включён как страховка);
#    "lockdown" — тот же drop-in + запрет пароля, под страховочным таймером;
#    "confirm"  — снять таймер; вызывается ТОЛЬКО после того, как домашняя
#                 машина зашла по ключу новым соединением.
#    Вся настройка — один файл 00-xray-auto-install.conf. Чужие конфиги
#    (sshd_config, 50-cloud-init.conf) не трогаем, поэтому откат — это просто
#    удалить наш файл и сделать reload. Результат проверяем по `sshd -T -C`
#    (эффективный конфиг с учётом Match для реального адреса клиента), а не
#    по тому, что записали.
# ---------------------------------------------------------------------------

cat > "$WORKDIR/ssh-harden.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
STAGE="${1:?usage: ssh-harden.sh prep|lockdown|confirm}"
PORT=22
DROPIN=/etc/ssh/sshd_config.d/00-xray-auto-install.conf
TIMER=xray-auto-install-ssh-rollback
XAI_TEST_BREAK_SSH="${XAI_TEST_BREAK_SSH:-0}"

log()  { printf '[ssh-harden] %s\n' "$*"; }
die()  { printf '[ssh-harden] ОШИБКА: %s\n' "$*" >&2; exit 1; }

socket_active() {
  systemctl list-unit-files ssh.socket >/dev/null 2>&1 && \
    systemctl is-enabled --quiet ssh.socket 2>/dev/null
}

restart_ssh() {
  systemctl daemon-reload
  # reload (SIGHUP) — sshd перечитывает конфиг, НЕ убивая текущие сессии.
  # `restart` здесь опасен: мы выполняемся ВНУТРИ дерева процессов ssh.service
  # (эта самая SSH-сессия — его потомок), а systemd по умолчанию
  # (KillMode=control-group) при restart убивает ВСЮ cgroup юнита — включая
  # текущую сессию и сам скрипт — раньше, чем новый sshd успевает подняться.
  # Поймано вживую на 95.128.157.141: lockdown оборвался без единой строчки
  # вывода, новый sshd так и не стартовал, connection пропала. Порт мы никогда
  # не меняем, так что reload всегда достаточно; restart — только fallback.
  if systemctl reload ssh.service 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
    return 0
  fi
  log "reload не поддержан — fallback на restart (риск оборвать текущую сессию)"
  if socket_active; then
    systemctl restart ssh.socket
    systemctl restart ssh.service 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  else
    systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null || systemctl restart ssh
  fi
}

local_selfcheck() {
  local up=0
  for _ in $(seq 1 10); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then exec 3<&- 3>&-; up=1; break; fi
    sleep 1
  done
  [[ "$up" -eq 1 ]]
}

rollback_ssh() {
  rm -f "$DROPIN"
  restart_ssh || true
}

stop_timer() {
  systemctl stop "${TIMER}.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "${TIMER}.service" "${TIMER}.timer" >/dev/null 2>&1 || true
}

# sshd берёт ПЕРВОЕ вхождение директивы. Наш 00-файл идёт первым внутри
# sshd_config.d, но строки самого sshd_config, стоящие ВЫШЕ Include, читаются
# раньше него и молча побеждают. Требуем: активный Include sshd_config.d/*.conf
# есть и стоит выше первой незакомментированной директивы из нашего набора.
# Иначе отказываемся — чужой файл не правим. mawk (дефолтный awk на Debian)
# не знает IGNORECASE, поэтому tolower.
check_include_order() {
  local rc=0
  awk '
    { l = tolower($0); sub(/^[ \t]+/, "", l) }
    l == "" || l ~ /^#/ { next }
    !inc && l ~ /^include[ \t]+\/etc\/ssh\/sshd_config\.d\/\*\.conf[ \t]*$/ { inc = NR; next }
    !first && l ~ /^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitrootlogin|x11forwarding|maxauthtries|logingracetime)([ \t]|=)/ { first = NR }
    END { if (!inc) exit 10; if (first && first < inc) exit 11; exit 0 }
  ' /etc/ssh/sshd_config || rc=$?
  case "$rc" in
    0)  return 0 ;;
    10) die "в /etc/ssh/sshd_config нет активного 'Include /etc/ssh/sshd_config.d/*.conf' — наш drop-in не будет прочитан. Нестандартный образ: настрой SSH руками." ;;
    11) die "в /etc/ssh/sshd_config одна из директив (PasswordAuthentication/PermitRootLogin/…) стоит ВЫШЕ Include sshd_config.d и перебьёт наш drop-in. Чужой файл не правлю: перенеси Include в начало или убери директиву руками." ;;
    *)  die "не удалось разобрать /etc/ssh/sshd_config (awk rc=$rc)" ;;
  esac
}

HARDENING='X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30'
LOCKDOWN='PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password'

write_dropin() {
  local tmp
  tmp="$(mktemp)"
  { printf '# xray-auto-install: единственный наш файл в sshd_config.d\n'; printf '%s\n' "$@"; } > "$tmp"
  install -m 644 "$tmp" "$DROPIN"
  rm -f "$tmp"
}

# Эффективный конфиг для реального клиента: -C с адресом из SSH_CLIENT
# учитывает Match-блоки (Match Address/User), которые голый `sshd -T` не видит.
# Аргументы — пары ключ=ожидание, ожидание — regex.
check_effective() {
  local addr eff pair key want got bad=0
  addr="${SSH_CLIENT%% *}"
  [[ -n "$addr" ]] || { log "SSH_CLIENT пуст — не знаю адрес клиента для sshd -T -C"; return 1; }
  if ! eff="$(sshd -T -C "user=root,host=x,addr=${addr}" 2>&1)"; then
    log "sshd -T -C упал:"; printf '%s\n' "$eff" >&2
    return 1
  fi
  for pair in "$@"; do
    key="${pair%%=*}"; want="${pair#*=}"
    got="$(awk -v k="$key" '$1 == k { print $2; exit }' <<<"$eff")"
    if [[ ! "$got" =~ ^(${want})$ ]]; then
      log "sshd -T: ${key}=${got:-<нет>}, ожидалось ${want}"
      bad=1
    fi
  done
  return "$bad"
}
EXPECT_HARDENING=(x11forwarding=no maxauthtries=3 logingracetime=30)
# without-password — старое имя prohibit-password; sshd -T на Debian 13
# печатает именно его, хотя в конфиге написано prohibit-password.
EXPECT_LOCKDOWN=(passwordauthentication=no kbdinteractiveauthentication=no 'permitrootlogin=prohibit-password|without-password')

if [[ "$STAGE" == "prep" ]]; then
  check_include_order
  write_dropin "$HARDENING"

  log "проверяю синтаксис (sshd -t)"
  if ! sshd -t; then
    rm -f "$DROPIN"
    die "sshd -t не прошёл — drop-in удалён, ничего не перезагружал"
  fi

  restart_ssh
  local_selfcheck || { rollback_ssh; die "ssh не слушает $PORT локально после reload — откатил наш drop-in"; }
  check_effective "${EXPECT_HARDENING[@]}" || { rollback_ssh; die "sshd -T не подтвердил hardening — откатил наш drop-in"; }
  log "prep готово: X11Forwarding/MaxAuthTries/LoginGraceTime подтверждены sshd -T, ssh слушает $PORT"

elif [[ "$STAGE" == "lockdown" ]]; then
  check_include_order

  # Страховочный таймер — ДО рискованного шага: если после reload ключ не
  # пустит, сервер через 3 минуты сам удалит наш drop-in (вернётся пароль).
  # Без работающего таймера пароль не отключаем вообще.
  stop_timer
  systemd-run --unit="$TIMER" --on-active=180 \
    --description="xray-auto-install: откат отключения пароля, если не подтверждено" \
    /bin/bash -c "rm -f ${DROPIN}; systemctl reload ssh.service 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart ssh.service 2>/dev/null || systemctl restart ssh 2>/dev/null || true" \
    >/dev/null 2>&1 || die "systemd-run не смог поставить страховочный таймер — пароль НЕ отключаю"
  systemctl is-active --quiet "${TIMER}.timer" || die "страховочный таймер ${TIMER}.timer не активен — пароль НЕ отключаю"

  if [[ "$XAI_TEST_BREAK_SSH" == 1 ]]; then
    log "ТЕСТ XAI_TEST_BREAK_SSH=1: ломаю вход по ключу (AuthorizedKeysFile в никуда) — доступ вернёт таймер"
    write_dropin "$HARDENING" "$LOCKDOWN" "AuthorizedKeysFile /nonexistent/xray-auto-install-test"
  else
    write_dropin "$HARDENING" "$LOCKDOWN"
  fi

  log "проверяю синтаксис (sshd -t)"
  if ! sshd -t; then
    rollback_ssh; stop_timer
    die "sshd -t не прошёл — наш drop-in удалён, пароль НЕ отключён"
  fi

  restart_ssh
  local_selfcheck || { rollback_ssh; stop_timer; die "ssh не слушает $PORT локально после reload — откатил наш drop-in"; }
  check_effective "${EXPECT_HARDENING[@]}" "${EXPECT_LOCKDOWN[@]}" \
    || { rollback_ssh; stop_timer; die "sshd -T не подтвердил отключение пароля — откатил наш drop-in"; }
  log "lockdown готово: sshd -T подтверждает все 6 директив; жду confirm (иначе откат через 3 мин)"

elif [[ "$STAGE" == "confirm" ]]; then
  stop_timer
  log "страховочный таймер снят — отключение пароля подтверждено"
else
  die "неизвестный STAGE: $STAGE"
fi
REMOTE_EOF

log "Заливаю ssh-harden.sh..."
scp_key "$WORKDIR/ssh-harden.sh" "root@${SERVER_IP}:/root/ssh-harden.sh"

log "Применяю базовый sshd-hardening (X11Forwarding off, MaxAuthTries 3, LoginGraceTime 30)..."
PREP_OUT="$(ssh_key "bash /root/ssh-harden.sh prep" 2>&1)" || { echo "$PREP_OUT" >&2; die "prep-hardening упал (полный вывод выше)."; }

log "Проверяю ключевой доступ новым соединением после prep..."
ssh_key "echo ok" >/dev/null || die "SSH не поднялся после hardening-конфига — пароль ещё включён, чини руками."
echo "  OK"

log "Отключаю парольный вход (страховочный таймер на 3 мин, если что-то пойдёт не так)..."
LOCKDOWN_OUT="$(ssh_key "XAI_TEST_BREAK_SSH=${XAI_TEST_BREAK_SSH} bash /root/ssh-harden.sh lockdown" 2>&1)" \
  || { echo "$LOCKDOWN_OUT" >&2; die "lockdown упал (полный вывод выше)."; }

log "Проверяю ключевой доступ новым соединением (пароль теперь должен быть отключён)..."
if ssh_key "echo ok" >/dev/null 2>&1; then
  # Обрыв ровно на подтверждении не должен означать молчаливый выход по set -e:
  # таймер тогда всё равно откатит — говорим об этом прямо.
  ssh_key "bash /root/ssh-harden.sh confirm && rm -f /root/ssh-harden.sh" \
    || die "Не удалось снять страховочный таймер SSH (обрыв соединения?). Через 3 минуты сервер
сам удалит наш SSH drop-in — вернётся вход по паролю; после этого запусти скрипт повторно."
  echo "  OK — парольный вход отключён, ключ работает, страховочный таймер снят."
else
  warn "Новое соединение по ключу не удалось!"
  warn "Через 3 минуты сервер сам удалит наш SSH drop-in (systemd-run) — вернётся вход по паролю."
  die "Останавливаюсь, не продолжаю на firewall без подтверждённого SSH. После отката можно запустить скрипт повторно."
fi

# ---------------------------------------------------------------------------
# 4. Firewall (nftables): only 22/tcp and 443/tcp, policy drop.
#    `nft -c -f` проверяет синтаксис до применения. Страховочный таймер
#    ставится ДО применения и снимается только после того, как домашняя
#    машина зашла новым соединением. Откат аварийный: он не восстанавливает
#    прежний firewall, а снимает фильтрацию целиком — так, чтобы она не
#    вернулась и после reboot.
# ---------------------------------------------------------------------------

cat > "$WORKDIR/firewall.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
STAGE="${1:?usage: firewall.sh apply|confirm}"
SSH_PORT="__SSH_PORT__"
TIMER=xray-auto-install-fw-rollback
XAI_TEST_BREAK_FW="${XAI_TEST_BREAK_FW:-0}"
ROLLBACK_CMD='nft flush ruleset; systemctl disable nftables; : > /etc/nftables.conf'

log()  { printf '[firewall] %s\n' "$*"; }
die()  { printf '[firewall] ОШИБКА: %s\n' "$*" >&2; exit 1; }

rollback_fw() { bash -c "$ROLLBACK_CMD" >/dev/null 2>&1 || true; }
stop_timer() {
  systemctl stop "${TIMER}.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "${TIMER}.service" "${TIMER}.timer" >/dev/null 2>&1 || true
}

if [[ "$STAGE" == "apply" ]]; then
  command -v nft >/dev/null 2>&1 || die "nft не найден (nftables не установлен)"

  SSH_RULE="tcp dport ${SSH_PORT} accept"
  if [[ "$XAI_TEST_BREAK_FW" == 1 ]]; then
    log "ТЕСТ XAI_TEST_BREAK_FW=1: не открываю SSH-порт в ruleset — доступ вернёт таймер"
    SSH_RULE="# ${SSH_RULE} (убрано тестовым флагом XAI_TEST_BREAK_FW)"
  fi

  RENDERED="$(mktemp)"
  cat > "$RENDERED" <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        icmp type { destination-unreachable, echo-request, time-exceeded } accept
        icmpv6 type { destination-unreachable, time-exceeded, echo-request, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
        ${SSH_RULE}
        tcp dport 443 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

  log "проверяю синтаксис (nft -c -f)"
  nft -c -f "$RENDERED" || { rm -f "$RENDERED"; die "nft -c -f не прошёл, ничего не применяю"; }

  stop_timer
  systemd-run --unit="$TIMER" --on-active=120 \
    --description="xray-auto-install: откат firewall, если не подтверждено" \
    /bin/bash -c "$ROLLBACK_CMD" >/dev/null 2>&1 \
    || { rm -f "$RENDERED"; die "systemd-run не смог поставить страховочный таймер — firewall НЕ применяю"; }
  systemctl is-active --quiet "${TIMER}.timer" \
    || { rm -f "$RENDERED"; die "страховочный таймер ${TIMER}.timer не активен — firewall НЕ применяю"; }

  install -m 0644 "$RENDERED" /etc/nftables.conf
  rm -f "$RENDERED"

  log "применяю ruleset"
  nft -f /etc/nftables.conf || { rollback_fw; stop_timer; die "nft -f упал — откатил (фильтрация снята)"; }
  systemctl enable nftables >/dev/null 2>&1 || true

  # nf_conntrack гарантированно загружен только теперь (правило `ct state`
  # в применённом ruleset его подтягивает) — раньше в скрипте sysctl-ключ
  # мог ещё не существовать. Дефолт (обычно 8192 на VPS с ~1ГБ RAM) хватает
  # на 1-2 человек, но современная веб-страница у одного клиента легко
  # держит десятки параллельных TCP-соединений + XHTTP сам многопоточен —
  # при нескольких активных пользователях таблица переполняется, и новые
  # соединения молча дропаются. Поднимаем с запасом; цена — доли МБ RAM.
  if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    echo "net.netfilter.nf_conntrack_max = 32768" > /etc/sysctl.d/99-conntrack.conf
    sysctl -qp /etc/sysctl.d/99-conntrack.conf
    # После reboot systemd-sysctl отрабатывает раньше, чем nftables подтянет
    # nf_conntrack, — ключа ещё нет, и лимит молча остаётся дефолтным (на
    # 138.124.71.35 после перезагрузки было 8192). modules-load.d грузит модуль
    # до systemd-sysctl (тот упорядочен After=systemd-modules-load).
    echo nf_conntrack > /etc/modules-load.d/nf_conntrack.conf
    log "nf_conntrack_max поднят до 32768 (модуль грузится при старте)"
  else
    log "nf_conntrack_max недоступен (модуль не загружен?) — пропускаю"
  fi

  if ! { systemctl is-active --quiet xray && ss -ltnp | grep ':443 ' >/dev/null; }; then
    log "предупреждение: xray/443 не выглядят активными после применения firewall"
  fi
  log "firewall применён — жду confirm с домашней машины (иначе откат через 2 мин)"

elif [[ "$STAGE" == "confirm" ]]; then
  stop_timer
  log "страховочный таймер снят — firewall подтверждён"
else
  die "неизвестный STAGE: $STAGE"
fi
REMOTE_EOF

sed -i "s/__SSH_PORT__/${SSH_PORT}/" "$WORKDIR/firewall.sh"

log "Настраиваю nftables (открыты только ${SSH_PORT} и 443)..."
scp_key "$WORKDIR/firewall.sh" "root@${SERVER_IP}:/root/firewall.sh"
FIREWALL_OUT="$(ssh_key "XAI_TEST_BREAK_FW=${XAI_TEST_BREAK_FW} bash /root/firewall.sh apply" 2>&1)" \
  || { echo "$FIREWALL_OUT" >&2; die "firewall apply упал (полный вывод выше)."; }

log "Проверяю доступ новым соединением после применения firewall..."
if ssh_key "systemctl is-active --quiet xray && ss -ltnp | grep ':443 ' >/dev/null" >/dev/null 2>&1; then
  ssh_key "bash /root/firewall.sh confirm && rm -f /root/firewall.sh" \
    || die "Не удалось снять страховочный таймер firewall (обрыв соединения?). Через 2 минуты
фильтрация будет снята (nft flush + disable nftables), ссылку не выдаю.
Вход: ssh -i '${KEY_PATH}' -o UserKnownHostsFile='${KNOWN_HOSTS}' -o StrictHostKeyChecking=yes root@${SERVER_IP}"
  echo "  OK — SSH и xray живы после применения firewall, страховочный таймер отменён."
else
  warn "Не удалось подтвердить доступ после firewall новым соединением!"
  warn "Через 2 минуты страховочный таймер снимет фильтрацию (nft flush + disable nftables) — SSH вернётся."
  warn "Вход после отката: ssh -i '${KEY_PATH}' -o UserKnownHostsFile='${KNOWN_HOSTS}' -o StrictHostKeyChecking=yes root@${SERVER_IP}"
  die "Firewall не подтверждён — ссылку не выдаю."
fi

# ---------------------------------------------------------------------------
# 5. Output
# ---------------------------------------------------------------------------

VLESS_LINK="vless://${UUID}@${SERVER_IP}:443?encryption=${ENCRYPTION}&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=${FP}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&spx=%2F&type=xhttp#${SERVER_IP}"

# Сначала пустой файл с 600, потом запись: `cat >` в существующий файл
# сохранил бы его старые права (раньше summary со ссылкой выходил 664).
install -m 600 /dev/null "$SUMMARY_FILE"
cat > "$SUMMARY_FILE" <<EOF
xray-auto-install — VLESS + XHTTP + Reality + Vision + VLESS Encryption
Сервер: ${SERVER_IP}
Дата: $(date -u +%Y-%m-%dT%H:%M:%SZ)

== Доступ ==
ssh -i '${KEY_PATH}' -o UserKnownHostsFile='${KNOWN_HOSTS}' -o StrictHostKeyChecking=yes root@${SERVER_IP}
  (парольный вход отключён, только по ключу)

== Firewall ==
nftables, policy drop, открыты только:
  ${SSH_PORT}/tcp — SSH
  443/tcp — VLESS

== Xray / Reality ==
Xray-core: ${XRAY_VERSION} (без фиксации версии — последний стабильный на момент установки)
SNI / target: ${REALITY_SNI} / ${REALITY_SNI}:443

== Ссылка ==
${VLESS_LINK}

== Важно ==
- Нужен клиент с поддержкой VLESS Encryption: свежий v2rayNG/Happ/sing-box.
- Если ссылка перестанет подключаться — попробуй заменить fp=firefox на fp=safari
  или fp=ios прямо в ссылке (см. README).
EOF

# 443 снаружи: firewall-этап подтверждал только новое SSH-соединение, а 443 —
# изнутри сервера. Фильтр у хостинга (вне nftables) закрыл бы его незаметно.
# Только предупреждение: неудача может быть и на стороне сети этой машины.
if timeout 10 bash -c "exec 3<>/dev/tcp/${SERVER_IP}/443" 2>/dev/null; then
  echo "  443/tcp снаружи: доступен"
else
  warn "443/tcp на ${SERVER_IP} недоступен с этой машины. Если клиент не подключится —"
  warn "проверь firewall в панели хостинга (помимо nftables) или сеть этой машины."
fi

log "Готово!"
echo
echo "$VLESS_LINK"
echo
echo "Xray-core: ${XRAY_VERSION}"
echo "Сводка сохранена: $SUMMARY_FILE"
# При запуске через `bash <(wget …)` рядом нет verify.sh — не отправляем
# человека к несуществующему файлу.
VERIFY_SH="$(dirname "${BASH_SOURCE[0]}")/verify.sh"
if [[ -f "$VERIFY_SH" ]]; then
  echo "Проверка сервера: ${VERIFY_SH} ${SERVER_IP}   (с перезагрузкой: ${VERIFY_SH} --reboot ${SERVER_IP})"
else
  echo "Проверка сервера: verify.sh из репозитория (git clone https://github.com/RamDll/xray-auto-install.git), ./verify.sh ${SERVER_IP}"
fi
echo "SSH-ключ: $KEY_PATH"
