#!/usr/bin/env bash
#
# xray-auto-install — native (no Docker, no panel) VLESS + XHTTP + Reality + Vision
# + VLESS Encryption (mlkem768x25519plus, ephemeral X25519 variant — not full
# ML-KEM-768; see the comment above VLESSENC_X25519 below for why), on a fresh
# Debian/Ubuntu box.
#
# Usage:
#   ./install.sh
# It asks for exactly two things: server IP and the root password issued by the
# provider. Everything else (packages, BBR, Xray-core, keys, local Reality "dest"
# stub, SSH hardening, firewall) is automatic and mirrors the manual setup that was
# tested end-to-end (including a full reboot) on 2026-09-09.
#
# What it deliberately does NOT do (evaluated and rejected as low-value for this
# threat model — see project README): create a separate sudo user, install
# fail2ban, add swap, or set an SSH key passphrase.
#
# Robustness patterns below (dpkg-lock handling, competing sshd directives,
# ssh.socket detection, nft syntax-check + timed auto-rollback) are ported from
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

read -rsp "Root password (от провайдера): " ROOT_PASSWORD
echo
[ -n "$ROOT_PASSWORD" ] || die "Пароль не может быть пустым."

SSH_PORT=22
# Пул крупных доменов для Reality serverName. dest у нас локальный (см. ниже),
# сервер к этим доменам не ходит — их реальная доступность/TLS-стек не важны,
# роль чисто визуальная (что видно в ClientHello/самоподписанном серте).
# Один и тот же SNI у всех, кто запустит этот скрипт, — лишний признак для
# массового сканирования, поэтому выбираем случайно из пула при каждом
# запуске, а не жёстко фиксируем один домен.
# Без apple/icloud: Xray-core сам пишет в лог «REALITY: Choosing apple,
# icloud, etc. as the target may get your IP blocked by the GFW» — это
# хардкод-проверка внутри движка, не наша догадка (см. github.com/RamDll/
# ovpn-stack install/NOTES.md). Список доменов — оттуда же (ovpn-stack
# SNI_POOL), уже отобран с учётом этого исключения.
SNI_POOL=(
  www.microsoft.com  www.bing.com       www.samsung.com    www.nvidia.com
  www.amd.com        www.intel.com      www.cloudflare.com cdn.jsdelivr.net
  www.tesla.com       www.sap.com        www.oracle.com     www.dell.com
  www.lenovo.com      www.cisco.com      www.qualcomm.com   www.hp.com
)
SNI="${SNI_POOL[RANDOM % ${#SNI_POOL[@]}]}"
FP="firefox"                     # fp=chrome не заработал на реальном мобильном клиенте, firefox — заработал
DEST_PORT=8444
IP_SLUG="$(echo "$SERVER_IP" | tr '.:' '_')"
KEY_PATH="$HOME/.ssh/xray-auto-install-${IP_SLUG}"
SUMMARY_FILE="$HOME/xray-auto-install-${IP_SLUG}-summary.txt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

SSH_PW_OPTS=(-o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=15)
SSH_KEY_OPTS=(-o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o IdentitiesOnly=yes -o ConnectTimeout=15 -i "$KEY_PATH")

ssh_pw()  { sshpass -p "$ROOT_PASSWORD" ssh "${SSH_PW_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }
scp_pw()  { sshpass -p "$ROOT_PASSWORD" scp -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no -P "$SSH_PORT" "$@"; }
ssh_key() { ssh "${SSH_KEY_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }
scp_key() { scp -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" -P "$SSH_PORT" "$@"; }

# Скрипт рассчитан на свежий/переустановленный сервер по этому же IP — смена
# хост-ключа тут норма (новый образ = новый ключ), а не признак MITM. Тихо
# чистим старую запись под этот конкретный IP перед подключением, чтобы не
# упасть на "Host key verification failed"; если записи нет — no-op.
if ssh-keygen -F "$SERVER_IP" >/dev/null 2>&1; then
  ssh-keygen -R "$SERVER_IP" >/dev/null 2>&1
  echo "  (старый хост-ключ для ${SERVER_IP} в known_hosts очищен — сервер переустановлен)"
fi

log "Проверяю парольный доступ к ${SERVER_IP}..."
ssh_pw "echo ok" >/dev/null || die "Не удалось подключиться по паролю. Проверь IP и пароль — либо на этом сервере
парольный вход уже отключён (в т.ч. этим же скриптом ранее): повторно так не поставить, нужен свежий root-пароль
от провайдера — переустанови ОС в его панели и запусти скрипт заново."
echo "  OK"
echo "  Reality SNI (случайно из пула): ${SNI}"

# ---------------------------------------------------------------------------
# 1. Remote bootstrap: packages, BBR, Xray-core, keys, fakesite, config.json
# ---------------------------------------------------------------------------

log "Собираю удалённый bootstrap-скрипт..."

cat > "$WORKDIR/bootstrap.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

SNI="__SNI__"
DEST_PORT="__DEST_PORT__"

log()  { printf '[bootstrap] %s\n' "$*"; }
die()  { printf '[bootstrap] ОШИБКА: %s\n' "$*" >&2; exit 1; }

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

log "останавливаю apt-daily/unattended-upgrades, чтобы не воевали за dpkg-lock"
stop_apt_daily
wait_dpkg_lock
dpkg --configure -a >/dev/null 2>&1 || true

log "apt update"
apt_do update -qq
log "устанавливаю пакеты"
apt_do -y install -qq curl unzip nginx openssl nftables ca-certificates >/dev/null
systemctl start apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true

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
for _ in $(seq 1 10); do ntp_ok && break; sleep 1; done
ntp_ok || log "предупреждение: время ещё не синхронизировано, продолжаю всё равно"

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
for try in 1 2 3; do
  if bash -c "$(curl -fsSL --retry 3 https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install >/dev/null 2>&1; then
    XRAY_INSTALL_OK=1
    break
  fi
  log "установка Xray-core — попытка $try не удалась, жду 10с и повторяю"
  sleep 10
done
[[ "$XRAY_INSTALL_OK" == 1 ]] || die "не удалось установить Xray-core после 3 попыток"
[ -x /usr/local/bin/xray ] || die "установщик отработал, но /usr/local/bin/xray не найден"
/usr/local/bin/xray version   # печатает 2 строки; НЕ пайпить в head — xray version | head -1
                               # ловит SIGPIPE (head закрывает трубу после 1-й строки, xray
                               # падает на второй write) => exit 141 под set -o pipefail,
                               # воспроизведено вживую на 95.128.157.141

log "генерирую ключи"
UUID=$(/usr/local/bin/xray uuid)
SHORT_ID=$(openssl rand -hex 8)

X25519_OUT=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUT" | grep -iE '^Private ?key' | sed -E 's/^[^:]+:\s*//')
PUBLIC_KEY=$(echo "$X25519_OUT" | grep -iE '^Public ?key|^Password' | head -1 | sed -E 's/^[^:]+:\s*//')

# `xray vlessenc` печатает ДВА раздела: "X25519, not Post-Quantum" (короткие
# значения, ~44 символа) и "ML-KEM-768, Post-Quantum" (длинные, ~1600+ символов
# — полноценный ML-KEM-768). Берём КОРОТКИЙ, эфемерный X25519-вариант: сам
# `xray vlessenc` в шапке вывода прямо пишет "Ephemeral key exchange is
# Post-Quantum safe anyway" — эфемерность ключа уже даёт защиту от
# harvest-now-decrypt-later, полный ML-KEM-768 тут даёт лишь дополнительную
# алгоритмическую стойкость ценой гигантской ссылки/QR. Это же — короткий
# вариант — было в изначальной вручную протестированной и подтверждённой
# рабочей конфигурации 138.124.71.35 (в её summary он был ошибочно подписан
# "постквантовое шифрование" — на деле это не так, см. историю в чате).
# Оба варианта используют одинаковый строковый префикс mlkem768x25519plus.native,
# поэтому явно обрезаем вывод ДО заголовка ML-KEM-768, чтобы не выхватить его.
VLESSENC_OUT=$(/usr/local/bin/xray vlessenc)
VLESSENC_X25519=$(echo "$VLESSENC_OUT" | awk '/ML-KEM-768/{exit} {print}')
DECRYPTION=$(echo "$VLESSENC_X25519" | grep -oE 'mlkem768x25519plus\.native\.[0-9]+s\.[A-Za-z0-9_-]+' | head -1)
ENCRYPTION=$(echo "$VLESSENC_X25519" | grep -oE 'mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]+' | head -1)

[ -n "$UUID" ] && [ -n "$SHORT_ID" ] && [ -n "$PRIVATE_KEY" ] && [ -n "$PUBLIC_KEY" ] \
  && [ -n "$DECRYPTION" ] && [ -n "$ENCRYPTION" ] || {
  echo "Не удалось распарсить сгенерированные ключи." >&2
  echo "--- xray x25519 ---" >&2; echo "$X25519_OUT" >&2
  echo "--- xray vlessenc ---" >&2; echo "$VLESSENC_OUT" >&2
  exit 1
}

log "локальная заглушка dest (nginx на 127.0.0.1:${DEST_PORT})"
mkdir -p /etc/nginx/fakesite-ssl
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/nginx/fakesite-ssl/key.pem -out /etc/nginx/fakesite-ssl/cert.pem \
  -days 3650 -nodes -subj "/CN=${SNI}" -addext "subjectAltName=DNS:${SNI}" >/dev/null 2>&1

cat > /etc/nginx/conf.d/fakesite.conf <<EOF
server {
    listen 127.0.0.1:${DEST_PORT} ssl;
    server_name ${SNI};
    ssl_certificate /etc/nginx/fakesite-ssl/cert.pem;
    ssl_certificate_key /etc/nginx/fakesite-ssl/key.pem;
    location / {
        return 200 "OK\n";
    }
}
EOF
nginx -t >/dev/null
systemctl enable --now nginx >/dev/null 2>&1
systemctl reload nginx

log "config.json"
mkdir -p /usr/local/etc/xray
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
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
        "dest": "127.0.0.1:${DEST_PORT}",
        "xver": 0,
        "serverNames": ["${SNI}"],
        "privateKey": "${PRIVATE_KEY}",
        "shortIds": ["${SHORT_ID}"]
      }
    },
    "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF

systemctl enable --now xray >/dev/null 2>&1
systemctl restart xray
sleep 1
systemctl is-active --quiet xray || { echo "xray не запустился" >&2; journalctl -u xray --no-pager -n 40 >&2; exit 1; }
ss -ltnp | grep -q ':443 ' || { echo "порт 443 не слушается" >&2; exit 1; }
curl -sk "https://127.0.0.1:${DEST_PORT}/" | grep -q OK || { echo "fakesite не отвечает" >&2; exit 1; }

echo "===XRAY_AUTO_INSTALL_VARS==="
echo "UUID=${UUID}"
echo "SHORT_ID=${SHORT_ID}"
echo "PRIVATE_KEY=${PRIVATE_KEY}"
echo "PUBLIC_KEY=${PUBLIC_KEY}"
echo "DECRYPTION=${DECRYPTION}"
echo "ENCRYPTION=${ENCRYPTION}"
echo "===END==="
REMOTE_EOF

sed -i "s/__SNI__/${SNI}/; s/__DEST_PORT__/${DEST_PORT}/" "$WORKDIR/bootstrap.sh"

log "Заливаю и запускаю bootstrap на сервере (это займёт минуту-две)..."
scp_pw "$WORKDIR/bootstrap.sh" "root@${SERVER_IP}:/root/bootstrap.sh"
BOOTSTRAP_OUT="$(ssh_pw "bash /root/bootstrap.sh && rm -f /root/bootstrap.sh" 2>&1)" || {
  echo "$BOOTSTRAP_OUT" >&2
  die "Bootstrap упал (полный вывод выше)."
}

eval "$(echo "$BOOTSTRAP_OUT" | sed -n '/===XRAY_AUTO_INSTALL_VARS===/,/===END===/p' | grep -E '^[A-Z_]+=' )"
for v in UUID SHORT_ID PRIVATE_KEY PUBLIC_KEY DECRYPTION ENCRYPTION; do
  [ -n "${!v:-}" ] || die "Не получил значение $v от сервера."
done
echo "  OK — сервис xray активен, порт 443 слушается, fakesite отвечает."

# ---------------------------------------------------------------------------
# 2. SSH key: generate, install, verify via a brand-new connection
# ---------------------------------------------------------------------------

log "Генерирую SSH-ключ (${KEY_PATH})..."
if [ -f "$KEY_PATH" ]; then rm -f "$KEY_PATH" "$KEY_PATH.pub"; fi
ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -C "xray-auto-install-${SERVER_IP}" >/dev/null

PUBKEY_CONTENT="$(cat "${KEY_PATH}.pub")"
ssh_pw "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '${PUBKEY_CONTENT}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"

log "Проверяю ключевой доступ НОВЫМ соединением (пароль ещё не трогали)..."
ssh_key "echo ok" >/dev/null || die "Ключевой доступ не заработал — пароль НЕ отключаю, разбирайся руками."
echo "  OK"

# ---------------------------------------------------------------------------
# 3. SSH hardening. One uploaded script, called twice with different stages:
#    "prep" (harmless bits, password still enabled as a safety net) then
#    "lockdown" (disable password). Each stage does, itself, on the server:
#      - neutralize competing PasswordAuthentication/PermitRootLogin "yes"
#        lines in OTHER config files (cloud-init's 50-cloud-init.conf is a
#        known offender — sshd takes the FIRST matching directive, so a
#        stray "yes" elsewhere can silently override our 00- drop-in)
#      - `sshd -t` before restarting, abort+rollback the drop-in on failure
#      - detect ssh.socket (Debian trixie can socket-activate ssh) and
#        restart the right unit(s)
#      - a local TCP self-check on 127.0.0.1:$port right after restart —
#        fails fast with a clear message instead of a home-side timeout
#      - `sshd -T` (authoritative effective config) to confirm what actually
#        took effect, not just what we wrote
#    "lockdown" additionally arms a systemd-run timer that reverts the
#    password-disable drop-in after 3 minutes unless cancelled — cancelled
#    only after this script confirms a brand-new key-based connection works.
# ---------------------------------------------------------------------------

cat > "$WORKDIR/ssh-harden.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
STAGE="${1:?usage: ssh-harden.sh prep|lockdown}"
PORT=22

log()  { printf '[ssh-harden] %s\n' "$*"; }
die()  { printf '[ssh-harden] ОШИБКА: %s\n' "$*" >&2; exit 1; }

backup_capped() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  cp -a "$file" "${file}.bak.$(date +%s)"
  local old
  mapfile -t old < <(ls -1t "${file}".bak.* 2>/dev/null | tail -n +4)
  if [[ ${#old[@]} -gt 0 ]]; then rm -f -- "${old[@]}"; fi
}

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

DROPIN_HARDENING=/etc/ssh/sshd_config.d/00-hardening.conf
DROPIN_NOPASS=/etc/ssh/sshd_config.d/00-disable-password.conf

if [[ "$STAGE" == "prep" ]]; then
  backup_capped "$DROPIN_HARDENING"
  cat > "$DROPIN_HARDENING" <<'EOF'
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF

  log "проверяю синтаксис (sshd -t)"
  if ! sshd -t; then
    rm -f "$DROPIN_HARDENING"
    die "sshd -t не прошёл — drop-in удалён, ничего не перезапускал"
  fi

  restart_ssh
  local_selfcheck || { rm -f "$DROPIN_HARDENING"; restart_ssh; die "ssh не слушает $PORT локально после restart — откатил и перезапустил"; }
  log "prep готово: X11Forwarding/MaxAuthTries/LoginGraceTime применены, ssh слушает $PORT"

elif [[ "$STAGE" == "lockdown" ]]; then
  backup_capped "$DROPIN_NOPASS"
  cat > "$DROPIN_NOPASS" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF

  # sshd берёт ПЕРВОЕ вхождение директивы. Наши 00-* дроп-ины идут первыми
  # по алфавиту, но если где-то (главный sshd_config, cloud-init) уже стоит
  # `yes` РАНЬШЕ по include-порядку — она молча победит. Глушим все такие
  # строки везде, кроме наших файлов.
  cf_list=(/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf)
  for cf in "${cf_list[@]}"; do
    [[ -f "$cf" && "$cf" != "$DROPIN_NOPASS" && "$cf" != "$DROPIN_HARDENING" ]] || continue
    grep -qiE '^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin)[[:space:]]+yes' "$cf" || continue
    backup_capped "$cf"
    sed -ri 's/^([[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitRootLogin)[[:space:]]+yes.*)/# \1  # off: xray-auto-install/I' "$cf"
    log "заглушил конкурирующую строку в $cf"
  done

  log "проверяю синтаксис (sshd -t)"
  if ! sshd -t; then
    rm -f "$DROPIN_NOPASS"
    die "sshd -t не прошёл — drop-in удалён, пароль НЕ отключён"
  fi

  # страховочный таймер: если после restart ключ вдруг не пустит — сервер
  # сам откатит запрет пароля через 3 минуты. Снимается ниже командой
  # ssh-harden.sh confirm, вызываемой ТОЛЬКО после успешной проверки новым
  # соединением с домашней машины.
  systemd-run --unit=xray-auto-install-ssh-rollback --on-active=180 \
    --description="xray-auto-install: откат отключения пароля, если не подтверждено" \
    /bin/bash -c "rm -f ${DROPIN_NOPASS}; systemctl daemon-reload; systemctl reload ssh.service 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart ssh.service 2>/dev/null || systemctl restart ssh 2>/dev/null || true" \
    >/dev/null 2>&1 || log "systemd-run недоступен — страховочный таймер не поставлен (действую без него)"

  restart_ssh
  if ! local_selfcheck; then
    rm -f "$DROPIN_NOPASS"
    restart_ssh
    die "ssh не слушает $PORT локально после restart — откатил отключение пароля"
  fi

  sshd_eff="$(sshd -T 2>/dev/null || true)"
  pw_eff="$(awk '$1=="passwordauthentication"{print $2}' <<<"$sshd_eff")"
  root_eff="$(awk '$1=="permitrootlogin"{print $2}' <<<"$sshd_eff")"
  if [[ "$pw_eff" != "no" ]]; then
    log "ВНИМАНИЕ: sshd -T показывает passwordauthentication=$pw_eff — пароль НЕ отключён эффективно."
    log "Конкурирующие строки (проверь руками):"
    grep -rniE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null || true
  else
    log "lockdown готово: sshd -T подтверждает passwordauthentication=no, permitrootlogin=$root_eff"
  fi

elif [[ "$STAGE" == "confirm" ]]; then
  systemctl stop xray-auto-install-ssh-rollback.timer >/dev/null 2>&1 || true
  systemctl reset-failed xray-auto-install-ssh-rollback.service >/dev/null 2>&1 || true
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
LOCKDOWN_OUT="$(ssh_key "bash /root/ssh-harden.sh lockdown" 2>&1)" || { echo "$LOCKDOWN_OUT" >&2; die "lockdown упал (полный вывод выше)."; }

log "Проверяю ключевой доступ новым соединением (пароль теперь должен быть отключён)..."
if ssh_key "echo ok" >/dev/null 2>&1; then
  ssh_key "bash /root/ssh-harden.sh confirm; rm -f /root/ssh-harden.sh"
  echo "  OK — парольный вход отключён, ключ работает, страховочный таймер снят."
else
  warn "Новое соединение не удалось! Если это был временный сбой — попробуй ssh руками в ближайшие 3 минуты."
  warn "Если не получится — сервер сам откатит отключение пароля через страховочный таймер (systemd-run, 3 мин)."
  die "Останавливаюсь, не продолжаю на firewall без подтверждённого SSH."
fi

# ---------------------------------------------------------------------------
# 4. Firewall (nftables): only 22/tcp and 443/tcp, policy drop.
#    `nft -c -f` validates syntax before touching the live ruleset. A
#    systemd-run timer reverts to allow-all after 2 minutes unless cancelled
#    — cancelled only after a brand-new SSH connection confirms access.
# ---------------------------------------------------------------------------

cat > "$WORKDIR/firewall.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
STAGE="${1:?usage: firewall.sh apply|confirm}"
SSH_PORT="__SSH_PORT__"

log()  { printf '[firewall] %s\n' "$*"; }
die()  { printf '[firewall] ОШИБКА: %s\n' "$*" >&2; exit 1; }

if [[ "$STAGE" == "apply" ]]; then
  command -v nft >/dev/null 2>&1 || die "nft не найден (nftables не установлен)"

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
        tcp dport ${SSH_PORT} accept
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

  install -m 0644 "$RENDERED" /etc/nftables.conf
  rm -f "$RENDERED"

  systemd-run --unit=xray-auto-install-fw-rollback --on-active=120 \
    --description="xray-auto-install: откат firewall, если не подтверждено" \
    /bin/bash -c "nft flush ruleset" >/dev/null 2>&1 \
    || log "systemd-run недоступен — страховочный таймер не поставлен (действую без него)"

  log "применяю ruleset"
  nft -f /etc/nftables.conf || { nft flush ruleset; die "nft -f упал — откатил (flush ruleset)"; }
  systemctl enable nftables >/dev/null 2>&1 || true

  if ! { systemctl is-active --quiet xray && ss -ltnp | grep -q ':443 '; }; then
    log "предупреждение: xray/443 не выглядят активными после применения firewall"
  fi
  log "firewall применён — жду confirm с домашней машины (иначе откат через 2 мин)"

elif [[ "$STAGE" == "confirm" ]]; then
  systemctl stop xray-auto-install-fw-rollback.timer >/dev/null 2>&1 || true
  systemctl reset-failed xray-auto-install-fw-rollback.service >/dev/null 2>&1 || true
  log "страховочный таймер снят — firewall подтверждён"
else
  die "неизвестный STAGE: $STAGE"
fi
REMOTE_EOF

sed -i "s/__SSH_PORT__/${SSH_PORT}/" "$WORKDIR/firewall.sh"

log "Настраиваю nftables (открыты только ${SSH_PORT} и 443)..."
scp_key "$WORKDIR/firewall.sh" "root@${SERVER_IP}:/root/firewall.sh"
FIREWALL_OUT="$(ssh_key "bash /root/firewall.sh apply" 2>&1)" || { echo "$FIREWALL_OUT" >&2; die "firewall apply упал (полный вывод выше)."; }

log "Проверяю доступ новым соединением после применения firewall..."
if ssh_key "systemctl is-active --quiet xray && ss -ltnp | grep -q ':443 '" >/dev/null 2>&1; then
  ssh_key "bash /root/firewall.sh confirm; rm -f /root/firewall.sh"
  echo "  OK — SSH и xray живы после применения firewall, страховочный таймер отменён."
else
  warn "Не удалось подтвердить состояние после firewall новым соединением!"
  warn "Через 2 минуты сработает страховочный таймер и правила сбросятся сами (nft flush ruleset)."
fi

# ---------------------------------------------------------------------------
# 5. Output
# ---------------------------------------------------------------------------

VLESS_LINK="vless://${UUID}@${SERVER_IP}:443?encryption=${ENCRYPTION}&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=${FP}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&spx=%2F&type=xhttp#${SERVER_IP}"

cat > "$SUMMARY_FILE" <<EOF
xray-auto-install — VLESS + XHTTP + Reality + Vision + VLESS Encryption
Сервер: ${SERVER_IP}
Дата: $(date -u +%Y-%m-%dT%H:%M:%SZ)

== Доступ ==
ssh -i '${KEY_PATH}' root@${SERVER_IP}
  (парольный вход отключён, только по ключу)

== Firewall ==
nftables, policy drop, открыты только:
  ${SSH_PORT}/tcp — SSH
  443/tcp — VLESS

== Ссылка ==
${VLESS_LINK}

== Важно ==
- Нужен клиент с поддержкой VLESS Encryption: свежий v2rayNG/Happ/sing-box.
- Если ссылка перестанет подключаться — попробуй заменить fp=firefox на fp=safari
  или fp=ios прямо в ссылке (см. README).
EOF

log "Готово!"
echo
echo "$VLESS_LINK"
echo
echo "Сводка сохранена: $SUMMARY_FILE"
echo "SSH-ключ: $KEY_PATH"
