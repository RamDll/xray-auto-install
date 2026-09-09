#!/usr/bin/env bash
#
# xray-auto-install — native (no Docker, no panel) VLESS + XHTTP + Reality + Vision
# + post-quantum VLESS Encryption (mlkem768x25519plus), on a fresh Debian/Ubuntu box.
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
SNI="www.microsoft.com"          # тестировался и подтверждён рабочим на 138.124.71.35
FP="firefox"                     # fp=chrome не заработал на реальном мобильном клиенте, firefox — заработал
DEST_PORT=8444
IP_SLUG="$(echo "$SERVER_IP" | tr '.:' '_')"
KEY_PATH="$HOME/.ssh/xray-auto-install-${IP_SLUG}"
SUMMARY_FILE="$HOME/xray-auto-install-${IP_SLUG}-summary.txt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

SSH_PW_OPTS=(-o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=15)
SSH_KEY_OPTS=(-o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=15 -i "$KEY_PATH")

ssh_pw()  { sshpass -p "$ROOT_PASSWORD" ssh "${SSH_PW_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }
scp_pw()  { sshpass -p "$ROOT_PASSWORD" scp -o StrictHostKeyChecking=accept-new -P "$SSH_PORT" "$@"; }
ssh_key() { ssh "${SSH_KEY_OPTS[@]}" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }

log "Проверяю парольный доступ к ${SERVER_IP}..."
ssh_pw "echo ok" >/dev/null || die "Не удалось подключиться по паролю. Проверь IP и пароль."
echo "  OK"

# ---------------------------------------------------------------------------
# 1. Remote bootstrap: packages, BBR, Xray-core, keys, fakesite, config.json
# ---------------------------------------------------------------------------

log "Собираю удалённый bootstrap-скрипт..."

cat > "$WORKDIR/bootstrap.sh" <<'REMOTE_EOF'
#!/usr/bin/env bash
set -euo pipefail

SNI="__SNI__"
DEST_PORT="__DEST_PORT__"

echo "--- apt update / install базовых пакетов ---"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl unzip nginx openssl nftables ca-certificates >/dev/null

echo "--- BBR ---"
modprobe tcp_bbr || true
echo tcp_bbr > /etc/modules-load.d/bbr.conf
cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sysctl --system >/dev/null 2>&1

echo "--- Xray-core (официальный установщик, latest stable release) ---"
bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install >/dev/null
/usr/local/bin/xray version | head -1

echo "--- Генерация ключей ---"
UUID=$(/usr/local/bin/xray uuid)
SHORT_ID=$(openssl rand -hex 8)

X25519_OUT=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUT" | grep -iE '^Private ?key' | sed -E 's/^[^:]+:\s*//')
PUBLIC_KEY=$(echo "$X25519_OUT" | grep -iE '^Public ?key|^Password' | head -1 | sed -E 's/^[^:]+:\s*//')

VLESSENC_OUT=$(/usr/local/bin/xray vlessenc)
DECRYPTION=$(echo "$VLESSENC_OUT" | grep -oE 'mlkem768x25519plus\.native\.[0-9]+s\.[A-Za-z0-9_-]+' | head -1)
ENCRYPTION=$(echo "$VLESSENC_OUT" | grep -oE 'mlkem768x25519plus\.native\.0rtt\.[A-Za-z0-9_-]+' | head -1)

[ -n "$UUID" ] && [ -n "$SHORT_ID" ] && [ -n "$PRIVATE_KEY" ] && [ -n "$PUBLIC_KEY" ] \
  && [ -n "$DECRYPTION" ] && [ -n "$ENCRYPTION" ] || {
  echo "Не удалось распарсить сгенерированные ключи." >&2
  echo "--- xray x25519 ---" >&2; echo "$X25519_OUT" >&2
  echo "--- xray vlessenc ---" >&2; echo "$VLESSENC_OUT" >&2
  exit 1
}

echo "--- Локальная заглушка dest (nginx на 127.0.0.1:${DEST_PORT}) ---"
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

echo "--- config.json ---"
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
BOOTSTRAP_OUT="$(ssh_pw "bash /root/bootstrap.sh && rm -f /root/bootstrap.sh")" \
  || die "Bootstrap упал. Смотри вывод выше."
echo "$BOOTSTRAP_OUT" | sed '/^===XRAY_AUTO_INSTALL_VARS===$/,$d'

eval "$(echo "$BOOTSTRAP_OUT" | sed -n '/===XRAY_AUTO_INSTALL_VARS===/,/===END===/p' | grep -E '^[A-Z_]+=' )"
for v in UUID SHORT_ID PRIVATE_KEY PUBLIC_KEY DECRYPTION ENCRYPTION; do
  [ -n "${!v:-}" ] || die "Не получил значение $v от сервера."
done
echo "  OK — сервис xray активен, порт 443 слушается, fakesite отвечает."

# ---------------------------------------------------------------------------
# 2. SSH key: generate, install, verify via a brand-new connection
# ---------------------------------------------------------------------------

log "Генерирую SSH-ключ (${KEY_PATH})..."
[ -f "$KEY_PATH" ] && rm -f "$KEY_PATH" "$KEY_PATH.pub"
ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -C "xray-auto-install-${SERVER_IP}" >/dev/null

PUBKEY_CONTENT="$(cat "${KEY_PATH}.pub")"
ssh_pw "mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '${PUBKEY_CONTENT}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"

log "Проверяю ключевой доступ НОВЫМ соединением (пароль ещё не трогали)..."
ssh_key "echo ok" >/dev/null || die "Ключевой доступ не заработал — пароль НЕ отключаю, разбирайся руками."
echo "  OK"

# ---------------------------------------------------------------------------
# 3. SSH hardening — first the harmless bits (restart + verify with password
#    still enabled as a safety net), THEN disable password auth and verify again.
# ---------------------------------------------------------------------------

log "Применяю базовый sshd-hardening (X11Forwarding off, MaxAuthTries 3, LoginGraceTime 30)..."
ssh_key "cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd"

log "Проверяю ключевой доступ новым соединением после первого restart..."
ssh_key "echo ok" >/dev/null || die "SSH не поднялся после hardening-конфига — пароль ещё включён, чини руками."
echo "  OK"

log "Отключаю парольный вход..."
ssh_key "cat > /etc/ssh/sshd_config.d/00-disable-password.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd"

log "Проверяю ключевой доступ новым соединением (пароль теперь должен быть отключён)..."
ssh_key "echo ok" >/dev/null || die "SSH не поднялся после отключения пароля! Доступ по паролю уже выключен — используй консоль провайдера."
echo "  OK — парольный вход отключён, ключ работает."

# ---------------------------------------------------------------------------
# 4. Firewall (nftables): only 22/tcp and 443/tcp, policy drop.
#    Safety net: a background job reverts to allow-all if we don't cancel it
#    within 2 minutes (protects against a typo locking us out).
# ---------------------------------------------------------------------------

log "Настраиваю nftables (открыты только 22 и 443)..."
ssh_key "cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif \"lo\" accept
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
nohup bash -c 'sleep 120 && nft flush ruleset' >/dev/null 2>&1 & disown
echo \$! > /root/.xray-auto-install-fw-failsafe.pid
nft -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1"

log "Проверяю доступ новым соединением после применения firewall..."
if ssh_key "kill \$(cat /root/.xray-auto-install-fw-failsafe.pid) 2>/dev/null; rm -f /root/.xray-auto-install-fw-failsafe.pid; systemctl is-active --quiet xray && ss -ltnp | grep -q ':443 '" ; then
  echo "  OK — SSH и xray живы после применения firewall, failsafe-таймер отменён."
else
  warn "Не удалось подтвердить состояние после firewall новым соединением!"
  warn "Через 2 минуты сработает failsafe и правила сбросятся сами (nft flush ruleset)."
fi

# ---------------------------------------------------------------------------
# 5. Output
# ---------------------------------------------------------------------------

VLESS_LINK="vless://${UUID}@${SERVER_IP}:443?encryption=${ENCRYPTION}&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=${FP}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&spx=%2F&type=xhttp#xray-auto-install"

cat > "$SUMMARY_FILE" <<EOF
xray-auto-install — VLESS + XHTTP + Reality + Vision + PQC
Сервер: ${SERVER_IP}
Дата: $(date -u +%Y-%m-%dT%H:%M:%SZ)

== Доступ ==
ssh -i '${KEY_PATH}' root@${SERVER_IP}
  (парольный вход отключён, только по ключу)

== Firewall ==
nftables, policy drop, открыты только:
  ${SSH_PORT}/tcp — SSH
  443/tcp — VLESS

== Стек ==
- Xray-core (последний стабильный релиз, установлен официальным скриптом XTLS/Xray-install)
- BBR включён и персистентен
- Конфиг: /usr/local/etc/xray/config.json
- Локальная заглушка dest: nginx на 127.0.0.1:${DEST_PORT}, самоподписанный серт (CN=${SNI})

== Протокол ==
VLESS + XHTTP (транспорт) + Reality (маскировка) + Vision flow + постквантовое VLESS-шифрование
UUID: ${UUID}
SNI: ${SNI}
shortId: ${SHORT_ID}
Reality privateKey (сервер): ${PRIVATE_KEY}
Reality publicKey (клиент): ${PUBLIC_KEY}

== Ссылка ==
${VLESS_LINK}

== Важно ==
- fp=chrome не работал на некоторых мобильных клиентах, fp=firefox — рабочий вариант по умолчанию.
- Нужен клиент с поддержкой VLESS Encryption (PQC): свежий v2rayNG/Happ/sing-box.
- Отдельный sudo-пользователь, fail2ban и passphrase на ключе сознательно не настраивались
  (при полной компрометации сервера/машины они не добавляют защиты — см. README).
EOF

log "Готово!"
echo
echo "$VLESS_LINK"
echo
echo "Сводка сохранена: $SUMMARY_FILE"
echo "SSH-ключ: $KEY_PATH"
