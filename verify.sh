#!/usr/bin/env bash
#
# verify.sh — проверка сервера, поставленного install.sh. Запускается с той же
# локальной машины: берёт тот же SSH-ключ, закреплённый known_hosts и summary.
#
# Usage:
#   ./verify.sh <IP>            — прогнать проверки
#   ./verify.sh --reboot <IP>   — проверки → перезагрузка → дождаться SSH → проверки
#
# Печатает PASS/FAIL/WARN по пунктам; код выхода ≠ 0, если был хоть один FAIL.
# Только читает состояние (кроме самой перезагрузки в режиме --reboot).
# Секреты (privateKey, decryption) никогда не печатает — только число совпадений.

set -euo pipefail

die() { printf 'ERROR: %s\n' "$1" >&2; exit 2; }

REBOOT=0
if [[ "${1:-}" == "--reboot" ]]; then REBOOT=1; shift; fi
SERVER_IP="${1:-}"
[[ -n "$SERVER_IP" && $# -eq 1 ]] || die "usage: ./verify.sh [--reboot] <IPv4>"
IPV4_OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
[[ "$SERVER_IP" =~ ^${IPV4_OCTET}(\.${IPV4_OCTET}){3}$ ]] || die "нужен IPv4-адрес, как при установке: '${SERVER_IP}'"

IP_SLUG="$(echo "$SERVER_IP" | tr '.:' '_')"
KEY_PATH="$HOME/.ssh/xray-auto-install-${IP_SLUG}"
KNOWN_HOSTS="$HOME/.ssh/xray-auto-install-${IP_SLUG}.known_hosts"
SUMMARY_FILE="$HOME/xray-auto-install-${IP_SLUG}-summary.txt"
SSH_PORT=22
[[ -f "$KEY_PATH" ]] || die "нет ключа $KEY_PATH — сервер ставился не с этой машины?"
[[ -s "$KNOWN_HOSTS" ]] || die "нет $KNOWN_HOSTS — без закреплённого хост-ключа не подключаюсь"

# Хост-ключ закреплён при установке: StrictHostKeyChecking=yes, подмена сервера
# = отказ, а не молчаливое accept-new.
SSH_OPTS=(-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
  -o "UserKnownHostsFile=$KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
ssh_key() { ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o PasswordAuthentication=no -o IdentitiesOnly=yes \
  -i "$KEY_PATH" -p "$SSH_PORT" "root@${SERVER_IP}" "$@"; }

if [[ -t 1 ]]; then C_OK=$'\033[1;32m' C_BAD=$'\033[1;31m' C_WARN=$'\033[1;33m' C_OFF=$'\033[0m'
else C_OK="" C_BAD="" C_WARN="" C_OFF=""; fi
FAILS=0
report() {  # report STATUS NAME DETAIL
  local c pad
  case "$1" in PASS) c=$C_OK ;; FAIL) c=$C_BAD; FAILS=$((FAILS + 1)) ;; *) c=$C_WARN ;; esac
  # printf %-Ns считает байты, а кириллица в UTF-8 — 2 байта на букву;
  # ${#var} в UTF-8-локали считает символы — выравниваем по ним.
  pad=$(( 34 - ${#2} )); (( pad < 1 )) && pad=1
  printf '%s%-4s%s  %s%*s%s\n' "$c" "$1" "$C_OFF" "$2" "$pad" "" "$3"
}

# Проверки, выполняемые на сервере. Каждая печатает строку
# STATUS<TAB>имя<TAB>подробности; локальная сторона только собирает их.
REMOTE_CHECKS=$(cat <<'REMOTE_EOF'
set -uo pipefail
C=/usr/local/etc/xray/config.json
r() { printf '%s\t%s\t%s\n' "$1" "$2" "$3"; }
chk() { if [[ "$2" == "$3" ]]; then r PASS "$1" "$2"; else r FAIL "$1" "есть '$2', ожидалось '$3'"; fi; }
jget() { grep -oE "\"$1\": *\"[^\"]+\"" "$C" 2>/dev/null | head -1 | cut -d'"' -f4; }

# --- SSH
if sshd -t 2>/dev/null; then r PASS "sshd -t" "синтаксис OK"; else r FAIL "sshd -t" "$(sshd -t 2>&1 | head -1)"; fi
eff="$(sshd -T -C "user=root,host=x,addr=${SSH_CLIENT%% *}" 2>&1)"
for pair in passwordauthentication=no kbdinteractiveauthentication=no \
            'permitrootlogin=prohibit-password|without-password' \
            x11forwarding=no maxauthtries=3 logingracetime=30; do
  key="${pair%%=*}"; want="${pair#*=}"
  got="$(awk -v k="$key" '$1 == k { print $2; exit }' <<<"$eff")"
  if [[ "$got" =~ ^(${want})$ ]]; then r PASS "sshd -T $key" "$got"; else r FAIL "sshd -T $key" "есть '${got:-<нет>}', ожидалось $want"; fi
done
chk "ssh drop-in" "$(ls /etc/ssh/sshd_config.d/00-xray-auto-install.conf 2>/dev/null)" /etc/ssh/sshd_config.d/00-xray-auto-install.conf

# --- firewall
input="$(nft list chain inet filter input 2>/dev/null)"
if [[ -n "$input" ]]; then r PASS "nft ruleset" "загружен"; else r FAIL "nft ruleset" "нет table inet filter / chain input"; fi
if grep -q 'policy drop' <<<"$input"; then r PASS "nft input policy" "drop"; else r FAIL "nft input policy" "не drop"; fi
ports="$(grep -oE 'dport [0-9]+ accept' <<<"$input" | awk '{print $2}' | sort -n | paste -sd, -)"
chk "nft открытые порты" "${ports:-<нет>}" "22,443"
chk "nftables enabled" "$(systemctl is-enabled nftables 2>/dev/null)" enabled
timers="$(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE 'xray-auto-install-[a-z-]+' | sort -u | paste -sd, -)"
if [[ -z "$timers" ]]; then r PASS "таймеры отката" "нет"; else r FAIL "таймеры отката" "висят: $timers"; fi

# --- xray (сразу после reboot сервис может ещё подниматься — даём ~15с)
for _ in $(seq 1 15); do systemctl is-active --quiet xray && break; sleep 1; done
chk "xray active" "$(systemctl is-active xray 2>/dev/null)" active
if /usr/local/bin/xray run -test -c "$C" >/dev/null 2>&1; then r PASS "xray run -test" "Configuration OK"; else r FAIL "xray run -test" "конфиг не принят"; fi
if ss -ltnp 2>/dev/null | grep ':443 ' | grep '"xray"' >/dev/null; then r PASS "443 слушает" "xray"; else r FAIL "443 слушает" "не xray / никто"; fi

# --- Reality target: из конфига + повторная проверка с сервера той же командой, что в install.sh
sni="$(grep -oE '"serverNames": *\[ *"[^"]+"' "$C" | sed -E 's/.*"([^"]+)"$/\1/')"
target="$(jget target)"
if [[ -n "$sni" && "$target" == "${sni}:443" ]]; then r PASS "Reality SNI/target" "$sni / $target"; else r FAIL "Reality SNI/target" "sni='$sni' target='$target'"; fi
out="$(timeout 10 openssl s_client -connect "${sni}:443" -servername "$sni" -tls1_3 -groups X25519 -alpn h2 \
  -verify_return_error -verify_hostname "$sni" </dev/null 2>&1)"
if [[ $? -eq 0 ]] && grep -q '^ALPN protocol: h2$' <<<"$out"; then
  r PASS "target TLS с сервера" "TLS1.3+X25519+h2+сертификат"
else
  r FAIL "target TLS с сервера" "$sni не проходит проверку"
fi

# --- DNS и время (после reboot NTP может синхронизироваться не сразу — ждём до ~60с)
if getent hosts "${sni:-www.microsoft.com}" >/dev/null; then r PASS "DNS" "резолвит ${sni:-www.microsoft.com}"; else r FAIL "DNS" "не резолвит ${sni:-www.microsoft.com}"; fi
for _ in $(seq 1 30); do [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" == yes ]] && break; sleep 2; done
chk "NTPSynchronized" "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" yes

# --- ядро
chk "nf_conntrack_max" "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)" 32768

# --- своп по правилу RAM (как в install.sh)
mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
if   (( mem_kb < 2 * 1024 * 1024 )); then want_mb=2048
elif (( mem_kb <= 4 * 1024 * 1024 )); then want_mb=1024
else want_mb=0; fi
sf_bytes="$(swapon --show=NAME,SIZE --bytes --noheadings 2>/dev/null | awk '$1 == "/swapfile" {print $2}')"
other="$(swapon --show=NAME --noheadings 2>/dev/null | grep -vx /swapfile | paste -sd, -)"
if [[ -n "$sf_bytes" ]]; then
  got_mb=$(( (sf_bytes + 1048575) / 1048576 ))   # swapon показывает на страницу меньше файла
  if (( want_mb > 0 && got_mb >= want_mb - 1 && got_mb <= want_mb )); then
    r PASS "своп" "/swapfile ${want_mb}MB при RAM $((mem_kb / 1024))MB"
  else
    r FAIL "своп" "/swapfile ${got_mb}MB, по правилу нужно ${want_mb}MB (RAM $((mem_kb / 1024))MB)"
  fi
elif [[ -n "$other" ]]; then
  r PASS "своп" "свой своп образа ($other) — скрипт его не трогал"
elif (( want_mb == 0 )); then
  r PASS "своп" "не нужен (RAM $((mem_kb / 1024))MB > 4 GiB)"
elif [[ "$(systemd-detect-virt --container 2>/dev/null)" != none ]]; then
  r WARN "своп" "нет — контейнер $(systemd-detect-virt --container), swapon запрещён"
else
  r FAIL "своп" "нет, а по правилу нужно ${want_mb}MB (RAM $((mem_kb / 1024))MB)"
fi

# --- права config.json: группа — из юнита, как в install.sh
xu="$(systemctl show -p User --value xray)"; xg="$(systemctl show -p Group --value xray)"
[[ -n "$xg" ]] || xg="$(id -gn "${xu:-root}" 2>/dev/null)"
chk "config.json права" "$(stat -c '%a %U:%G' "$C" 2>/dev/null)" "640 root:${xg}"

# --- journald
lim="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^SystemMaxUse=' | tail -1)"
chk "journald лимит" "$lim" "SystemMaxUse=100M"

# --- секреты в журнале xray: значения берём из конфига, наружу — только счётчик
pk="$(jget privateKey)"; dc="$(jget decryption)"
if [[ -z "$pk" || -z "$dc" ]]; then
  r FAIL "секреты в журнале" "не нашёл privateKey/decryption в конфиге"
else
  n=$(( $(journalctl -u xray --no-pager -q 2>/dev/null | grep -cF -e "$pk" -e "$dc") ))
  if (( n == 0 )); then r PASS "секреты в журнале" "0 совпадений (journalctl -u xray)"; else r FAIL "секреты в журнале" "$n строк с privateKey/decryption"; fi
fi
REMOTE_EOF
)

run_checks() {
  echo "== ${SERVER_IP}: $1 =="
  # --- снаружи: вход по ключу и отказ в пароле
  if ssh_key true 2>/dev/null; then report PASS "SSH по ключу" "вход OK"
  else report FAIL "SSH по ключу" "не пускает — дальнейшие проверки невозможны"; return; fi
  # Методы, которые сервер предлагает до аутентификации: пароля быть не должно.
  # ssh здесь ОБЯЗАН завершиться отказом (код 255) — под set -e/pipefail это
  # не ошибка скрипта, поэтому `|| true`.
  local methods
  methods="$( { ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o PreferredAuthentications=none -o PubkeyAuthentication=no \
    -p "$SSH_PORT" "root@${SERVER_IP}" true 2>&1 || true; } | sed -nE 's/.*Permission denied \(([^)]*)\).*/\1/p')"
  if [[ -n "$methods" && ! "$methods" =~ password|keyboard-interactive ]]; then
    report PASS "пароль отвергается" "сервер предлагает только: $methods"
  else
    report FAIL "пароль отвергается" "сервер предлагает: ${methods:-<не удалось узнать>}"
  fi
  # --- снаружи: 443 доступен (фильтр хостинга вне nftables закрыл бы его
  # незаметно). WARN, а не FAIL: причина может быть и в сети этой машины.
  if timeout 10 bash -c "exec 3<>/dev/tcp/${SERVER_IP}/443" 2>/dev/null; then
    report PASS "443 снаружи" "TCP-подключение с этой машины проходит"
  else
    report WARN "443 снаружи" "не подключается с этой машины (фильтр хостинга? сеть этой машины?)"
  fi
  # --- локально: права summary (в нём ссылка с ключами)
  if [[ -f "$SUMMARY_FILE" ]]; then
    local m; m="$(stat -c %a "$SUMMARY_FILE")"
    if [[ "$m" == 600 ]]; then report PASS "summary права" "600"; else report FAIL "summary права" "$m, нужно 600"; fi
  else
    report WARN "summary права" "нет $SUMMARY_FILE"
  fi
  # --- на сервере
  local st name detail
  while IFS=$'\t' read -r st name detail; do
    [[ -n "$st" ]] && report "$st" "$name" "$detail"
  done < <(ssh_key 'bash -s' <<<"$REMOTE_CHECKS" 2>/dev/null || echo $'FAIL\tпроверки на сервере\tssh-сессия оборвалась')
}

run_checks "проверка"

if (( REBOOT )); then
  echo
  boot_before="$(ssh_key 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)" || die "не смог прочитать boot_id перед перезагрузкой"
  echo "== перезагружаю ${SERVER_IP} и жду SSH (до 5 мин) =="
  ssh_key 'systemctl reboot' >/dev/null 2>&1 || true
  sleep 15
  up=0
  for _ in $(seq 1 57); do
    boot_now="$(ssh_key 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)" || boot_now=""
    if [[ -n "$boot_now" && "$boot_now" != "$boot_before" ]]; then up=1; break; fi
    sleep 5
  done
  if (( up )); then
    echo
    run_checks "после перезагрузки"
  else
    report FAIL "перезагрузка" "SSH не вернулся за 5 минут"
  fi
fi

echo
if (( FAILS == 0 )); then echo "${C_OK}Итог: все проверки пройдены${C_OFF}"; exit 0; fi
echo "${C_BAD}Итог: FAIL — ${FAILS}${C_OFF}"
exit 1
