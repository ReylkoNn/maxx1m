#!/usr/bin/env bash
# =============================================================================
# Max1m — Turnkey 1-Command Installer for Russian VPS (Ubuntu / Debian, No VPN)
#
# Usage:
#   sudo ./bootstrap_vps.sh --domain chat.company.ru [--turn-domain turn.company.ru] [--invites 5] [--title "Офис"]
#
# If you have a second domain/IP dedicated to TURN on TCP/TLS 443, pass
# `--turn-domain turn.company.ru --turn-tls-443` so WebRTC media traverses even
# strict corporate firewalls that allow ONLY outbound TCP 443!
# On a single-IP VPS, Caddy uses TCP 443 for HTTPS/WSS and coturn uses 3478 + TLS 5349.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DOMAIN=""
TURN_DOMAIN=""
TURN_TLS_PORT="5349"
INVITE_COUNT=5
NODE_TITLE=""
FORCE_RELAY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)        DOMAIN="$2"; shift 2 ;;
    --turn-domain)   TURN_DOMAIN="$2"; shift 2 ;;
    --turn-tls-443)  TURN_TLS_PORT="443"; shift 1 ;;
    --invites)       INVITE_COUNT="$2"; shift 2 ;;
    --title)         NODE_TITLE="$2"; shift 2 ;;
    --force-relay)   FORCE_RELAY="true"; shift 1 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Ошибка: укажите домен сервера: sudo ./bootstrap_vps.sh --domain chat.company.ru" >&2
  exit 1
fi

if [[ -z "$TURN_DOMAIN" ]]; then
  TURN_DOMAIN="$DOMAIN"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[1/5] Устанавливаем Docker Engine и Docker Compose..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg python3 openssl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
  apt-get install -y -qq docker.io docker-compose-v2 || apt-get install -y -qq docker.io docker-compose-plugin
  systemctl enable --now docker
fi

VPS_IP="$(curl -4 -fsSL --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"

echo "[2/5] Генерируем криптостойкие 256-битные ключи (.env и turnserver.conf)..."
if [[ -f .env ]]; then
  source .env
fi

SECRET_KEY="${SECRET_KEY:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
TURN_SHARED_SECRET="${TURN_SHARED_SECRET:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"

CALL_STUN_URLS="stun:${TURN_DOMAIN}:3478"
CALL_TURN_URLS="turn:${TURN_DOMAIN}:3478?transport=udp,turn:${TURN_DOMAIN}:3478?transport=tcp,turns:${TURN_DOMAIN}:${TURN_TLS_PORT}?transport=tcp"

umask 077
cat > .env <<EOF
MAX1M_DOMAIN=${DOMAIN}
SECRET_KEY=${SECRET_KEY}
TURN_SHARED_SECRET=${TURN_SHARED_SECRET}
CALL_STUN_URLS=${CALL_STUN_URLS}
CALL_TURN_URLS=${CALL_TURN_URLS}
CALL_FORCE_RELAY_RECOMMENDED=${FORCE_RELAY}
EOF
chmod 600 .env

CADDY_CERT_SUBPATH="/caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${TURN_DOMAIN}/${TURN_DOMAIN}"
TURN_CERT_LINE="# cert=${CADDY_CERT_SUBPATH}.crt"
TURN_PKEY_LINE="# pkey=${CADDY_CERT_SUBPATH}.key"

sed \
  -e "s|\${TURN_TLS_PORT}|${TURN_TLS_PORT}|g" \
  -e "s|\${TURN_SHARED_SECRET}|${TURN_SHARED_SECRET}|g" \
  -e "s|\${TURN_REALM}|${TURN_DOMAIN}|g" \
  -e "s|\${VPS_PUBLIC_IP}|${VPS_IP}|g" \
  -e "s|\${TURN_CERT_LINE}|${TURN_CERT_LINE}|g" \
  -e "s|\${TURN_PKEY_LINE}|${TURN_PKEY_LINE}|g" \
  turnserver.conf.template > turnserver.conf
chmod 600 turnserver.conf

echo "[3/5] Собираем и запускаем контейнеры Max1m (Backend + Caddy TLS 1.3 + coturn)..."
docker compose up -d --build

echo "[4/5] Ожидаем выпуск TLS-сертификата для https://${DOMAIN} ..."
SPKI_PIN=""
for attempt in $(seq 1 24); do
  if SPKI_PIN="$(python3 -c "import generate_join_link as g; print(g.probe_live_spki_pin('https://${DOMAIN}'))" 2>/dev/null)"; then
    if [[ -n "$SPKI_PIN" ]]; then
      break
    fi
  fi
  sleep 3
done

# Enable coturn TLS certificate if Caddy issued it on the shared volume
if docker compose exec -T coturn test -f "${CADDY_CERT_SUBPATH}.crt" 2>/dev/null; then
  sed -i \
    -e "s|^# cert=|cert=|g" \
    -e "s|^# pkey=|pkey=|g" \
    turnserver.conf
  docker compose restart coturn >/dev/null 2>&1 || true
fi

echo "[5/5] Выпускаем одноразовые инвайт-коды (${INVITE_COUNT} шт.) и строки max1m-join:// ..."
echo ""
echo "========================================================================="
echo " УЗЕЛ MAX1M УСПЕШНО ЗАПУЩЕН: https://${DOMAIN}"
if [[ -n "$SPKI_PIN" ]]; then
  echo " TLS SPKI Pin: ${SPKI_PIN}"
fi
echo "========================================================================="

for idx in $(seq 1 "$INVITE_COUNT"); do
  RAW_OUT="$(docker compose exec -T backend python create_invite.py 2>/dev/null || true)"
  INV_CODE="$(printf '%s\n' "$RAW_OUT" | grep -Eo 'MAX1M-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' | head -n1 || true)"
  if [[ -n "$INV_CODE" && -n "$SPKI_PIN" ]]; then
    JOIN_STR="$(python3 generate_join_link.py --server "https://${DOMAIN}" --pin "$SPKI_PIN" --invite "$INV_CODE" --title "$NODE_TITLE")"
    echo ""
    echo " Сотрудник #${idx} (инвайт ${INV_CODE}):"
    echo "   ${JOIN_STR}"
  elif [[ -n "$INV_CODE" ]]; then
    echo " Сотрудник #${idx} — Инвайт: ${INV_CODE} (сертификат ещё выпускается; повторите generate_join_link.py через минуту)"
  fi
done

echo ""
echo "Передайте каждому коллеге его персональную строку max1m-join:// —"
echo "она в 1 клик настроит сервер, закрепит TLS SPKI Pin и подставит инвайт!"
echo "========================================================================="
