#!/bin/bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Uruchom jako root: bash install_lxc.sh"
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="/opt/multiservis"
APP_USER="multiservis"

apt-get update
apt-get install -y python3 python3-venv python3-pip ca-certificates

if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$APP_DIR"
cp -a "$SRC_DIR/app" "$APP_DIR/"
cp "$SRC_DIR/requirements.txt" "$APP_DIR/"
cp "$SRC_DIR/.env" "$APP_DIR/.env"
mkdir -p "$APP_DIR/storage/receptions" "$APP_DIR/storage/calls"

python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 600 "$APP_DIR/.env"

cp "$SRC_DIR/deploy/multiservis-api.service" /etc/systemd/system/multiservis-api.service
systemctl daemon-reload
systemctl enable --now multiservis-api

sleep 2
systemctl --no-pager --full status multiservis-api || true

echo
echo "Gotowe. Test lokalny: curl http://127.0.0.1:8000/health"
