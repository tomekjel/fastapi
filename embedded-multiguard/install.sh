#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Uruchom jako root na kontenerze fastapi." >&2
  exit 1
fi

export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh-tomekjel}"
REPO="tomekjel/fastapi"
APP_ROOT="/opt/multiservis"
ROUTER_DIR="$APP_ROOT/app/routers"
ROUTER_FILE="$ROUTER_DIR/multiguard_license.py"
MAIN_FILE="$APP_ROOT/app/main.py"
BACKUP_DIR="$APP_ROOT/backups/multiguard-license-$(date +%Y%m%d-%H%M%S)"

command -v gh >/dev/null || { echo "Brak gh." >&2; exit 1; }
gh auth status >/dev/null

test -f "$MAIN_FILE" || { echo "Brak $MAIN_FILE" >&2; exit 1; }
mkdir -p "$ROUTER_DIR" "$BACKUP_DIR"
cp -a "$MAIN_FILE" "$BACKUP_DIR/main.py"
[ ! -f "$ROUTER_FILE" ] || cp -a "$ROUTER_FILE" "$BACKUP_DIR/multiguard_license.py"

gh api "repos/$REPO/contents/embedded-multiguard/app/routers/multiguard_license.py?ref=main"   --jq .content | tr -d '\n' | base64 -d > "$ROUTER_FILE"
chmod 0644 "$ROUTER_FILE"

PYTHON="$APP_ROOT/.venv/bin/python"
PIP="$APP_ROOT/.venv/bin/pip"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3)"
fi
if [ -x "$PIP" ]; then
  "$PIP" install --quiet 'cryptography>=43,<47'
else
  "$PYTHON" -m pip install --quiet 'cryptography>=43,<47'
fi

"$PYTHON" - "$MAIN_FILE" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")

import_line = "from app.routers import multiguard_license"
include_line = "app.include_router(multiguard_license.router)"

if import_line not in source:
    lines = source.splitlines()
    insert_at = 0
    for i, line in enumerate(lines):
        if line.startswith("from app.routers import ") or line.startswith("import app.routers"):
            insert_at = i + 1
    lines.insert(insert_at, import_line)
    source = "\n".join(lines) + "\n"

if include_line not in source:
    marker = '@app.get("/")'
    if marker in source:
        source = source.replace(marker, include_line + "\n\n" + marker, 1)
    else:
        source += "\n" + include_line + "\n"

path.write_text(source, encoding="utf-8")
PY

"$PYTHON" -m py_compile "$ROUTER_FILE" "$MAIN_FILE"

systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
sleep 2

curl -fsS https://api.multi-servis.pl/health >/dev/null
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/multiguard/activation-events"'
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/v1/multi-guard/provision"'

echo "OK: moduł licencji Multi-Guard jest wpięty do Multi-Servis API."
echo "OK: endpoint aktywacji i powiadomień jest widoczny w OpenAPI."
echo "Backup: $BACKUP_DIR"
