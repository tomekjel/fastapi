#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Uruchom jako root na kontenerze fastapi." >&2
  exit 1
fi

REPO="tomekjel/fastapi"
RAW_BASE="https://raw.githubusercontent.com/$REPO/main/embedded-multiguard"
APP_ROOT="/opt/multiservis"
ROUTER_DIR="$APP_ROOT/app/routers"
LICENSE_ROUTER_FILE="$ROUTER_DIR/multiguard_license.py"
RUNTIME_ROUTER_FILE="$ROUTER_DIR/multiguard_runtime.py"
MAIN_FILE="$APP_ROOT/app/main.py"
BACKUP_DIR="$APP_ROOT/backups/multiguard-license-$(date +%Y%m%d-%H%M%S)"

command -v curl >/dev/null || { echo "Brak curl." >&2; exit 1; }

test -f "$MAIN_FILE" || { echo "Brak $MAIN_FILE" >&2; exit 1; }
mkdir -p "$ROUTER_DIR" "$BACKUP_DIR"
cp -a "$MAIN_FILE" "$BACKUP_DIR/main.py"
[ ! -f "$LICENSE_ROUTER_FILE" ] || cp -a "$LICENSE_ROUTER_FILE" "$BACKUP_DIR/multiguard_license.py"
[ ! -f "$RUNTIME_ROUTER_FILE" ] || cp -a "$RUNTIME_ROUTER_FILE" "$BACKUP_DIR/multiguard_runtime.py"

curl -fsSL "$RAW_BASE/app/routers/multiguard_license.py" -o "$LICENSE_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_runtime.py" -o "$RUNTIME_ROUTER_FILE"
chmod 0644 "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE"

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

import_lines = [
    "from app.routers import multiguard_license",
    "from app.routers import multiguard_runtime",
]
include_lines = [
    "app.include_router(multiguard_license.router)",
    "app.include_router(multiguard_runtime.router)",
]

for import_line in import_lines:
    if import_line not in source:
        lines = source.splitlines()
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith("from app.routers import ") or line.startswith("import app.routers"):
                insert_at = i + 1
        lines.insert(insert_at, import_line)
        source = "\n".join(lines) + "\n"

for include_line in include_lines:
    if include_line not in source:
        marker = '@app.get("/")'
        if marker in source:
            source = source.replace(marker, include_line + "\n\n" + marker, 1)
        else:
            source += "\n" + include_line + "\n"

path.write_text(source, encoding="utf-8")
PY

"$PYTHON" -m py_compile "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE" "$MAIN_FILE"

systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
sleep 2

curl -fsS https://api.multi-servis.pl/health >/dev/null
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/multiguard/activation-events"'
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/v1/multi-guard/provision"'
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/multiguard/agent/event"'
curl -fsS https://api.multi-servis.pl/openapi.json \
  | grep -q '"/multiguard/notifications"'

echo "OK: moduły licencji i integracji Multi-Guard są wpięte do Multi-Servis API."
echo "OK: licencje, zdarzenia agenta i centrum OWNER są widoczne w OpenAPI."
echo "Backup: $BACKUP_DIR"
