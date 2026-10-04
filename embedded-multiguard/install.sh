#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Uruchom jako root na kontenerze fastapi." >&2
  exit 1
fi

REPO="tomekjel/fastapi"
REF="${MULTISERVIS_BACKEND_REF:-main}"
RAW_BASE="https://raw.githubusercontent.com/$REPO/$REF/embedded-multiguard"
APP_ROOT="/opt/multiservis"
ROUTER_DIR="$APP_ROOT/app/routers"
LICENSE_ROUTER_FILE="$ROUTER_DIR/multiguard_license.py"
RUNTIME_ROUTER_FILE="$ROUTER_DIR/multiguard_runtime.py"
REMOTE_ROUTER_FILE="$ROUTER_DIR/multiguard_remote.py"
MESH_ADAPTER_FILE="$ROUTER_DIR/multiguard_meshcentral.py"
MAIN_FILE="$APP_ROOT/app/main.py"
BACKUP_DIR="$APP_ROOT/backups/multiguard-backend-$(date +%Y%m%d-%H%M%S)"
OPENAPI_TMP="$(mktemp)"
DEPLOY_STARTED=0
HAD_LICENSE=0
HAD_RUNTIME=0
HAD_REMOTE=0
HAD_MESH=0

cleanup() {
  rm -f "$OPENAPI_TMP"
}
trap cleanup EXIT

rollback() {
  local rc=$?
  trap - ERR
  if [ "$DEPLOY_STARTED" -eq 1 ]; then
    echo "BŁĄD: wdrożenie nie przeszło walidacji. Przywracam poprzedni backend..." >&2
    cp -a "$BACKUP_DIR/main.py" "$MAIN_FILE"
    if [ "$HAD_LICENSE" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_license.py" "$LICENSE_ROUTER_FILE"
    else
      rm -f "$LICENSE_ROUTER_FILE"
    fi
    if [ "$HAD_RUNTIME" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_runtime.py" "$RUNTIME_ROUTER_FILE"
    else
      rm -f "$RUNTIME_ROUTER_FILE"
    fi
    if [ "$HAD_REMOTE" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_remote.py" "$REMOTE_ROUTER_FILE"
    else
      rm -f "$REMOTE_ROUTER_FILE"
    fi
    if [ "$HAD_MESH" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_meshcentral.py" "$MESH_ADAPTER_FILE"
    else
      rm -f "$MESH_ADAPTER_FILE"
    fi
    systemctl restart multiservis-api.service || true
  fi
  echo "Backup: $BACKUP_DIR" >&2
  exit "$rc"
}
trap rollback ERR

command -v curl >/dev/null || { echo "Brak curl." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "Brak systemctl." >&2; exit 1; }
test -f "$MAIN_FILE" || { echo "Brak $MAIN_FILE" >&2; exit 1; }

mkdir -p "$ROUTER_DIR" "$BACKUP_DIR"
cp -a "$MAIN_FILE" "$BACKUP_DIR/main.py"

if [ -f "$LICENSE_ROUTER_FILE" ]; then
  HAD_LICENSE=1
  cp -a "$LICENSE_ROUTER_FILE" "$BACKUP_DIR/multiguard_license.py"
fi
if [ -f "$RUNTIME_ROUTER_FILE" ]; then
  HAD_RUNTIME=1
  cp -a "$RUNTIME_ROUTER_FILE" "$BACKUP_DIR/multiguard_runtime.py"
fi
if [ -f "$REMOTE_ROUTER_FILE" ]; then
  HAD_REMOTE=1
  cp -a "$REMOTE_ROUTER_FILE" "$BACKUP_DIR/multiguard_remote.py"
fi
if [ -f "$MESH_ADAPTER_FILE" ]; then
  HAD_MESH=1
  cp -a "$MESH_ADAPTER_FILE" "$BACKUP_DIR/multiguard_meshcentral.py"
fi

DEPLOY_STARTED=1

curl -fsSL "$RAW_BASE/app/routers/multiguard_license.py" -o "$LICENSE_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_runtime.py" -o "$RUNTIME_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_remote.py" -o "$REMOTE_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_meshcentral.py" -o "$MESH_ADAPTER_FILE"
chmod 0644 "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE" "$REMOTE_ROUTER_FILE" "$MESH_ADAPTER_FILE"

PYTHON="$APP_ROOT/.venv/bin/python"
PIP="$APP_ROOT/.venv/bin/pip"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3 || true)"
fi
test -n "$PYTHON" || { echo "Brak interpretera Python." >&2; exit 1; }

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
    "from app.routers import multiguard_remote",
]
include_lines = [
    "app.include_router(multiguard_license.router)",
    "app.include_router(multiguard_runtime.router)",
    "app.include_router(multiguard_remote.router)",
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

"$PYTHON" -m py_compile "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE" "$REMOTE_ROUTER_FILE" "$MESH_ADAPTER_FILE" "$MAIN_FILE"

systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service

HEALTH_OK=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 5 https://api.multi-servis.pl/health >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  sleep 2
done
test "$HEALTH_OK" -eq 1 || { echo "API nie wróciło do stanu health=OK." >&2; exit 1; }

curl -fsS --max-time 15 https://api.multi-servis.pl/openapi.json -o "$OPENAPI_TMP"

"$PYTHON" - "$OPENAPI_TMP" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8-sig") as handle:
    data = json.load(handle)

paths = data.get("paths", {})
required = [
    "/multiguard/licenses/receptions/{reception_id}",
    "/multiguard/licenses/receptions/{reception_id}/generate",
    "/multiguard/licenses/receptions/{reception_id}/release-channel",
    "/v1/multi-guard/discovery/register",
    "/v1/multi-guard/discovery/assignment",
    "/multiguard/pending-installations",
    "/multiguard/pending-installations/{installation_id}/assign",
    "/multiguard/overview",
    "/multiguard/notifications",
    "/multiguard/support-requests",
    "/multiguard/agent/heartbeat",
    "/multiguard/agent/event",
    "/multiguard/events/{event_id}",
    "/multiguard/devices",
    "/multiguard/devices/{installation_id}/events",
    "/multiguard/telemetry",
    "/multiguard/panel/dashboard",
    "/multiguard/panel/telemetry",
    "/multiguard/panel/telemetry/detail",
    "/multiguard/panel/licenses",
    "/multiguard/agent/remote/poll",
    "/multiguard/agent/remote/decision",
    "/multiguard/agent/remote/end",
    "/multiguard/remote-sessions",
    "/multiguard/remote-sessions/{session_id}",
    "/multiguard/remote-sessions/{session_id}/connect",
    "/multiguard/remote-sessions/{session_id}/end",
    "/multiguard/remote/mesh-bind",
]
missing = [item for item in required if item not in paths]
if missing:
    raise SystemExit("Brak tras po wdrożeniu: " + ", ".join(missing))

schema = (
    data.get("components", {})
    .get("schemas", {})
    .get("GenerateLicenseRequest", {})
)
properties = schema.get("properties", {})
if "releaseChannel" not in properties:
    raise SystemExit("GenerateLicenseRequest nie zawiera releaseChannel.")

print("OK: wszystkie wymagane trasy Multi-Guard są widoczne w OpenAPI.")
print("OK: generowanie licencji obsługuje releaseChannel.")
PY

trap - ERR
echo "OK: backend Multi-Guard został wdrożony i zweryfikowany."
echo "Źródło: $REPO@$REF"
echo "Backup: $BACKUP_DIR"
