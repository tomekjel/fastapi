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
UPDATES_ROUTER_FILE="$ROUTER_DIR/multiguard_updates.py"
SERVICE_PANEL_FILE="$ROUTER_DIR/multiguard_service_panel.py"
SETTINGS_PANEL_FILE="$ROUTER_DIR/multiguard_panel_settings.py"
OWNER_DEVICE_FILE="$ROUTER_DIR/multiguard_panel_devices.py"
THEME_FILE="$ROUTER_DIR/multiguard_panel_theme.py"
TRIAGE_FILE="$ROUTER_DIR/multiguard_panel_triage.py"
DIAGNOSTICS_PANEL_FILE="$ROUTER_DIR/multiguard_panel_diagnostics.py"
SCRIPT_DIR="$APP_ROOT/scripts"
SYNC_SCRIPT_FILE="$SCRIPT_DIR/sync_multiguard_releases.py"
RELEASE_ROOT="$APP_ROOT/releases/multiguard"
GH_CONFIG_DIR="${MULTI_GUARD_GH_CONFIG_DIR:-/root/.config/gh-tomekjel}"
MAIN_FILE="$APP_ROOT/app/main.py"
BACKUP_DIR="$APP_ROOT/backups/multiguard-backend-$(date +%Y%m%d-%H%M%S)"
OPENAPI_TMP="$(mktemp)"
DEPLOY_STARTED=0
HAD_LICENSE=0
HAD_RUNTIME=0
HAD_REMOTE=0
HAD_MESH=0
HAD_UPDATES=0
HAD_SERVICE_PANEL=0
HAD_SETTINGS_PANEL=0
HAD_OWNER_DEVICE_FILE=0
HAD_THEME_FILE=0
HAD_TRIAGE_FILE=0
HAD_DIAGNOSTICS_PANEL=0

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
    if [ "$HAD_UPDATES" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_updates.py" "$UPDATES_ROUTER_FILE"
    else
      rm -f "$UPDATES_ROUTER_FILE"
    fi
    if [ "$HAD_SERVICE_PANEL" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_service_panel.py" "$SERVICE_PANEL_FILE"
    else
      rm -f "$SERVICE_PANEL_FILE"
    fi
    if [ "$HAD_SETTINGS_PANEL" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_panel_settings.py" "$SETTINGS_PANEL_FILE"
    else
      rm -f "$SETTINGS_PANEL_FILE"
    fi
    if [ "$HAD_OWNER_DEVICE_FILE" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_panel_devices.py" "$OWNER_DEVICE_FILE"
    else
      rm -f "$OWNER_DEVICE_FILE"
    fi
    if [ "$HAD_THEME_FILE" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_panel_theme.py" "$THEME_FILE"
    else
      rm -f "$THEME_FILE"
    fi
    if [ "$HAD_TRIAGE_FILE" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_panel_triage.py" "$TRIAGE_FILE"
    else
      rm -f "$TRIAGE_FILE"
    fi
    if [ "$HAD_DIAGNOSTICS_PANEL" -eq 1 ]; then
      cp -a "$BACKUP_DIR/multiguard_panel_diagnostics.py" "$DIAGNOSTICS_PANEL_FILE"
    else
      rm -f "$DIAGNOSTICS_PANEL_FILE"
    fi
    systemctl disable --now multiservis-multiguard-release-sync.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/multiservis-multiguard-release-sync.service
    rm -f /etc/systemd/system/multiservis-multiguard-release-sync.timer
    systemctl daemon-reload || true
    systemctl restart multiservis-api.service || true
  fi
  echo "Backup: $BACKUP_DIR" >&2
  exit "$rc"
}
trap rollback ERR

command -v curl >/dev/null || { echo "Brak curl." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "Brak systemctl." >&2; exit 1; }
command -v gh >/dev/null || { echo "Brak GitHub CLI (gh)." >&2; exit 1; }
test -f "$MAIN_FILE" || { echo "Brak $MAIN_FILE" >&2; exit 1; }

if [ ! -d "$GH_CONFIG_DIR" ] && [ -d /root/.config/gh ]; then
  GH_CONFIG_DIR="/root/.config/gh"
fi
test -d "$GH_CONFIG_DIR" || { echo "Brak konfiguracji GitHub CLI dla prywatnego repo Multi-Guard." >&2; exit 1; }
GH_CONFIG_DIR="$GH_CONFIG_DIR" gh auth status -h github.com >/dev/null

mkdir -p "$ROUTER_DIR" "$SCRIPT_DIR" "$RELEASE_ROOT" "$BACKUP_DIR"
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
if [ -f "$UPDATES_ROUTER_FILE" ]; then
  HAD_UPDATES=1
  cp -a "$UPDATES_ROUTER_FILE" "$BACKUP_DIR/multiguard_updates.py"
fi

if [ -f "$SERVICE_PANEL_FILE" ]; then
  HAD_SERVICE_PANEL=1
  cp -a "$SERVICE_PANEL_FILE" "$BACKUP_DIR/multiguard_service_panel.py"
fi
if [ -f "$SETTINGS_PANEL_FILE" ]; then
  HAD_SETTINGS_PANEL=1
  cp -a "$SETTINGS_PANEL_FILE" "$BACKUP_DIR/multiguard_panel_settings.py"
fi
if [ -f "$OWNER_DEVICE_FILE" ]; then
  HAD_OWNER_DEVICE_FILE=1
  cp -a "$OWNER_DEVICE_FILE" "$BACKUP_DIR/multiguard_panel_devices.py"
fi
if [ -f "$THEME_FILE" ]; then
  HAD_THEME_FILE=1
  cp -a "$THEME_FILE" "$BACKUP_DIR/multiguard_panel_theme.py"
fi
if [ -f "$TRIAGE_FILE" ]; then
  HAD_TRIAGE_FILE=1
  cp -a "$TRIAGE_FILE" "$BACKUP_DIR/multiguard_panel_triage.py"
fi
if [ -f "$DIAGNOSTICS_PANEL_FILE" ]; then
  HAD_DIAGNOSTICS_PANEL=1
  cp -a "$DIAGNOSTICS_PANEL_FILE" "$BACKUP_DIR/multiguard_panel_diagnostics.py"
fi

DEPLOY_STARTED=1

curl -fsSL "$RAW_BASE/app/routers/multiguard_license.py" -o "$LICENSE_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_runtime.py" -o "$RUNTIME_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_remote.py" -o "$REMOTE_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_meshcentral.py" -o "$MESH_ADAPTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_updates.py" -o "$UPDATES_ROUTER_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_service_panel.py" -o "$SERVICE_PANEL_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_panel_settings.py" -o "$SETTINGS_PANEL_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_panel_devices.py" -o "$OWNER_DEVICE_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_panel_theme.py" -o "$THEME_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_panel_triage.py" -o "$TRIAGE_FILE"
curl -fsSL "$RAW_BASE/app/routers/multiguard_panel_diagnostics.py" -o "$DIAGNOSTICS_PANEL_FILE"
curl -fsSL "$RAW_BASE/scripts/sync_multiguard_releases.py" -o "$SYNC_SCRIPT_FILE"
chmod 0644 "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE" "$REMOTE_ROUTER_FILE" "$MESH_ADAPTER_FILE" "$UPDATES_ROUTER_FILE" "$SERVICE_PANEL_FILE" "$SETTINGS_PANEL_FILE" "$OWNER_DEVICE_FILE" "$THEME_FILE" "$TRIAGE_FILE" "$DIAGNOSTICS_PANEL_FILE"
chmod 0755 "$SYNC_SCRIPT_FILE"

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
    "from app.routers import multiguard_updates",
    "from app.routers import multiguard_service_panel",
    "from app.routers import multiguard_panel_settings",
    "from app.routers import multiguard_panel_devices",
    "from app.routers import multiguard_panel_triage",
    "from app.routers import multiguard_panel_diagnostics",
]
include_lines = [
    "app.include_router(multiguard_license.router)",
    "app.include_router(multiguard_runtime.router)",
    "app.include_router(multiguard_remote.router)",
    "app.include_router(multiguard_updates.router)",
    "app.include_router(multiguard_service_panel.router)",
    "app.include_router(multiguard_panel_settings.router)",
    "app.include_router(multiguard_panel_devices.router)",
    "app.include_router(multiguard_panel_triage.router)",
    "app.include_router(multiguard_panel_diagnostics.router)",
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

"$PYTHON" -m py_compile "$LICENSE_ROUTER_FILE" "$RUNTIME_ROUTER_FILE" "$REMOTE_ROUTER_FILE" "$MESH_ADAPTER_FILE" "$UPDATES_ROUTER_FILE" "$SERVICE_PANEL_FILE" "$SETTINGS_PANEL_FILE" "$OWNER_DEVICE_FILE" "$THEME_FILE" "$TRIAGE_FILE" "$DIAGNOSTICS_PANEL_FILE" "$SYNC_SCRIPT_FILE" "$MAIN_FILE"

cat > /etc/systemd/system/multiservis-multiguard-release-sync.service <<EOF
[Unit]
Description=Synchronizacja podpisanych release Multi-Guard
After=network-online.target multiservis-api.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$APP_ROOT
Environment=GH_CONFIG_DIR=$GH_CONFIG_DIR
Environment=MULTI_GUARD_RELEASE_ROOT=$RELEASE_ROOT
ExecStart=$PYTHON $SYNC_SCRIPT_FILE
EOF

cat > /etc/systemd/system/multiservis-multiguard-release-sync.timer <<'EOF'
[Unit]
Description=Okresowa synchronizacja release Multi-Guard

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Persistent=true
Unit=multiservis-multiguard-release-sync.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now multiservis-multiguard-release-sync.timer

systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service

GH_CONFIG_DIR="$GH_CONFIG_DIR" MULTI_GUARD_RELEASE_ROOT="$RELEASE_ROOT" "$PYTHON" "$SYNC_SCRIPT_FILE"

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
    "/multiguard/panel/service",
    "/multiguard/panel/service/{order_id}",
    "/multiguard/panel/telemetry",
    "/multiguard/panel/telemetry/detail",
    "/multiguard/panel/licenses",
    "/multiguard/panel/versions",
    "/multiguard/panel/settings",
    "/multiguard/panel/device/{installation_id}/note",
    "/multiguard/panel/incident/{event_id}",
    "/multiguard/panel/device/{installation_id}/diagnostic-plan",
    "/multiguard/agent/remote/poll",
    "/multiguard/agent/remote/decision",
    "/multiguard/agent/remote/end",
    "/multiguard/remote-sessions",
    "/multiguard/remote-sessions/{session_id}",
    "/multiguard/remote-sessions/{session_id}/connect",
    "/multiguard/remote-sessions/{session_id}/end",
    "/multiguard/remote/mesh-bind",
    "/multiguard/releases/{target}/{arch}/{current_version}",
    "/multiguard/update-assets/{channel}/{version}/{filename}",
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

MANIFEST_TMP="$(mktemp)"
curl -fsS --max-time 20 \
  -H 'X-Multi-Guard-Installation: 00000000-0000-4000-8000-000000000029' \
  https://api.multi-servis.pl/multiguard/releases/windows/x86_64/0.3.29 \
  -o "$MANIFEST_TMP"

"$PYTHON" - "$MANIFEST_TMP" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8-sig") as handle:
    payload = json.load(handle)

version = tuple(int(part) for part in payload["version"].split("."))
if version <= (0, 3, 29):
    raise SystemExit("Backend updatera nie oferuje wersji nowszej niż 0.3.29.")
if not str(payload.get("url") or "").startswith(
    "https://api.multi-servis.pl/multiguard/update-assets/"
):
    raise SystemExit("Release nie jest serwowany przez api.multi-servis.pl.")
if not str(payload.get("signature") or "").strip():
    raise SystemExit("Brak podpisu aktualizacji.")
sha = str(payload.get("sha256") or "")
if len(sha) != 64:
    raise SystemExit("Nieprawidłowy SHA-256 aktualizacji.")
print("OK: 0.3.29 otrzymuje podpisaną aktualizację przez backend.")
PY
rm -f "$MANIFEST_TMP"

trap - ERR
echo "OK: backend Multi-Guard został wdrożony i zweryfikowany."
echo "Źródło: $REPO@$REF"
echo "Backup: $BACKUP_DIR"
