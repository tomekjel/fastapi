#!/usr/bin/env bash
# Deploy ONLY Multi-Servis V12 OWNER browser panel from an immutable commit.
# No Android APK/client code, no agent release/manifests, no timers or KeyGate writes.
# Requires root, source SHA, a compatible running Multi-Servis backend, and PostgreSQL.
set -Eeuo pipefail
test "${EUID}" -eq 0 || { echo "BLOCKED: run as root on FastAPI host" >&2; exit 1; }
: "${MULTISERVIS_OWNER_WEB_REF:?Set approved 40-character commit SHA}"
[[ "$MULTISERVIS_OWNER_WEB_REF" =~ ^[0-9a-f]{40}$ ]] ||
  { echo "BLOCKED: owner panel deployment ref must be full commit SHA" >&2; exit 1; }

ROOT=/opt/multiservis
ROUTERS="$ROOT/app/routers"
MAIN="$ROOT/app/main.py"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] && [ -f "$MAIN" ] || { echo "BLOCKED: expected FastAPI environment missing" >&2; exit 1; }
command -v systemctl >/dev/null && command -v curl >/dev/null ||
 { echo "BLOCKED: systemctl and curl required" >&2; exit 1; }
[ -d "$ROUTERS" ] || { echo "BLOCKED: router directory missing" >&2; exit 1; }
STAGE="$(mktemp -d)"
BACKUP="$ROOT/backups/owner-panel-v12-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p -m 700 "$BACKUP"
CHANGED=0
SAVED_MANIFEST="$BACKUP/existing-file-manifest.txt"
: > "$SAVED_MANIFEST"
ROUTER_FILES=(
  multiguard_license.py
  multiguard_runtime.py
  multiguard_service_panel.py
  multiguard_panel_theme.py
  multiguard_panel_settings.py
  multiguard_panel_devices.py
  multiguard_panel_triage.py
  multiguard_panel_diagnostics.py
)
rollback() {
  local exitcode=$?
  trap - ERR
  if [ "$CHANGED" -eq 1 ]; then
    echo "ROLLBACK owner V12 panel files..."
    while IFS='|' read -r status name; do
      if [ "$status" = "OLD" ]; then
        cp -p "$BACKUP/$name" "$ROUTERS/$name"
      elif [ "$status" = "NEW" ]; then
        rm -f "$ROUTERS/$name"
      fi
    done < "$SAVED_MANIFEST"
    cp -p "$BACKUP/main.py" "$MAIN"
    systemctl restart multiservis-api.service || true
  fi
  echo "Rollback file snapshot retained at: $BACKUP" >&2
  exit "$exitcode"
}
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
trap rollback ERR

cp -p "$MAIN" "$BACKUP/main.py"
for name in "${ROUTER_FILES[@]}"; do
  if [ -f "$ROUTERS/$name" ]; then
    echo "OLD|$name" >> "$SAVED_MANIFEST"
    cp -p "$ROUTERS/$name" "$BACKUP/$name"
  else
    echo "NEW|$name" >> "$SAVED_MANIFEST"
  fi
done

RAW="https://raw.githubusercontent.com/tomekjel/fastapi/${MULTISERVIS_OWNER_WEB_REF}/embedded-multiguard"
for name in "${ROUTER_FILES[@]}"; do
  curl --fail --show-error --silent --location --retry 3 --max-time 25 \
    "$RAW/app/routers/$name" -o "$STAGE/$name"
done
curl --fail --show-error --silent --location --retry 3 --max-time 25 \
  "$RAW/scripts/preflight_owner_panel.py" -o "$STAGE/preflight.py"

# Strictly READ-ONLY DB schema and media mount preflight; no mutation.
cd "$ROOT"
PYTHONPATH="$ROOT" "$PY" "$STAGE/preflight.py"
"$PY" -m py_compile "$STAGE"/*.py

# Verify existing client/Android router contracts are not lost by replacement.
"$PY" - "$ROUTERS" "$STAGE" <<'PY'
from pathlib import Path
import ast,sys
old,new=map(Path,sys.argv[1:])
for name in ("multiguard_license.py","multiguard_runtime.py"):
    def routes(p):
        tree=ast.parse(p.read_text(encoding="utf-8"))
        paths={}
        for node in tree.body:
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec,ast.Call) or not isinstance(dec.func,ast.Attribute):
                    continue
                if dec.func.attr not in ("get","post","put","patch","delete"):
                    continue
                if dec.args and isinstance(dec.args[0],ast.Constant) and isinstance(dec.args[0].value,str):
                    route=dec.args[0].value
                    if "/panel" in route:continue
                    signature=ast.dump(node.args,include_attributes=False)
                    paths[(dec.func.attr,route)]=signature
        return paths
    before=routes(old/name);after=routes(new/name)
    missing=set(before)-set(after)
    changed={k for k in before.keys()&after.keys() if before[k]!=after[k]}
    if missing or changed:
        raise SystemExit(f"BLOCKED: non-owner endpoints changed: {name}: missing={missing}; signatures={changed}")
print("PASS: existing non-panel API endpoints and function signatures preserved")
PY

# Create a PREPARED copy of main before writing anything into the live service.
cp -p "$MAIN" "$STAGE/main.py"
"$PY" - "$STAGE/main.py" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]);source=path.read_text(encoding="utf-8")
modules=(
 "multiguard_license","multiguard_runtime",
 "multiguard_service_panel","multiguard_panel_settings",
 "multiguard_panel_devices","multiguard_panel_triage","multiguard_panel_diagnostics",
)
# Do not rewrite Android routes, dependency injection, auth or existing functions.
for name in modules:
    statement=f"from app.routers import {name}"
    if statement not in source:
        lines=source.splitlines()
        index=next((i+1 for i,line in reversed(list(enumerate(lines)))
                     if line.startswith("from app.routers import ")),None)
        if index is None:
            raise SystemExit("BLOCKED: cannot locate existing router import location")
        lines.insert(index,statement)
        source="\n".join(lines)+"\n"
for name in modules:
    registration=f"app.include_router({name}.router)"
    if registration not in source:
        marker='@app.get("/")'
        if marker not in source:raise SystemExit("BLOCKED: cannot find safe include_router insertion marker")
        source=source.replace(marker,registration+"\n\n"+marker,1)
path.write_text(source,encoding="utf-8")
PY
"$PY" -m py_compile "$STAGE/main.py"

# All validation passed; code-only replace, no release sync and no Android files.
CHANGED=1
for name in "${ROUTER_FILES[@]}"; do
  cp -p "$STAGE/$name" "$ROUTERS/$name"
done
cp -p "$STAGE/main.py" "$MAIN"
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service

ok=0
for attempt in $(seq 1 25); do
  if curl -fsS --max-time 5 https://api.multi-servis.pl/health >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 2
done
[ "$ok" -eq 1 ] || { echo "BLOCKED: health did not recover" >&2; false; }

curl -fsS --max-time 20 https://api.multi-servis.pl/openapi.json -o "$STAGE/openapi.json"
"$PY" - "$STAGE/openapi.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1],encoding="utf-8-sig"));paths=j.get("paths",{})
must_have=[
"/multiguard/panel/dashboard",
"/multiguard/panel/computers",
"/multiguard/panel/service",
"/multiguard/panel/service/{order_id}",
"/multiguard/panel/service/{order_id}/media/{media_id}",
"/multiguard/panel/settings",
"/multiguard/panel/device/{installation_id}/note",
"/multiguard/panel/device/{installation_id}/diagnostic-plan",
"/multiguard/panel/incident/{event_id}",
"/multiguard/agent/heartbeat",
"/multiguard/agent/event",
"/multiguard/releases/{target}/{arch}/{current_version}",
]
missing=[name for name in must_have if name not in paths]
if missing:raise SystemExit("BLOCKED: required routes missing: "+", ".join(missing))
print("PASS: OWNER V12 panel + unchanged Multi-Guard agent/update entrypoints")
PY
CHANGED=0
trap - ERR
echo "SUCCESS: OWNER web V12 deployed from commit ${MULTISERVIS_OWNER_WEB_REF}"
echo "Backup location: $BACKUP"
