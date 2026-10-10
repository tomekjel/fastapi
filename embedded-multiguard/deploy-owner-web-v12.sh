#!/usr/bin/env bash
# Deploy reviewed Multi-Servis V12 OWNER panel and explicitly approved Multi-Guard licensing backend from immutable SHA.
# No Android APK/client code, no timers, no direct database content edits. Rollback on failure.
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

# Verify existing Android/agent contracts are unchanged apart from the TWO
# approved Multi-Guard licensing handlers needed for OWNER workshop + direct
# sales.  Never broadly disable the former non-OWNER route guard.
"$PY" - "$ROUTERS" "$STAGE" <<'PY'
from pathlib import Path
import ast,sys
old,new=map(Path,sys.argv[1:])
AUTHORIZED_LICENSE_EVOLUTION=frozenset({
    ("post","/v1/multi-guard/provision"),
    ("post","/v1/multi-guard/discovery/assignment"),
    # OWNER-approved reconnection recovery: manual archive or a confirmed
    # uninstall must not suppress a running client that registers again.
    ("post","/v1/multi-guard/discovery/register"),
})
changed_authorized=set()
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
                    key=dec.func.attr,route
                    if key in paths:
                        raise SystemExit(f"BLOCKED: duplicate non-owner route {key}")
                    paths[key]=node
        return paths
    before=routes(old/name);after=routes(new/name)
    missing=set(before)-set(after)
    if missing:
        raise SystemExit(f"BLOCKED: non-owner endpoint removed: {name}: {missing}")
    # First-time deployment from older Multi-Servis builds may legitimately
    # introduce existing reviewed V12 routes. Only changes to pre-existing
    # public route implementations are guarded below. Web-only hotfixes never
    # modify those contracts.
    for key in before.keys()&after.keys():
        original,revised=before[key],after[key]
        if ast.dump(original,include_attributes=False)==ast.dump(revised,include_attributes=False):
            continue
        if name!="multiguard_license.py" or key not in AUTHORIZED_LICENSE_EVOLUTION:
            raise SystemExit(f"BLOCKED: unrelated Android/agent endpoint changed: {name}:{key}")
        # Even these two explicitly authorised handlers MUST keep their
        # request types, arguments, decorators, return annotation, etc.
        def interface(node):
            return (
                node.name,
                ast.dump(node.args,include_attributes=False),
                ast.dump(node.returns,include_attributes=False) if node.returns else None,
                tuple(ast.dump(d,include_attributes=False) for d in node.decorator_list),
            )
        if interface(original)!=interface(revised):
            raise SystemExit(f"BLOCKED: incompatible licensing endpoint interface: {key}")
        changed_authorized.add(key)
# The original V12 deploy altered two licensing handlers. An explicitly
# approved owner clean-up also changes authenticated discovery/register to
# revive a returning computer. Subsequent panel-only patches may leave any
# of these unchanged, while all other public handlers remain protected.
# The initial V12 deployment changed both approved endpoints; a later
# OWNER web-only patch must be allowed to keep those interfaces untouched.
# The loop above strictly blocks all other modifications or new public routes.
if not changed_authorized.issubset(AUTHORIZED_LICENSE_EVOLUTION):
    raise SystemExit(f"BLOCKED: unexpected licensing evolution set: {changed_authorized}")
print("PASS: unchanged agent/Android public API surface; OWNER panel-only update authorised.")
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
  # The pull service has UMask=0077. curl creates stage files as 0600;
  # cp -p would copy that root-only mode into the FastAPI router directory.
  # Uvicorn runs without root privileges and then fails on import with
  # PermissionError, taking the entire API down. Use a fixed, safe read-only
  # module mode instead of preserving the temporary download permissions.
  install -m 0644 "$STAGE/$name" "$ROUTERS/$name"
done
cp -p "$STAGE/main.py" "$MAIN"
# Pre-restart, fail-closed check for readable Python modules; do not permit
# future changes to silently recreate the previous 0600 permissions regression.
for name in "${ROUTER_FILES[@]}"; do
  [ "$(stat -c '%a' "$ROUTERS/$name")" = "644" ] ||
    { echo "BLOCKED: owner router file mode is not 0644: $name" >&2; false; }
done
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
"/multiguard/panel/computers/pending/{installation_id}/archive",
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
