#!/usr/bin/env bash
# MASTER 1.5: repair only live app/main.py router import/registration.
# Never replace production OWNER, workshop, license or any database state.
set -Eeuo pipefail
[ "$(id -u)" -eq 0 ] || { echo "ROOT_REQUIRED" >&2; exit 1; }
cd /opt/multiservis
MAIN=/opt/multiservis/app/main.py
PY=/opt/multiservis/.venv/bin/python
ROUTERS=/opt/multiservis/app/routers
test -x "$PY"
test -f "$MAIN"
test -f "$ROUTERS/master15_owner_profile_bridge.py"
test -f "$ROUTERS/multiguard_owner_profile_grant.py"

echo "=== CHECK MODULE IMPORT BEFORE RESTART ==="
"$PY" - <<'PY'
from app.routers import master15_owner_profile_bridge as bridge
assert bridge.router is not None
print("PASS: owner bridge module imports cleanly")
PY

BACKUP="/opt/multiservis/backups/master15-owner-bridge-repair-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$MAIN" "$BACKUP/main.py"
COMMITTED=0
rollback() {
  rc=$?
  trap - ERR
  if [ "$COMMITTED" != 1 ]; then
    cp -a "$BACKUP/main.py" "$MAIN"
    systemctl restart multiservis-api.service || true
    echo "ROLLBACK_DONE backup=$BACKUP" >&2
  fi
  exit "$rc"
}
trap rollback ERR

echo "=== PATCH ROUTER ORDER ==="
"$PY" - "$MAIN" <<'PY'
from pathlib import Path
import sys

p=Path(sys.argv[1])
s=p.read_text(encoding="utf-8")
import_line="from app.routers import master15_owner_profile_bridge"
include_line="app.include_router(master15_owner_profile_bridge.router)"
anchor="app.include_router(multiguard_license.router)"

if s.count(anchor) != 1:
    raise SystemExit("STOP: unexpected main.py layout")
if import_line in s or include_line in s:
    raise SystemExit("STOP: bridge already partially registered")
s=s.replace(anchor,import_line+"\n"+anchor+"\n"+include_line,1)
# The import MUST precede the include; this failed in the prior deployment.
assert s.index(import_line) < s.index(include_line)
compile(s,str(p),"exec")
p.write_text(s,encoding="utf-8")
print("PASS: import precedes include")
PY

echo "=== VALIDATE FULL APP IMPORT WITHOUT RESTART ==="
"$PY" - <<'PY'
from app.main import app
from app.routers import master15_owner_profile_bridge as bridge
# Production may use _IncludedRouter wrappers without .path; inspect
# the same OpenAPI paths served to clients, not raw app.routes.
bridge_paths={r.path for r in bridge.router.routes if hasattr(r,"path")}
published=app.openapi().get("paths",{})
for expected in (
    "/v1/multi-guard/owner-profile-grant",
    "/v1/multi-guard/owner-profile-report",
):
    if expected not in bridge_paths:
        raise SystemExit("MISSING_BRIDGE_ROUTE:"+expected)
    if expected not in published:
        raise SystemExit("MISSING_OPENAPI_ROUTE:"+expected)
print("PASS: both routes published in app.openapi()")
PY

echo "=== RESTART AND VERIFY LOCAL API ==="
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
"$PY" - <<'PY'
import json,time,urllib.request
required=(
    "/v1/multi-guard/owner-profile-grant",
    "/v1/multi-guard/owner-profile-report",
)
for attempt in range(12):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json",timeout=4) as response:
            data=json.load(response)
        assert all(x in data["paths"] for x in required)
        print("PASS: LOCAL_OWNER_ROUTES_HTTP_200")
        break
    except Exception:
        if attempt==11:
            raise
        time.sleep(1)
PY

COMMITTED=1
trap - ERR
echo "DEPLOYED_OWNER_BRIDGE_VERIFIED"
echo "BACKUP=$BACKUP"
echo "NO_LICENSE_MESH_OR_WORKSHOP_CHANGES"
