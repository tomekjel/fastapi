#!/usr/bin/env bash
# MASTER 1.5: Register already deployed, audited OWNER profile grant/report routes.
# Does not alter Windows, MeshCentral, licensing rows, or grant any token.
set -Eeuo pipefail
cd /opt/multiservis
MAIN=/opt/multiservis/app/main.py
PY=/opt/multiservis/.venv/bin/python
SERVICE=multiservis-api.service
MARKER=MG15_OWNER_PROFILE_ROUTES_V1
test -x "$PY" && test -f "$MAIN"
test "$(id -u)" -eq 0
BACKUP="/opt/multiservis/backups/master15-owner-profile-routes-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$MAIN" "$BACKUP/main.py"
rollback(){
  rc=$?
  trap - ERR
  cp -a "$BACKUP/main.py" "$MAIN"
  systemctl restart "$SERVICE" || true
  echo "ROLLBACK: restored original main.py; backup at $BACKUP" >&2
  exit "$rc"
}
trap rollback ERR
echo "=== MASTER 1.5 / SAFE OWNER PROFILE ROUTE ACTIVATION ==="
"$PY" - "$MAIN" <<'PY'
from pathlib import Path
import ast,sys
from app.routers import master15_owner_profile_bridge as bridge
from app.routers import multiguard_owner_profile_grant as codec
from app.routers import multiguard_workshop_remote as workshop
from app.routers import multiguard_license as licence
path=Path(sys.argv[1])
source=path.read_text(encoding="utf8")
if "MG15_OWNER_PROFILE_ROUTES_V1" in source:
    raise SystemExit("STOP: already installed")
appnodes=ast.parse(source,filename=str(path))
# Ensure no alternate ASGI app is shadowed at end, and append only after app.
if not any(isinstance(node,(ast.Assign,ast.AnnAssign)) and
           any(getattr(x,"id",None)=="app" for x in
              (node.targets if isinstance(node,ast.Assign) else [node.target]))
           for node in appnodes.body):
    raise SystemExit("STOP: no top-level app assignment in production main.py")
assert callable(codec.create_profile_transition_grant)
assert callable(licence._owner_effective_entitlement_mode)
assert callable(licence._signing_key)
assert callable(workshop._service_transition_sessions)
paths={r.path for r in bridge.router.routes}
if paths!={"/v1/multi-guard/owner-profile-grant","/v1/multi-guard/owner-profile-report"}:
    raise SystemExit("STOP: unexpected bridge route set "+repr(paths))
# Confirm the production app does not already expose either route.
from app.main import app
existing=app.openapi()["paths"]
if any(p in existing for p in paths):
    raise SystemExit("STOP: profile endpoint already registered")
extension='\n# MG15_OWNER_PROFILE_ROUTES_V1: signed OWNER SCM grants and reports.\n'
extension+='from app.routers import master15_owner_profile_bridge as _mg15_owner_profile_bridge\n'
extension+='app.include_router(_mg15_owner_profile_bridge.router)\n'
new=source+extension
compile(new,str(path),"exec")
path.write_text(new,encoding="utf8")
print("PASS: exactly two existing signed OWNER profile routes enabled")
PY

"$PY" -m py_compile "$MAIN"
echo "=== VERIFY APP IMPORT AND EXACT ROUTES ==="
"$PY" - <<'PY'
from app.main import app
paths=app.openapi()["paths"]
expected=("/v1/multi-guard/owner-profile-grant",
          "/v1/multi-guard/owner-profile-report")
for path in expected:
    assert "post" in paths.get(path,{}),f"POST missing: {path}"
    print("PASS: POST",path)
PY

echo "=== RESTART AND CHECK REAL HTTP ==="
systemctl restart "$SERVICE"
READY=0
for i in $(seq 1 40); do
  if systemctl is-active --quiet "$SERVICE" &&
     curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null; then
    READY=1; break
  fi
  sleep 1
done
test "$READY" -eq 1
"$PY" - <<'PY'
import json,urllib.request
with urllib.request.urlopen("http://127.0.0.1:8000/openapi.json",timeout=5) as response:
    paths=json.load(response)["paths"]
for path in ("/v1/multi-guard/owner-profile-grant",
             "/v1/multi-guard/owner-profile-report"):
    assert "post" in paths.get(path,{}), "MISSING LIVE POST "+path
print("PASS: live OWNER broker endpoints HTTP 200 OpenAPI")
PY
trap - ERR
echo "OWNER_PROFILE_ROUTES_DEPLOYED_PASS"
echo "BACKUP=$BACKUP"
echo "NO_MESH_OR_WINDOWS_CHANGE_PERFORMED"
