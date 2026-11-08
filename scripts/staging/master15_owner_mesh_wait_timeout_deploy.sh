#!/usr/bin/env bash
set -Eeuo pipefail
test "$(id -u)" -eq 0
cd /opt/multiservis
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
export PYTHONPATH=/opt/multiservis
PY=/opt/multiservis/.venv/bin/python
R=/opt/multiservis/app/routers/master15_owner_mesh_sync_engine.py
UNIT=multiservis-api.service
BK="/opt/multiservis/backups/master15-owner-mesh-timeout-$(date -u +%Y%m%d-%H%M%S)"
TMP=$(mktemp)
mkdir -p "$BK"
cp -a "$R" "$BK/original.py"
done_install=0
cleanup(){
  rc=$?
  trap - ERR
  rm -f "$TMP"
  if test "$done_install" -eq 1;then
    cp -a "$BK/original.py" "$R"
    systemctl restart "$UNIT" || true
    echo "ROLLBACK: previous OWNER Mesh engine restored" >&2
  fi
  exit "$rc"
}
trap cleanup ERR
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_sync_engine.py --jq .content | base64 -d > "$TMP"
"$PY" -m py_compile "$TMP"
"$PY" - "$TMP" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
for marker in (
 'deadline=time.monotonic()+60.0',
 "retry_delays=(10.0,20.0)",
 "WINDOWS_CONFIRMATION_TIMEOUT",
 "status='RETRY',last_error='WINDOWS_CONFIRMATION_TIMEOUT'",
 'if _verified_standard_shutdown(db,iid):',
):
 assert marker in s, "MISSING_TIMING_OR_TIMEOUT_GUARD"
print("PASS: 60s acknowledgement timeout, 10/20s Mesh delays and no endless WAITING")
PY
install -m 0644 "$TMP" "$R"
done_install=1
systemctl restart "$UNIT"
ready=0
for i in $(seq 1 30);do
 if systemctl is-active --quiet "$UNIT" && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null;then ready=1;break;fi
 sleep 1
done
test "$ready" -eq 1
"$PY" - <<'PY'
import os
import subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import validate_groups
from app.routers import multiguard_license as lic
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<2:raise SystemExit("STOP_API_NOT_RUNNING")
for e in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
 if b"=" in e:
  k,v=e.split(b"=",1)
  if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
validate_groups(os.environ)
with engine.connect() as db:
 rows=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).all()
 if len(rows)!=1:raise SystemExit("STOP_ASUS_NOT_UNIQUE")
 iid=rows[0][0]
 group,status,attempts=sync.get_status(db,iid)
 print("ASUS_CURRENT_OWNER_GROUP:",group,"/",status,"ATTEMPTS:",attempts)
 print("ASUS_OWNER_MODE:",lic._owner_effective_entitlement_mode(db,iid))
print("PASS: live FastAPI imports timeout-safe OWNER worker; no group move or licence mutation")
PY
done_install=0
trap - ERR
rm -f "$TMP"
echo "MASTER15_OWNER_MESH_TIMEOUT_DEPLOY_PASS"
echo "BACKUP=$BK"
