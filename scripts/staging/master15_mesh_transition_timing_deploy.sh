#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
test "$(id -u)" -eq 0
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
R=/opt/multiservis/app/routers/master15_owner_mesh_sync_engine.py
PY=/opt/multiservis/.venv/bin/python
BK="/opt/multiservis/backups/master15-mesh-timing-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
test -f "$R"
cp -a "$R" "$BK/original.py"
TMP=$(mktemp)
rollback(){
 rc=$?
 trap - ERR
 if test -f "$BK/installed";then
   cp -a "$BK/original.py" "$R"
   systemctl restart multiservis-api.service || true
   echo "ROLLBACK_PREVIOUS_ENGINE_RESTORED" >&2
 fi
 rm -f "$TMP"
 exit "$rc"
}
trap rollback ERR
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_sync_engine.py --jq .content | base64 -d > "$TMP"
"$PY" -m py_compile "$TMP"
"$PY" - "$TMP" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
assert "deadline=time.monotonic()+60.0" in s
assert "retry_delays=(10.0,20.0)" in s
assert "AWAITING_SIGNED_WINDOWS_ACK" in s
assert 'status={"WAITING":"Przełączanie…","MOVING":"Przełączanie…","OK":"OK","RETRY":"Ponów"}' in s
print("PASS_TIMING_SOURCE_CHECK")
PY
install -m 0644 "$TMP" "$R"
touch "$BK/installed"
"$PY" -m py_compile "$R"
systemctl restart multiservis-api.service
ready=0
for i in $(seq 1 25);do
 if systemctl is-active --quiet multiservis-api.service && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json;then ready=1;break;fi
 sleep 1
done
test "$ready" -eq 1
"$PY" - <<'PY'
from app.routers import master15_owner_mesh_sync_engine as sync
from app.database import engine
from sqlalchemy import text
import inspect
src=inspect.getsource(sync.run_pending_installation)
assert "60.0" in src and "retry_delays" in src
with engine.connect() as db:
 rows=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).all()
 assert len(rows)==1
 label,status,_=sync.get_status(db,rows[0][0])
 print("ROG_OWNER_STATUS:",label,"/",status)
print("PASS: backend imports updated worker and OWNER status")
PY
rm -f "$TMP"
trap - ERR
echo "MASTER15_MESH_TRANSITION_TIMING_DEPLOY_PASS"
echo "BACKUP=$BK"
