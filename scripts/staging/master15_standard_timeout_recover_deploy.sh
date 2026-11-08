#!/usr/bin/env bash
set -Eeuo pipefail
test "$(id -u)" -eq 0
cd /opt/multiservis
export PYTHONPATH=/opt/multiservis
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
PY=/opt/multiservis/.venv/bin/python
R=/opt/multiservis/app/routers/master15_owner_mesh_sync_engine.py
TMP=$(mktemp)
BACKUP="/opt/multiservis/backups/master15-standard-timeout-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$R" "$BACKUP/original.py"
rollback(){
  ec=$?
  trap - ERR
  if test -f "$BACKUP/installed";then
    cp -a "$BACKUP/original.py" "$R"
    systemctl restart multiservis-api.service || true
    echo "ROLLBACK_PREVIOUS_ENGINE_RESTORED" >&2
  fi
  rm -f "$TMP"
  exit "$ec"
}
trap rollback ERR
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_sync_engine.py --jq .content | base64 -d > "$TMP"
"$PY" -m py_compile "$TMP"
grep -q "WINDOWS_CONFIRMATION_TIMEOUT" "$TMP"
grep -q "retry_delays=(10.0,20.0)" "$TMP"
install -m 0644 "$TMP" "$R"
touch "$BACKUP/installed"
systemctl restart multiservis-api.service
healthy=0
for i in $(seq 1 30);do
  if systemctl is-active --quiet multiservis-api.service && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null;then
    healthy=1
    break
  fi
  sleep 1
done
test "$healthy" = 1
"$PY" - <<'PY'
import os,subprocess,time
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers import multiguard_license as license
from app.routers.master15_owner_mesh_group_policy import Group,validate_groups
print("=== MASTER15 ASUS STANDARD CURRENT OPERATION / RECOVERY ===")
pid=int(subprocess.check_output(["systemctl","show","--property=MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<2:raise SystemExit("API_NOT_RUNNING")
for entry in Path(f"/proc/{pid}/environ").read_bytes().split(b"\x00"):
 if b"=" in entry:
  k,v=entry.split(b"=",1)
  if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
groups=validate_groups(os.environ)
with engine.connect() as db:
 rows=db.execute(text("""
  SELECT p.installation_id,p.hostname,s.revision,s.status,s.attempts,s.requested_group,
         s.target_mesh_id,s.requested_at,s.last_error,
         t.state AS receipt,t.target_mode,t.created_at AS receipt_created_at
  FROM guard.pending_installations p
  JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
  LEFT JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
  WHERE upper(p.hostname)='ROG'
 """)).mappings().all()
 if len(rows)!=1:raise SystemExit("STOP_ROG_NOT_UNIQUE")
 r=rows[0]; iid=r["installation_id"]
 desired,target=sync._current_owner_target(db,iid)
 if desired!="NONE" or r["requested_group"]!="NONE" or target!=groups[Group.STANDARD] or r["target_mesh_id"]!=target:
  raise SystemExit("STOP_OWNER_NOT_STANDARD")
 valid=sync._verified_standard_shutdown(db,iid)
 print("ASUS_OWNER_STANDARD:YES")
 print("SIGNED_WINDOWS_STANDARD_RECEIPT_VALID:",valid)
 print("RESERVATION_STATE:",r["receipt"],"TARGET:",r["target_mode"])
 print("SYNC_PREVIOUS:",r["status"],"ATTEMPTS:",r["attempts"])
 status=r["status"]
 age=db.execute(text("SELECT EXTRACT(EPOCH FROM now()-requested_at) FROM guard.owner_mesh_group_sync WHERE installation_id=:iid"),{"iid":iid}).scalar_one()
 print("SECONDS_SINCE_REQUEST:",int(age))
if valid and status in ("WAITING","RETRY"):
 # The signed ack was already completed; recover this revision once without
 # requiring the user to touch OWNER. Never override an unverified transition.
 with engine.begin() as db:
  db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE installation_id=:iid FOR UPDATE"),{"iid":iid}).one()
  now=db.execute(text("SELECT revision,status,requested_group,target_mesh_id FROM guard.owner_mesh_group_sync WHERE installation_id=:iid FOR UPDATE"),{"iid":iid}).mappings().one()
  if now["revision"]!=r["revision"] or now["requested_group"]!="NONE" or now["target_mesh_id"]!=target:
   raise SystemExit("STOP_CONCURRENT_OWNER_CHANGE")
  if now["status"]=="RETRY":
   db.execute(text("""UPDATE guard.owner_mesh_group_sync SET status='WAITING',attempts=0,last_error=NULL,
    revision=revision+1,updated_at=now() WHERE installation_id=:iid AND status='RETRY'"""),{"iid":iid})
 print("SIGNED_ACK_RECOVERY_SYNC_RUNNING")
 result=sync.run_pending_installation(engine,iid,max_attempts=3)
 print("RECOVERY_RESULT:",result)
elif status=="WAITING" and age>=60 and not valid:
 with engine.begin() as db:
  db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE installation_id=:iid FOR UPDATE"),{"iid":iid}).one()
  update=db.execute(text("""UPDATE guard.owner_mesh_group_sync
    SET status='RETRY',last_error='WINDOWS_CONFIRMATION_TIMEOUT',updated_at=now()
    WHERE installation_id=:iid AND revision=:rev AND status='WAITING' AND requested_at<=now()-interval '60 seconds'
  """),{"iid":iid,"rev":r["revision"]})
 print("TIMED_OUT_WAITING_RECOVERED:",update.rowcount==1)
elif status=="OK":
 print("ALREADY_CONFIRMED_NO_ACTION")
else:
 print("NO_UNVERIFIED_MESH_ACTION")
with engine.connect() as db:
 label,display,attempts=sync.get_status(db,iid)
 print("OWNER_GROUP_STATUS:",label,"/",display,"ATTEMPTS:",attempts)
 after=db.execute(text("SELECT status,last_error FROM guard.owner_mesh_group_sync WHERE installation_id=:iid"),{"iid":iid}).mappings().one()
 print("LAST_SYNC_ERROR_CATEGORY:",after["last_error"] or "NONE")
print("MASTER15_TIMEOUT_AND_ASUS_RECOVERY_COMPLETE")
PY
rm -f "$TMP"
trap - ERR
echo "MASTER15_STANDARD_TIMEOUT_FIX_DEPLOY_PASS"
echo "BACKUP=$BACKUP"
