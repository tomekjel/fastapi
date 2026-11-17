#!/usr/bin/env bash
# Targeted MG OWNER first-Standard bootstrap. Execute inside LXC 103 as root.
# This does NOT touch Lenovo, SCM, MeshCentral or paid-license rows.
set -Eeuo pipefail
test "$(id -u)" -eq 0 || { echo "STOP ROOT_REQUIRED"; exit 1; }
cd /opt/multiservis
SOURCE=/opt/multiservis/app/routers/master15_owner_profile_bridge.py
PY=/opt/multiservis/.venv/bin/python
SERVICE=multiservis-api.service
IID=cce9ab4a-bf6a-4135-a6bc-f0486e65e0c3
test -f "$SOURCE" && test -x "$PY" || { echo "STOP LIVE_BRIDGE_MISSING"; exit 1; }
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
gh auth status -h github.com >/dev/null 2>&1 || { echo "STOP GH_AUTH_REQUIRED"; exit 1; }
T="$(mktemp)"
BACKUP="/opt/multiservis/backups/master110-lenovo-standard-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$SOURCE" "$BACKUP/master15_owner_profile_bridge.py"
DEPLOYED=0
rollback() {
  ec=$?
  trap - ERR
  if [ "$DEPLOYED" = 1 ]; then
    cp -a "$BACKUP/master15_owner_profile_bridge.py" "$SOURCE"
    systemctl restart "$SERVICE" || true
    echo "ROLLBACK: ORIGINAL_OWNER_BRIDGE_RESTORED"
  fi
  rm -f "$T"
  exit "$ec"
}
trap rollback ERR
gh api "repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_profile_bridge.py?ref=6471bb3b4e36137d84882b228cb157e31dcc0c5a" --jq .content | tr -d '\n' | base64 -d > "$T"
echo "=== PRECHECK OWNER PROFILE CODE ==="
"$PY" - "$SOURCE" "$T" <<'PY'
import ast,sys
from pathlib import Path
before=Path(sys.argv[1]).read_text(encoding="utf-8")
after=Path(sys.argv[2]).read_text(encoding="utf-8")
ast.parse(before)
ast.parse(after)
assert 'def _sync_standard_after_verified_ack(iid: UUID, reservation_id: UUID)' in before, "STOP LIVE_BRIDGE_NOT_AT_VERIFIED_BASE"
assert 'existing_sync = db.execute(text(' not in before, "STOP ALREADY_PATCHED"
assert 'existing_sync = db.execute(text(' in after
assert 'mesh_sync.queue_after_owner_save(db, req.installationId)' in after
assert 'background_tasks.add_task(_sync_standard_after_verified_ack, req.installationId, req.reservationId)' in after
assert before.count('@router.post(')==2 and after.count('@router.post(')==2
assert before.count('def owner_profile_grant(')==1 and after.count('def owner_profile_grant(')==1
print("PASS: CURRENT BRIDGE MATCHES; GRANT BOOTSTRAP PRESENT")
PY
echo "=== READ-ONLY PRECHECK ACTIVE LENOVO ==="
"$PY" - "$IID" <<'PY'
import sys,os,subprocess
from pathlib import Path
from uuid import UUID
from datetime import datetime, timezone, timedelta
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as license
from app.routers import master15_owner_mesh_sync_engine as sync
iid=UUID(sys.argv[1])
pid=subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip()
assert pid.isdecimal() and int(pid)>1, "API_SERVICE_PID_MISSING"
for entry in Path("/proc/"+pid+"/environ").read_bytes().split(b"\x00"):
    if b"=" in entry:
        k,v=entry.split(b"=",1)
        if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
with engine.connect() as db:
    p=db.execute(text("SELECT hostname,status,last_seen_at FROM guard.pending_installations WHERE installation_id=:iid"),{"iid":iid}).mappings().one()
    l=db.execute(text("SELECT lifecycle,plan_code,rebind_pending,valid_until FROM guard.license_links WHERE installation_id=:iid"),{"iid":iid}).mappings().one()
    old=db.execute(text("SELECT requested_group,status FROM guard.owner_mesh_group_sync WHERE installation_id=:iid"),{"iid":iid}).mappings().first()
    assert str(p["hostname"]).upper()=="THINKPAD" and p["status"]=="PROVISIONED","WRONG_ACTIVE_INSTALLATION"
    assert l["lifecycle"]=="ACTIVE" and l["plan_code"]=="multi_guard" and not l["rebind_pending"],"NOT_ACTIVE_STANDARD"
    assert l["valid_until"]>datetime.now(timezone.utc),"LICENSE_EXPIRED"
    assert p["last_seen_at"] is not None and p["last_seen_at"]>datetime.now(timezone.utc)-timedelta(days=1),"LENOVO_NOT_RECENTLY_ONLINE"
    assert license._owner_effective_entitlement_mode(db,iid)=="CLIENT","OWNER_MODE_NOT_CLIENT"
    from app.routers.master15_owner_mesh_group_policy import validate_groups
    validate_groups(os.environ)
    assert old is None or old["requested_group"]=="NONE","EXISTING_NONSTANDARD_SYNC"
    print("PASS: UNIQUE_SELECTED_INSTALLATION; ACTIVE_STANDARD; OWNER_CLIENT")
    print("SYNC_BEFORE:",dict(old) if old else "MISSING")
PY
echo "=== DEPLOY BRIDGE AND CHECK API ==="
install -m 0644 "$T" "$SOURCE"
DEPLOYED=1
"$PY" -m py_compile "$SOURCE"
"$PY" - <<'PY'
from app.main import app
from app.routers import master15_owner_profile_bridge as b
assert "post" in app.openapi()["paths"].get("/v1/multi-guard/owner-profile-grant",{})
assert "post" in app.openapi()["paths"].get("/v1/multi-guard/owner-profile-report",{})
assert b._sync_standard_after_verified_ack.__code__.co_argcount==2
print("PASS: VERIFIED OWNER GRANT AND REPORT ROUTES")
PY
systemctl restart "$SERVICE"
healthy=0
for _ in $(seq 1 30); do
  if systemctl is-active --quiet "$SERVICE" && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null; then healthy=1; break; fi
  sleep 1
done
test "$healthy" = 1 || { echo "STOP API_NOT_HEALTHY"; exit 1; }
echo "PASS: LIVE_API_HEALTHY"
echo "=== BOOTSTRAP MISSING STANDARD OWNER SYNC (NO FALSE ACK) ==="
"$PY" - "$IID" <<'PY'
import os,sys,subprocess
from pathlib import Path
from uuid import UUID
from sqlalchemy import text
from app.database import engine
from app.routers import master15_owner_mesh_sync_engine as sync
iid=UUID(sys.argv[1])
pid=subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip()
for entry in Path("/proc/"+pid+"/environ").read_bytes().split(b"\x00"):
    if b"=" in entry:
        k,v=entry.split(b"=",1)
        if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
with engine.begin() as db:
    p=db.execute(text("SELECT hostname,status FROM guard.pending_installations WHERE installation_id=:iid FOR UPDATE"),{"iid":iid}).mappings().one()
    l=db.execute(text("SELECT lifecycle,plan_code,rebind_pending,valid_until FROM guard.license_links WHERE installation_id=:iid"),{"iid":iid}).mappings().one()
    assert str(p["hostname"]).upper()=="THINKPAD" and p["status"]=="PROVISIONED" and l["lifecycle"]=="ACTIVE" and l["plan_code"]=="multi_guard" and not l["rebind_pending"],"OWNER_STATE_CHANGED_ABORT"
    assert sync._current_owner_target(db,iid)[0]=="NONE", "NOT_STANDARD"
    previous=db.execute(text("SELECT requested_group,status FROM guard.owner_mesh_group_sync WHERE installation_id=:iid FOR UPDATE"),{"iid":iid}).mappings().first()
    if previous is None:
        sync.queue_after_owner_save(db,iid)
        print("PASS: FIRST_STANDARD_SYNC_QUEUED")
    else:
        print("INFO: EXISTING_SYNC_PRESERVED",previous["requested_group"],previous["status"])
with engine.connect() as db:
    label,state,attempts=sync.get_status(db,iid)
    t=db.execute(text("SELECT target_mode,state FROM guard.workshop_profile_transitions WHERE installation_id=:iid"),{"iid":iid}).mappings().first()
    print("OWNER_GROUP:",label,"/",state,"ATTEMPTS:",attempts)
    print("WINDOWS_TRANSITION:",dict(t) if t else "NOT_YET_REPORTED")
    print("WINDOWS_ACK_VALID:",sync._verified_standard_shutdown(db,iid))
print("NO_MESH_MOVE_NO_SCM_NO_LICENCE_RESET")
PY
DEPLOYED=0
rm -f "$T"
trap - ERR
echo "=== PATCH DEPLOYED; WINDOWS VERIFIED ACK STILL REQUIRED FOR OK ==="
echo "BACKUP=$BACKUP"
