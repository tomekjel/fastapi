#!/usr/bin/env bash
set -Eeuo pipefail
test "$(id -u)" = 0
cd /opt/multiservis
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
R=/opt/multiservis/app/routers
PY=/opt/multiservis/.venv/bin/python
UNIT=multiservis-api.service
DROP=/etc/systemd/system/multiservis-api.service.d/70-mg15-standard.conf
BK="/opt/multiservis/backups/mg15-standard-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK" "$(dirname "$DROP")"
FILES="master15_owner_mesh_group_policy.py master15_owner_mesh_sync_engine.py master15_owner_profile_bridge.py"
for f in $FILES;do test -f "$R/$f"; cp -a "$R/$f" "$BK/$f";done
if test -f "$DROP";then cp -a "$DROP" "$BK/dropin.conf";else touch "$BK/no-dropin";fi
rollback(){
 rc=$?;trap - ERR
 for f in $FILES;do cp -a "$BK/$f" "$R/$f";done
 if test -f "$BK/no-dropin";then rm -f "$DROP";else cp -a "$BK/dropin.conf" "$DROP";fi
 systemctl daemon-reload; systemctl restart "$UNIT" || true
 echo "ROLLBACK_DONE BACKUP=$BK" >&2;exit "$rc"
}
trap rollback ERR
echo "=== DISCOVER VERIFIED STANDARD MESH GROUP ==="
STDID="$("$PY" - <<'PY'
import os,subprocess,json,re
from app.routers import multiguard_meshcentral as mesh
pid=subprocess.check_output(["systemctl","show","multiservis-api.service","-p","MainPID","--value"],text=True).strip()
if not pid.isdigit() or int(pid)<2:raise SystemExit("BAD_FASTAPI_PID")
for b in open("/proc/"+pid+"/environ","rb").read().split(b"\x00"):
 if b"=" in b:
  k,v=b.split(b"=",1)
  if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
cmd=mesh._base_command()
assert cmd.count("DeviceSharing")==1
cmd[cmd.index("DeviceSharing")]="ListDeviceGroups"
data=json.loads(mesh._run(cmd+["--json"]))
if not isinstance(data,list):raise SystemExit("BAD_GROUPS_JSON")
matches=[x for x in data if isinstance(x,dict) and x.get("name",x.get("meshname",x.get("groupname")))=="MultiGuard STANDARD – Bez zdalnego dostępu"]
if len(matches)!=1:raise SystemExit("GROUP_MISSING_OR_DUPLICATE")
id=matches[0].get("_id") or matches[0].get("meshid")
if not isinstance(id,str) or not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$._-]{32,128}",id):raise SystemExit("BAD_GROUP_ID")
if id in (os.environ.get("MESH_CENTRAL_SESSION_CONSENT_MESH_ID"),os.environ.get("MESH_SERVICE_PRO_GROUP_ID")):raise SystemExit("GROUP_CONFLICT")
print(id)
PY
)"
test -n "$STDID"
echo "PASS: distinct STANDARD group resolved"
echo "=== INSTALL CODE ==="
for f in $FILES;do
 temp=$(mktemp)
 gh api "repos/tomekjel/fastapi/contents/scripts/staging/$f" --jq .content | tr -d '\n' | base64 -d > "$temp"
 install -m 0644 "$temp" "$R/$f"
 rm -f "$temp"
 "$PY" -m py_compile "$R/$f"
done
printf '[Service]\nEnvironment="MESH_STANDARD_GROUP_ID=%s"\n' "$STDID" > "$DROP"
chmod 0644 "$DROP"
systemctl daemon-reload
echo "=== VALIDATE APP IMPORT AND ROUTES ==="
"$PY" - <<'PY'
from app.main import app
from app.routers.master15_owner_mesh_group_policy import resolve_edition,Group
assert resolve_edition("CLIENT","multi_guard")==Group.STANDARD
for p in ("/v1/multi-guard/owner-profile-grant","/v1/multi-guard/owner-profile-report"):
 assert "post" in app.openapi()["paths"].get(p,{})
print("PASS: Standard policy and OWNER routes")
PY
systemctl restart "$UNIT"
ready=0
for i in $(seq 1 30);do
 if systemctl is-active --quiet "$UNIT" && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json;then ready=1;break;fi
 sleep 1
done
test "$ready" = 1
"$PY" - <<'PY'
import os,subprocess
from sqlalchemy import text
from app.database import engine
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import validate_groups
pid=subprocess.check_output(["systemctl","show","multiservis-api.service","-p","MainPID","--value"],text=True).strip()
for b in open("/proc/"+pid+"/environ","rb").read().split(b"\0"):
 if b"=" in b:
  k,v=b.split(b"=",1)
  if k.startswith(b"MESH_"):os.environ[k.decode()]=v.decode()
assert len(validate_groups(os.environ))==3
with engine.begin() as db:
 ids=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).scalars().all()
 if len(ids)!=1:raise SystemExit("ROG_AMBIGUOUS")
 iid=ids[0]
 group,target=sync._current_owner_target(db,iid)
 if group!="NONE" or target!=os.environ["MESH_STANDARD_GROUP_ID"]:raise SystemExit("ROG_NOT_STANDARD")
 sync.queue_after_owner_save(db,iid)
with engine.connect() as db:
 label,status,_=sync.get_status(db,iid)
 assert label=="Standard"
 print("PASS: 3 group config; OWNER",label,status)
print("NO_MESH_MOVE_BEFORE_VERIFIED_WINDOWS_ACK")
PY
trap - ERR
echo "MASTER15_STANDARD_GROUP_DEPLOY_PASS"
echo "BACKUP=$BK"
