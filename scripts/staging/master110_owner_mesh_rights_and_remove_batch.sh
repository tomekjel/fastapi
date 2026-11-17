#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh-tomekjel}"
echo '=== OWNER MESH: UPRAWNIENIA + BEZPIECZNE USUNIECIE STAREGO ASUS ==='
/opt/multiservis/.venv/bin/python - <<'PY'
import os,subprocess,sys,json
from pathlib import Path
from app.routers import multiguard_meshcentral as mc
from app.routers.master15_owner_mesh_group_policy import validate_groups,Group
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<=0:raise SystemExit("STOP API_DOWN")
for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in item:
        k,v=item.split(b"=",1)
        if k.startswith(b"MESH_"):
            os.environ[k.decode(errors="replace")]=v.decode(errors="replace")
groups=validate_groups(os.environ)
def query(action):
    cmd=mc._base_command()
    assert cmd.count("DeviceSharing")==1,"BAD_MESH_COMMAND"
    cmd[cmd.index("DeviceSharing")]=action
    return json.loads(mc._run(cmd+["--json"]))
u=query("UserInfo")
data=query("ListDeviceGroups")
meshes=data if isinstance(data,list) else data.get("meshes",[]) if isinstance(data,dict) else []
if isinstance(meshes,dict):
    meshes=[dict(obj,**{"_id":id}) for id,obj in meshes.items() if isinstance(obj,dict)]
uid=u.get("_id") or ""
print("MESH_ACCOUNT",uid if isinstance(uid,str) and uid.startswith("user/") else "[UNKNOWN]")
site=u.get("siteadmin",0)
try:site=int(site)
except (ValueError,TypeError):site=0
print("SITEADMIN_MASK",site)
links=u.get("links") or {}
if not isinstance(links,dict):links={}
gstatus={}
for name,gid in (("KLIENT",groups[Group.CLIENT]),("SERWIS",groups[Group.SERVICE])):
    item=next((m for m in meshes if (m.get("_id") or m.get("id") or m.get("meshid"))==gid),None)
    link=links.get(gid)
    if not isinstance(link,dict) and isinstance(item,dict):
        link=(item.get("links") or {}).get(uid)
    try:rights=int(link.get("rights",0)) if isinstance(link,dict) else 0
    except (TypeError,ValueError):rights=0
    gstatus[name]=bool(rights & 4) or (site & 2)!=0
    print("GROUP",name,"VISIBLE",bool(item),"RIGHTS_MASK",rights,
        "MANAGE_DEVICES",bool(rights & 4),"ADMIN_OVERRIDE",bool(site & 2))
# For now do not guess missing group-level rights, because 'Denied' already
# establishes actual backend rejection.
if not all(gstatus.values()):
    print("STOP MESH_RIGHTS_NOT_CONFIRMED")
    print("ACTION: W MeshCentral nadaj powyzszemu kontu 'Manage Devices' w grupach KLIENT i SERWIS.")
    print("NO CHANGES MADE")
    raise SystemExit(3)
print("PASS GROUP_RIGHTS_PRESENCE")
PY
echo '--- GUARDED OLD ASUS NODE REMOVAL ---'
F="$(mktemp)"
trap 'rm -f "$F"' EXIT
gh api "repos/tomekjel/fastapi/contents/scripts/staging/master110_asus_old_mesh_agent_guarded_remove_diagnostic.sh?ref=96ec59fb0c6d1b4bfbbe2c06ff3a6cf32e82b457" --jq .content | base64 -d > "$F"
bash "$F"
echo '=== END: CHECK OWNER DELETE BUTTON FOR OLD REVOKED ASUS ONLY ==='
