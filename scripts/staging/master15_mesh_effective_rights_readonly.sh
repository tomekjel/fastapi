#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json,os,subprocess
from pathlib import Path
from app.routers import multiguard_meshcentral as mc
from app.routers.master15_owner_mesh_group_policy import validate_groups,Group

pid=int(subprocess.check_output(
    ["systemctl","show","-p","MainPID","--value","multiservis-api.service"],
    text=True).strip())
if pid<=0: raise SystemExit("STOP: API inactive")
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")
groups=validate_groups(os.environ)
def query(action):
    cmd=mc._base_command()
    if cmd.count("DeviceSharing")!=1:raise RuntimeError("Invalid Mesh command")
    cmd[cmd.index("DeviceSharing")]=action
    return json.loads(mc._run(cmd+["--json"]))
user=query("UserInfo")
raw=query("ListDeviceGroups")
meshes=raw if isinstance(raw,list) else (
    raw.get("meshes",[]) if isinstance(raw,dict) else [])
if isinstance(meshes,dict):
    meshes=[dict(x,**{"_id":k}) for k,x in meshes.items() if isinstance(x,dict)]
uid=str(user.get("_id") or "")
if not uid.startswith("user/"):raise SystemExit("STOP: unexpected Mesh user id")
links=user.get("links") or {}
print("=== EFFECTIVE MESH GROUP RIGHTS READONLY ===")
print("USER_SITEADMIN:",user.get("siteadmin"))
print("USER_GROUP_LINK_COUNT:",sum(str(k).startswith("mesh/") for k in links))
for name,groupid in (("KLIENT",groups[Group.CLIENT]),("SERWIS",groups[Group.SERVICE])):
    matched=[x for x in meshes if (x.get("_id") or x.get("id") or x.get("meshid"))==groupid]
    print(name+"_GROUP_FOUND:",bool(matched))
    direct=links.get(groupid)
    directrights=direct.get("rights") if isinstance(direct,dict) else None
    try:bits=int(directrights)
    except (ValueError,TypeError): bits=None
    print(name+"_DIRECT_LINK:", "YES" if direct is not None else "NO")
    print(name+"_DIRECT_RIGHTS_MASK:", bits if bits is not None else "UNKNOWN")
    if bits is not None:
        print(name+"_MANAGE_DEVICES_FLAG:",bool(bits&4))
        print(name+"_EDIT_GROUP_FLAG:",bool(bits&1))
        print(name+"_FULL_RIGHTS:",bits in (0xFFFFFFFF,0xFFFFFFFFFFFFFFFF))
    # Group links keyed by exact authenticated user ID:
    gl=matched[0].get("links") if matched else None
    item=gl.get(uid) if isinstance(gl,dict) else None
    val=item.get("rights") if isinstance(item,dict) else None
    print(name+"_GROUP_LINK_TO_USER:","YES" if item is not None else "NO")
    print(name+"_GROUP_LINK_RIGHTS:",val if isinstance(val,int) else "UNKNOWN")
print("=== END READONLY ===")
PY
