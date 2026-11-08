#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json, os, subprocess
from pathlib import Path
from app.routers import multiguard_meshcentral as mc
from app.routers.master15_owner_mesh_group_policy import Group,validate_groups
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<=0:raise SystemExit("STOP: API is not running")
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")
groups=validate_groups(os.environ)
print("=== MESH MOVE PERMISSIONS (READONLY) ===")
def call(name):
    command=mc._base_command()
    if command.count("DeviceSharing")!=1:raise RuntimeError("UNEXPECTED_CLI")
    command[command.index("DeviceSharing")]=name
    try:
        result=mc._run(command+["--json"])
        try:return json.loads(result)
        except ValueError:return {"_non_json_response":True}
    except Exception as err:
        print(name+"_ERROR_CLASS:",type(err).__name__)
        # Only classified, never print raw CLI output/credentials.
        message=str(err).lower()
        if "denied" in message or "forbidden" in message or "permission" in message:
            print(name+"_ERROR_CATEGORY: PERMISSION")
        elif "login" in message or "auth" in message:
            print(name+"_ERROR_CATEGORY: AUTH")
        else:print(name+"_ERROR_CATEGORY: OTHER")
        return None
def walk_groups(v):
    if isinstance(v,list):return [x for x in v if isinstance(x,dict)]
    if isinstance(v,dict):
        for key in ("meshes","groups","devicegroups","deviceGroups"):
            if isinstance(v.get(key),list):return walk_groups(v[key])
        return [dict(x,_id=k) for k,x in v.items() if isinstance(x,dict)]
    return []
info=call("UserInfo")
if isinstance(info,dict):
    print("USERINFO_AVAILABLE:YES")
    print("USERINFO_FIELDS:",sorted(x for x in info if x in ("siteadmin","siteAdmin","rights","permissions","name","account","userid","_id","links")))
    for key in ("siteadmin","siteAdmin","rights","permissions"):
        if key in info and isinstance(info[key],(int,str,bool)):
            print("USER_"+key.upper()+":",str(info[key])[:32])
else:print("USERINFO_AVAILABLE:NO")
devices=call("ListDeviceGroups")
g=walk_groups(devices)
print("GROUPS_VISIBLE_COUNT:",len(g))
for typ,expected in (("KLIENT",groups[Group.CLIENT]),("SERWIS",groups[Group.SERVICE])):
    found=[x for x in g if str(x.get("_id") or x.get("id") or x.get("meshid") or "")==expected]
    print(typ+"_GROUP_VISIBLE:","YES" if found else "NO")
    if found:
        o=found[0]
        print(typ+"_GROUP_FIELDS:", sorted(k for k in o if k in ("name","rights","users","links","consent","mtype")))
        # Rights can be represented by links keyed by account identifiers.
        # Only show the presence, not user identifiers or grant details.
        print(typ+"_HAS_USER_LINKS:","YES" if isinstance(o.get("links"),dict) and o["links"] else "NO")
print("=== READONLY_COMPLETE ===")
PY
