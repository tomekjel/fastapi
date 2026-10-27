"""Read-only production preflight. Print statuses only: no IDs, secrets, hosts or names."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

KEYS=(
    "MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID",
    "MESH_CENTRAL_OWNER_OWNED_MESH_ID",
    "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID",
)
# Internal adapters only; never include values in output.
PRIVATE_CONFIG_KEYS=(
    "MESH_CENTRAL_TOKEN_FILE",
    "MESH_CENTRAL_URL",
    "MESH_CENTRAL_NODE_BIN",
    "MESH_CENTRAL_MESHCTRL_PATH",
)
PATTERN=re.compile(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}")
ROUTER=Path("/opt/multiservis/app/routers")
API=ROUTER/"multiguard_workshop_remote.py"
MESH=ROUTER/"multiguard_meshcentral.py"

def status(label,value):
    print("OWNER_MESH_PREFLIGHT "+label+"="+value, flush=True)

def read_service_env():
    pid=subprocess.check_output(
        ["systemctl","show","multiservis-api.service","--property","MainPID","--value"],
        text=True,timeout=8).strip()
    if not pid.isdecimal() or int(pid)<=1:
        raise RuntimeError("API_NOT_RUNNING")
    # Never write raw /proc environ or systemctl Environment to logs.
    values={}
    for record in Path("/proc/"+pid+"/environ").read_bytes().split(b"\0"):
        name,sep,value=record.partition(b"=")
        if sep and name.decode("ascii","ignore") in (KEYS+PRIVATE_CONFIG_KEYS):
            values[name.decode("ascii")]=value.decode("ascii","ignore").strip()
    return values

def group_ids(payload):
    if isinstance(payload,list):
        return [x.get("_id") for x in payload if isinstance(x,dict)]
    if isinstance(payload,dict):
        if "meshes" in payload:
            return group_ids(payload["meshes"])
        if all(isinstance(v,dict) for v in payload.values()):
            return [v.get("_id",k) for k,v in payload.items()]
    raise ValueError("MESHCTRL_INVALID_GROUP_LIST")

def main():
    status("PRODUCTION_STANDING_ROUTE","PRESENT" if API.is_file() and
           "def request_for_owner" in API.read_text(encoding="utf-8") and
           "STANDING_OWNER_REQUESTED" in API.read_text(encoding="utf-8")
           else "NOT_DEPLOYED")
    values=read_service_env()
    for name in PRIVATE_CONFIG_KEYS:
        if values.get(name):
            os.environ[name]=values[name]
    groups={}
    for name in KEYS:
        value=values.get(name,"")
        valid=bool(PATTERN.fullmatch(value))
        status(name,"VALID" if valid else "MISSING" if not value else "INVALID")
        groups[name]=value if valid else None
    if not MESH.is_file():
        status("MESHCTRL","ADAPTER_NOT_DEPLOYED")
        return 2
    spec=importlib.util.spec_from_file_location("owner_readonly_mesh",MESH)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    # Reuse production's existing token-file authorization, never print it.
    cmd=list(module._base_command())
    cmd[cmd.index("DeviceSharing")]="ListDeviceGroups"
    result=module._run(cmd+["--json"])
    ids=set(x for x in group_ids(json.loads(result)) if isinstance(x,str))
    for name in KEYS:
        status(name+"_EXISTS","YES" if groups[name] in ids else
               "NO" if groups[name] else "UNKNOWN")
    if not all(groups.values()) or not all(v in ids for v in groups.values()):
        return 2
    if len(set(groups.values()))!=len(KEYS):
        status("GROUP_ISOLATION","DUPLICATED")
        return 2
    status("GROUP_ISOLATION","DISTINCT_AND_PRESENT")
    return 0

if __name__=="__main__":
    try:
        sys.exit(main())
    except Exception as e:
        status("RESULT",type(e).__name__)
        sys.exit(3)
