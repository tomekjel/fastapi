#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import os,json,subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mc
from app.routers import multiguard_license as lic

pid=int(subprocess.check_output(
    ["systemctl","show","--property=MainPID","--value","multiservis-api.service"],
    text=True).strip())
if pid<1: raise SystemExit("STOP: API not running")
for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in item:
        k,v=item.split(b"=",1)
        os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")

command=mc._base_command()
if command.count("DeviceSharing")!=1: raise SystemExit("STOP: Unexpected Mesh CLI command")
command[command.index("DeviceSharing")]="ListDevices"
devices=json.loads(mc._run(command+["--json"]))
if not isinstance(devices,list):raise SystemExit("STOP: ListDevices returned non-list")
print("=== OWNER MESH CROSS CHECK, READ-ONLY ===")
with engine.connect() as db:
    rows=db.execute(text("""
        SELECT l.installation_id,l.plan_code, n.mesh_node_id,
               p.hostname,p.model,p.status AS installation_status
        FROM guard.license_links l
        LEFT JOIN guard.workshop_mesh_nodes n
          ON n.installation_id=l.installation_id
        LEFT JOIN guard.pending_installations p
          ON p.installation_id=l.installation_id
        WHERE l.installation_id IS NOT NULL
        ORDER BY l.updated_at DESC LIMIT 10
    """)).mappings().all()
    print("OWNER_LINKS:",len(rows))
    print("MESH_NODES_VISIBLE:",len(devices))
    print("VISIBLE_GROUPS:")
    client=os.getenv("MESH_CENTRAL_SESSION_CONSENT_MESH_ID","")
    service=os.getenv("MESH_SERVICE_PRO_GROUP_ID","")
    for i,node in enumerate(devices,1):
        if not isinstance(node,dict): raise SystemExit("STOP: invalid Mesh node")
        nodeid=str(node.get("_id") or "")
        groupid=str(node.get("meshid") or "")
        g="SERWIS" if groupid==service else "KLIENT" if groupid==client else "INNA"
        print(f"  NODE_{i}: GROUP={g}, HOST_IS_ROG={'YES' if str(node.get('host','')).strip().upper()=='ROG' else 'NO'}, "
              f"NAME_MENTIONS_ASUS={'YES' if 'ASUS' in str(node.get('name','')).upper() else 'NO'}, "
              f"NODE_ID_VALID={'YES' if nodeid.startswith('node/') else 'NO'}")
        for j,row in enumerate(rows,1):
            saved=str(row["mesh_node_id"] or "")
            host=str(row["hostname"] or "")
            host_match=bool(host and host.casefold()==str(node.get("host","")).casefold())
            name_match=bool(host and host.casefold()==str(node.get("name","")).casefold())
            same_id=saved==nodeid
            same_suffix=bool(saved and nodeid and saved.split("/")[-1]==nodeid.split("/")[-1])
            print(f"  LINK_{j}_NODE_{i}: SAME_ID={'YES' if same_id else 'NO'}, "
                  f"SAME_NODE_SUFFIX={'YES' if same_suffix else 'NO'}, "
                  f"OWNER_HOST_MATCH={'YES' if host_match else 'NO'}, "
                  f"OWNER_NAME_MATCH={'YES' if name_match else 'NO'}, "
                  f"SAVED_NODE_EXISTS={'YES' if saved else 'NO'}")
    for j,row in enumerate(rows,1):
        mode=lic._owner_effective_entitlement_mode(db,row["installation_id"])
        print(f"OWNER_{j}: MODE={mode}, PLAN={row['plan_code']}, "
              f"HOST_IS_ROG={'YES' if str(row['hostname'] or '').strip().upper()=='ROG' else 'NO'}, "
              f"INSTALLATION_STATUS={row['installation_status'] or 'UNKNOWN'}")
print("=== READONLY_COMPLETE ===")
PY
