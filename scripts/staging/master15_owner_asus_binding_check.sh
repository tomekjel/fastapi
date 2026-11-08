#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json,os,subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mc
from app.routers import multiguard_license as license
from app.routers.master15_owner_mesh_group_policy import observed_group_for_node

# Read process environment only for the runtime Mesh CLI; never print values.
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<=0: raise SystemExit("STOP: API not running")
env={}
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        env[k.decode("utf8","replace")]=v.decode("utf8","replace")
os.environ.update(env)
cmd=mc._base_command()
assert cmd.count("DeviceSharing")==1
cmd[cmd.index("DeviceSharing")]="ListDevices"
devices=json.loads(mc._run(cmd+["--json"]))
assert isinstance(devices,list)

print("=== MASTER 1.5 / OWNER-ASUS MESH BINDING READONLY ===")
with engine.connect() as db:
    rows=db.execute(text("""
        SELECT l.id,l.installation_id,l.plan_code,l.lifecycle,
               n.mesh_node_id,n.session_id
        FROM guard.license_links l
        LEFT JOIN guard.workshop_mesh_nodes n
          ON n.installation_id=l.installation_id
        WHERE l.installation_id IS NOT NULL
        ORDER BY l.updated_at DESC LIMIT 30
    """)).mappings().all()
    print("OWNER_LINKS_COUNT:",len(rows))
    print("MESH_VISIBLE_COUNT:",len(devices))
    for i,row in enumerate(rows,1):
        mode=license._owner_effective_entitlement_mode(db,row["installation_id"])
        node=row["mesh_node_id"]
        if node:
            present,group=observed_group_for_node(devices,node)
            expected=os.getenv("MESH_SERVICE_PRO_GROUP_ID") if mode=="SERVICE" else (
                os.getenv("MESH_CENTRAL_SESSION_CONSENT_MESH_ID") if row["plan_code"]=="multi_guard_pro" else None)
            match="YES" if present and expected and group==expected else "NO" if present else "NOT_VISIBLE"
        else:
            present=False
            match="NO_LINK"
        print(f"OWNER_ROW_{i}: MODE={mode}; PLAN={row['plan_code']}; "
              f"DB_NODE_LINK={'YES' if node else 'NO'}; "
              f"NODE_VISIBLE={'YES' if present else 'NO'}; "
              f"EXPECTED_GROUP_MATCH={match}")
print("=== END READONLY ===")
PY
