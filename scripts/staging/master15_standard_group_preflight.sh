#!/usr/bin/env bash
# Read-only production gate for three-group MeshCentral OWNER sync.
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import os,json,subprocess
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as license
from app.routers import multiguard_meshcentral as mesh
print("=== MASTER 1.5 / THREE MESH GROUPS PREFLIGHT (READ ONLY) ===")
# Gather the live systemd service environment ONLY in memory; do not log it.
pid=subprocess.check_output(["systemctl","show","multiservis-api.service","-p","MainPID","--value"],text=True).strip()
if not pid.isdigit() or int(pid)<2:raise SystemExit("STOP: FASTAPI_NOT_RUNNING")
raw=open(f"/proc/{pid}/environ","rb").read()
for item in raw.split(b"\0"):
    if b"=" in item:
        k,v=item.split(b"=",1)
        if k.startswith(b"MESH_") or k in (b"PATH",b"NODE_ENV"):
            os.environ[k.decode()]=v.decode()
print("FASTAPI_ENV: loaded without exposing credentials")
cmd=mesh._base_command()
assert cmd.count("DeviceSharing")==1
cmd[cmd.index("DeviceSharing")]="ListDeviceGroups"
try:
    output=mesh._run(cmd+["--json"])
    parsed=json.loads(output)
    print("DEVICE_GROUPS_JSON_TYPE:",type(parsed).__name__)
    groups=parsed if isinstance(parsed,list) else parsed.get("devicegroups",parsed.get("groups",[])) if isinstance(parsed,dict) else []
    print("DEVICE_GROUPS_COUNT:",len(groups) if isinstance(groups,list) else "INVALID")
    if isinstance(groups,list):
        for g in groups:
            if not isinstance(g,dict):continue
            name=str(g.get("name",g.get("meshname",g.get("groupname",""))))
            print("GROUP",repr(name[:90]),"HAS_ID",bool(g.get("_id") or g.get("meshid")))
except Exception as exc:
    print("GROUP_DISCOVERY_ERROR",type(exc).__name__,str(exc)[:160])
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT p.installation_id,p.hostname,l.lifecycle,l.plan_code,l.updated_at AS license_updated,
             t.target_mode,t.state AS transition_state,t.created_at AS transition_created,
             t.expires_at AS transition_expires,
             s.requested_group,s.status AS sync_status,s.attempts,s.last_error,
             n.mesh_node_id IS NOT NULL AS bound
      FROM guard.pending_installations p
      LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
      LEFT JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
      LEFT JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
      LEFT JOIN guard.workshop_mesh_nodes n ON n.installation_id=p.installation_id
      WHERE upper(p.hostname)='ROG' ORDER BY p.last_seen_at DESC LIMIT 3
    """)).mappings().all()
    for r in rows:
        print("ASUS",r["hostname"],"PLAN",r["plan_code"],"LIFECYCLE",r["lifecycle"],
              "SYNC",r["requested_group"],r["sync_status"],r["attempts"],
              "ERROR",r["last_error"],"NODE_BOUND",r["bound"])
        print("BROKER_REPORT",r["target_mode"],r["transition_state"],
              "FRESH_AFTER_LICENCE",bool(r["transition_created"] and r["license_updated"] and r["transition_created"]>=r["license_updated"]))
        try:print("OWNER_MODE",license._owner_effective_entitlement_mode(db,r["installation_id"]))
        except Exception as exc:print("OWNER_MODE_ERROR",type(exc).__name__)
print("=== PREFLIGHT COMPLETE ===")
PY
