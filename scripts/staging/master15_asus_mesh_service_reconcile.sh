#!/usr/bin/env bash
# MASTER 1.5 ASUS one-time historical binding migration.
# This is NOT a replacement for normal OWNER Save triggering Mesh sync.
# Fail closed unless exactly one OWNER computer and one visible Mesh device
# with the same normalized host/name, approved CLIENT group and saved SERVICE.
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json,os,subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
from app.routers import multiguard_license as license
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import validate_groups,Group

pid=int(subprocess.check_output(
 ["systemctl","show","--property=MainPID","--value","multiservis-api.service"],
 text=True).strip())
if pid<1: raise SystemExit("STOP: API service not active")
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")
config=validate_groups(os.environ)
cmd=mesh._base_command()
if cmd.count("DeviceSharing")!=1: raise SystemExit("STOP: unexpected CLI command")
cmd[cmd.index("DeviceSharing")]="ListDevices"
devices=json.loads(mesh._run(cmd+["--json"]))
if not isinstance(devices,list) or len(devices)!=1:
    raise SystemExit("STOP: MeshCentral must have exactly one visible node in ASUS pilot")
node=devices[0]
if not isinstance(node,dict):raise SystemExit("STOP: invalid Mesh device")
nodeid=str(node.get("_id") or "")
mesh._auto_mesh_identifier(nodeid,"node")
if node.get("meshid")!=config[Group.CLIENT]:
    raise SystemExit("STOP: pilot node not in original CLIENT group")
print("PASS: one valid node currently in Klient")

with engine.connect() as db:
    rows=db.execute(text("""
        SELECT l.id,l.installation_id,l.plan_code,p.hostname,p.status,
               n.mesh_node_id
        FROM guard.license_links l
        JOIN guard.pending_installations p ON p.installation_id=l.installation_id
        JOIN guard.workshop_mesh_nodes n ON n.installation_id=l.installation_id
        WHERE l.installation_id IS NOT NULL
    """)).mappings().all()
    if len(rows)!=1: raise SystemExit("STOP: expected exactly one OWNER computer binding")
    row=rows[0]
    iid=row["installation_id"]
    if license._owner_effective_entitlement_mode(db,iid)!="SERVICE":
        raise SystemExit("STOP: ASUS is not saved as Service")
    hostname=str(row["hostname"] or "").strip()
    visible_name=str(node.get("name") or "").strip()
    if not hostname or hostname.casefold()!=visible_name.casefold():
        raise SystemExit("STOP: Mesh device name does not match OWNER registered hostname")
    oldid=str(row["mesh_node_id"] or "")
    if not oldid or oldid==nodeid:
        raise SystemExit("STOP: no stale node id to reconcile")
    # Cross-check the full target entitlement before modifying bindings.
    desired,target=sync._current_owner_target(db,iid)
    if desired!="SERVICE" or target!=config[Group.SERVICE]:
        raise SystemExit("STOP: SERVICE entitlement target mismatch")
    print("PASS: unique ASUS hostname match; OWNER=Service; target=Serwis")
    duplicates=db.execute(text("""
        SELECT COUNT(*) FROM guard.workshop_mesh_nodes
        WHERE mesh_node_id=:node_id
    """),{"node_id":nodeid}).scalar_one()
    if duplicates: raise SystemExit("STOP: visible node is already bound elsewhere")

# Changes are installation-scoped and transactionally recorded. No removal.
with engine.begin() as db:
    db.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).one()
    changed=db.execute(text("""
        UPDATE guard.workshop_mesh_nodes
        SET mesh_node_id=:new_id,updated_at=now()
        WHERE installation_id=:iid AND mesh_node_id=:old_id
        RETURNING installation_id
    """),{"iid":iid,"old_id":oldid,"new_id":nodeid}).all()
    if len(changed)!=1:raise SystemExit("STOP: concurrent node binding change")
    sync.queue_after_owner_save(db,iid)
    print("PASS: ASUS Mesh node binding corrected; SERVICE sync queued")

# Exit cleanly even when the Mesh API is temporarily unavailable.
result=sync.run_pending_installation(engine,iid,max_attempts=3)
print("MESH_SYNC_RESULT:",result)
with engine.connect() as db:
    g,status,attempts=sync.get_status(db,iid)
    print("OWNER_GRUPA_MESH:",g,"/",status,"ATTEMPTS:",attempts)
if result=="OK":
    print("PASS: MeshCentral verified ASUS in Serwis")
else:
    print("ATTENTION: no verified group change; inspect pending status before retry")
print("=== ASUS MIGRATION COMPLETE ===")
PY
