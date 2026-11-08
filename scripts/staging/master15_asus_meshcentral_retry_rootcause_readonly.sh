#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json,os,subprocess,inspect
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
from app.routers import master15_owner_mesh_sync_engine as sync

print("=== MASTER 1.5 / ASUS MESH RETRY ROOT CAUSE / READ ONLY ===")
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<2:raise SystemExit("STOP_API_INACTIVE")
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        key,value=pair.split(b"=",1)
        os.environ[key.decode("utf8","replace")]=value.decode("utf8","replace")
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT p.installation_id,n.mesh_node_id,s.target_mesh_id,s.requested_group,
             s.status,s.attempts,s.revision,s.last_error,
             t.state AS receipt_state,t.target_mode AS receipt_target
      FROM guard.pending_installations p
      JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
      LEFT JOIN guard.workshop_mesh_nodes n ON n.installation_id=p.installation_id
      LEFT JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
      WHERE upper(p.hostname)='ROG'
    """)).mappings().all()
    if len(rows)!=1:raise SystemExit("STOP_ROG_NOT_UNIQUE")
    row=rows[0]
    print("OWNER_GROUP",row["requested_group"],"SYNC",row["status"],"ATTEMPTS",row["attempts"],
          "RECEIPT",row["receipt_state"],row["receipt_target"])
    print("MESH_SAVED_NODE_PRESENT",bool(row["mesh_node_id"]))
    print("MESH_TARGET_CONFIGURED",bool(row["target_mesh_id"]))
    print("SERVER_HAS_MOVE_FUNCTION",callable(getattr(mesh,"move_registered_node_to_group",None)))
    print("STANDARD_RECEIPT_GATE",sync._verified_standard_shutdown(db,row["installation_id"]))
try:
    args=mesh._base_command()
    print("MESH_CLI_CONFIGURED",True)
    if args.count("DeviceSharing")!=1:raise RuntimeError("unexpected_cli")
    args[args.index("DeviceSharing")]="ListDevices"
    # This is an authenticated READ-ONLY ListDevices operation; no move.
    raw=mesh._run(args+["--json"])
    nodes=json.loads(raw)
    if not isinstance(nodes,list):raise RuntimeError("not_list")
    print("MESH_LIST_DEVICES_PASS",len(nodes))
    saved=str(row["mesh_node_id"] or "")
    targets=[x for x in nodes if isinstance(x,dict) and x.get("_id")==saved]
    print("SAVED_NODE_VISIBLE_EXACTLY_ONCE",len(targets)==1)
    if len(targets)==1:
        x=targets[0]
        print("SAVED_NODE_IN_TARGET_GROUP",x.get("meshid")==row["target_mesh_id"])
        print("SAVED_NODE_IN_SERVICE_GROUP",x.get("meshid")==os.getenv("MESH_SERVICE_PRO_GROUP_ID"))
    matching_hosts=[x for x in nodes if isinstance(x,dict) and (
        str(x.get("name") or "").upper()=="ROG" or str(x.get("host") or "").upper()=="ROG")]
    print("ROG_HOSTNAME_MATCHING_NODES",len(matching_hosts))
    for x in matching_hosts[:3]:
        print("ROG_NAME_MATCH_SAVED_ID",str(x.get("_id") or "")==saved)
        print("ROG_NAME_IN_TARGET_GROUP",x.get("meshid")==row["target_mesh_id"])
        print("ROG_NAME_IN_SERVICE_GROUP",x.get("meshid")==os.getenv("MESH_SERVICE_PRO_GROUP_ID"))
except Exception as exc:
    msg=str(exc).lower()
    markers=("unauthoriz","forbidden","permission","login","token","timed out","timeout",
             "certificate","tls","ssl","connect","not found","unsupported","syntax",
             "meshctrl","invalid","error")
    print("MESH_LIST_DEVICES_ERROR_TYPE",type(exc).__name__)
    print("MESH_LIST_DEVICES_ERROR_CATEGORIES",[m for m in markers if m in msg])
    print("MESH_LIST_DEVICES_FAILED_NO_MOVE_ATTEMPTED")
print("=== READ ONLY COMPLETE ===")
PY
