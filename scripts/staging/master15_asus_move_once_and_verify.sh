#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import json,os,re,subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mc
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import Group,validate_groups,observed_group_for_node
from app.routers import multiguard_license as license

pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid<=0: raise SystemExit("STOP: FastAPI inactive")
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")
groups=validate_groups(os.environ)
target=groups[Group.SERVICE]
client=groups[Group.CLIENT]

print("=== ASUS ONE-TIME MOVE / VERIFY ===")
with engine.connect() as db:
    records=db.execute(text("""
        SELECT l.installation_id,l.plan_code,p.hostname,n.mesh_node_id,
               s.requested_group,s.status,s.attempts,s.revision,s.target_mesh_id
        FROM guard.license_links l
        JOIN guard.pending_installations p ON p.installation_id=l.installation_id
        JOIN guard.workshop_mesh_nodes n ON n.installation_id=l.installation_id
        JOIN guard.owner_mesh_group_sync s ON s.installation_id=l.installation_id
        WHERE l.installation_id IS NOT NULL
    """)).mappings().all()
    if len(records)!=1:raise SystemExit("STOP: not one OWNER installation")
    record=records[0]
    iid=record["installation_id"]
    nodeid=record["mesh_node_id"]
    mc._auto_mesh_identifier(nodeid,"node")
    if str(record["hostname"]).strip().upper()!="ROG":
        raise SystemExit("STOP: ASUS hostname is not ROG")
    if license._owner_effective_entitlement_mode(db,iid)!="SERVICE":
        raise SystemExit("STOP: saved OWNER edition is not Service")
    if (record["requested_group"]!="SERVICE" or
        record["target_mesh_id"]!=target or
        record["status"]!="RETRY" or record["attempts"]!=3):
        raise SystemExit("STOP: unexpected queued sync state")
    revision=record["revision"]
    print("PASS: OWNER Service / ASUS ROG / bound node / three attempts")

before=sync._list_visible_nodes()
if len(before)!=1:
    raise SystemExit("STOP: expected exactly one visible Mesh node")
visible,oldgroup=observed_group_for_node(before,nodeid)
if not visible:
    raise SystemExit("STOP: bound ASUS node invisible")
if oldgroup not in (client,target):
    raise SystemExit("STOP: unexpected group")
print("GROUP_BEFORE:","SERWIS" if oldgroup==target else "KLIENT")
error_class="NONE"
if oldgroup==client:
    try:
        mc.move_registered_node_to_group(nodeid,target)
        print("MOVE_COMMAND_RETURNED: SUCCESS")
    except Exception as exc:
        error_class=type(exc).__name__
        # Output is untrusted; never print error text, IDs, hosts, tokens.
        msg=str(exc).lower()
        categories=(
          ("AUTHENTICATION","invalid login|unable to connect|authentication|unauthorized"),
          ("PERMISSION","access denied|permission denied|forbidden|denied"),
          ("UNRECOGNIZED_GROUP","invalid group|group not found|invalid mesh|device group"),
          ("NODE_NOT_FOUND","device not found|invalid device|unknown device"),
          ("CLI_OPTIONS","unknown option|invalid argument|invalid command|missing required"),
          ("TIMEOUT","timed out|timeout"),
          ("TLS","certificate|ssl|tls"),
          ("EMPTY_OUTPUT","nie potwierdzi|no confirmation"),
          ("INSUFFICIENT_RIGHTS","rights|privileges|insufficient"),
        )
        diagnosis=next((category for category,pattern in categories if re.search(pattern,msg)),"OTHER")
        print("MOVE_COMMAND_ERROR:",error_class)
        print("ERROR_CATEGORY:",diagnosis)
        print("ERROR_LENGTH:",len(str(exc)))
else:
    print("MOVE_SKIPPED_ALREADY_IN_SERVICE")
try:
    after=sync._list_visible_nodes()
    found,actual=observed_group_for_node(after,nodeid)
except Exception as exc:
    print("READBACK_ERROR:",type(exc).__name__)
    raise SystemExit(3)
if not found:raise SystemExit("STOP: bound node vanished after command")
print("GROUP_AFTER:","SERWIS" if actual==target else "KLIENT" if actual==client else "OTHER")
if actual!=target:
    print("NOT_CONFIRMED: retaining RETRY state; no DB status modification")
    raise SystemExit(2)
with engine.begin() as db:
    db.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).one()
    # Transactional guard against a different OWNER target/revision.
    latest=db.execute(text("""
        SELECT s.revision,s.requested_group,s.target_mesh_id,s.status
        FROM guard.owner_mesh_group_sync s
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).mappings().one()
    if (latest["revision"]!=revision or latest["requested_group"]!="SERVICE"
        or latest["target_mesh_id"]!=target or latest["status"]!="RETRY"):
        raise SystemExit("STOP: OWNER state changed during Mesh move, no status update")
    result=db.execute(text("""
        UPDATE guard.owner_mesh_group_sync
        SET status='OK',observed_mesh_id=:observed,confirmed_at=now(),
            last_error=NULL,updated_at=now()
        WHERE installation_id=:iid AND revision=:revision
          AND status='RETRY' AND target_mesh_id=:observed
        RETURNING installation_id
    """),{"iid":iid,"revision":revision,"observed":actual}).all()
    if len(result)!=1:raise SystemExit("STOP: sync confirmation race")
print("PASS: VERIFIED MESH GROUP SERWIS")
print("PASS: OWNER GRUPA MESH Serwis / OK")
PY
