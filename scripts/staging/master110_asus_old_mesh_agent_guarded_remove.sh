#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import importlib.util,os
from uuid import UUID
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
OLD_IID=UUID("8c226c6e-d8bb-495e-a626-411f383eff10")
NEW_IID=UUID("7c8470c9-6e81-48a4-be7c-f75ec2cb4c6d")
OLD_LID=UUID("a29b7aba-fb1f-48cb-8f22-3eadc2aa4727")
NEW_LID=UUID("d521b000-5351-4026-aca0-d5e8ca373849")
print("=== MASTER110 OLD ASUS MESH CLEANUP (GUARDED) ===")
with engine.connect() as db:
    rows=db.execute(text("""SELECT l.id,l.installation_id,l.lifecycle,p.hostname,p.status
    FROM guard.license_links l JOIN guard.pending_installations p ON p.installation_id=l.installation_id
    WHERE l.id IN (:old,:new)"""),{"old":OLD_LID,"new":NEW_LID}).mappings().all()
    assert len(rows)==2 and {(r["id"],r["installation_id"],r["lifecycle"],r["hostname"]) for r in rows}=={
      (OLD_LID,OLD_IID,"REVOKED","ROG"),(NEW_LID,NEW_IID,"ACTIVE","ROG")},"STOP LICENSE SAFETY"
    nodes=db.execute(text("SELECT mesh_node_id FROM guard.workshop_mesh_nodes WHERE installation_id=:iid"),{"iid":OLD_IID}).scalars().all()
    assert len(nodes)==1 and nodes[0],"STOP EXPECT EXACTLY ONE OLD MESH NODE"
    node=str(nodes[0])
    print("OLD_NODE_FINGERPRINT",node[:12]+"…")
    # Check all known installation ownership tables, including internal guard.installations ID link.
    cols=lambda t:set(db.execute(text("SELECT column_name FROM information_schema.columns WHERE table_schema='guard' AND table_name=:t"),{"t":t}).scalars())
    for table in ("installations","workshop_mesh_nodes"):
        c=cols(table)
        if "mesh_node_id" not in c:continue
        idcol="installation_external_id" if table=="installations" and "installation_external_id" in c else "installation_id"
        for field in ("mesh_node_id","mesh_last_verified_node_id"):
            if field not in c:continue
            refs=db.execute(text(f"SELECT CAST({idcol} AS text) FROM guard.{table} WHERE {field}=:node"),{"node":node}).scalars().all()
            print("OWNERSHIP",table,field,"COUNT",len(refs))
            assert all(str(v)==str(OLD_IID) for v in refs),f"STOP NODE SHARED: {table}.{field}"
    active_node_refs=[]
    for table in ("installations","workshop_mesh_nodes"):
        c=cols(table)
        idcol="installation_external_id" if table=="installations" else "installation_id"
        if idcol not in c:continue
        for field in ("mesh_node_id","mesh_last_verified_node_id"):
            if field not in c:continue
            rr=db.execute(text(f"SELECT {field} FROM guard.{table} WHERE {idcol}=:iid AND {field} IS NOT NULL"),{"iid":NEW_IID}).scalars().all()
            active_node_refs.extend(map(str,rr))
    assert node not in active_node_refs,"STOP OLD NODE IS IN CURRENT INSTALLATION"
    # Never remove a node if owner tables show any different installation owning it.
    for table in ("remote_sessions","workshop_remote_sessions"):
        c=cols(table)
        if "installation_id" in c and "status" in c:
            pending=db.execute(text(f"SELECT count(*) FROM guard.{table} WHERE installation_id=:iid AND UPPER(status) IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"),{"iid":OLD_IID}).scalar()
            assert not pending,f"STOP REMOTE SESSION ACTIVE: {table}"
    print("PASS DATABASE OWNERSHIP")
spec=importlib.util.spec_from_file_location("mg_safe_delete_worker","/opt/multiservis/auto_mesh_worker.py")
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
worker.load_api_environment()
inventory=worker.inventory()
records=inventory.get(node,[])
assert len(records)==1,"STOP OLD NODE NOT UNIQUELY IN INVENTORY"
approved={os.getenv("MESH_CENTRAL_SESSION_CONSENT_MESH_ID","").strip(),os.getenv("MESH_SERVICE_PRO_GROUP_ID","").strip()}-{""}
assert approved and records[0].get("meshid") in approved,"STOP NOT APPROVED GROUP"
assert not records[0].get("conn"),"STOP OLD NODE REPORTS ONLINE"
print("PASS MESH INVENTORY: unique, approved group, offline")
# The OLD revoked agent only: never remove the active ASUS or change its license.
try:
    mesh._run(mesh._auto_mesh_command("RemoveDevice")+["--id",node])
except mesh.MeshCentralError as exc:
    if worker.inventory().get(node):
        print("STOP MESH REMOVAL UNCONFIRMED",type(exc).__name__)
        raise SystemExit(2)
if worker.inventory().get(node):
    raise SystemExit("STOP OLD NODE STILL IN MESH INVENTORY")
print("PASS OLD AGENT REMOVED FROM MESH")
print("NEXT: USE OWNER DELETE ON OLD REVOKED ASUS ROW ONLY")
print("=== END — CURRENT ASUS AND LICENSES NOT MODIFIED ===")
PY
