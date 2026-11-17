#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import importlib.util,os
from uuid import UUID
from sqlalchemy import text
from app.database import engine
print("=== MASTER110 ASUS — MESH OWNER DELETE SAFETY AUDIT / READ ONLY ===")
old=UUID("8c226c6e-d8bb-495e-a626-411f383eff10")
current=UUID("7c8470c9-6e81-48a4-be7c-f75ec2cb4c6d")
def columns(db,table):
 return set(db.execute(text("SELECT column_name FROM information_schema.columns WHERE table_schema='guard' AND table_name=:t"),{"t":table}).scalars())
with engine.connect() as db:
 links=db.execute(text("""SELECT installation_id,lifecycle FROM guard.license_links
 WHERE installation_id IN (:a,:b)"""),{"a":old,"b":current}).mappings().all()
 if len(links)!=2 or {(str(r["installation_id"]),r["lifecycle"]) for r in links}!={(str(old),"REVOKED"),(str(current),"ACTIVE")}:
  raise SystemExit("STOP: EXPECTED OLD REVOKED / CURRENT ACTIVE PAIR MISSING")
 nodes={"OLD":set(),"CURRENT":set()}
 for table in ("installations","workshop_mesh_nodes"):
  cols=columns(db,table)
  if "installation_id" not in cols:
   print("TABLE",table,"NO_INSTALLATION_ID");continue
  fields=[c for c in ("mesh_node_id","mesh_last_verified_node_id") if c in cols]
  if not fields:continue
  for label,iid in (("OLD",old),("CURRENT",current)):
   rows=db.execute(text("SELECT "+",".join('"'+c+'"' for c in fields)+" FROM guard."+table+" WHERE installation_id=:i LIMIT 20"),{"i":iid}).mappings().all()
   print("DB",label,table,"ROWS",len(rows))
   for r in rows:
    for key,val in r.items():
     if val:
      nodes[label].add(str(val))
      print("NODE_REFERENCE",label,table,key,"FINGERPRINT",str(val)[:10]+"…")
 print("OLD_NODE_COUNT",len(nodes["OLD"]))
 print("CURRENT_NODE_COUNT",len(nodes["CURRENT"]))
 overlap=nodes["OLD"] & nodes["CURRENT"]
 print("OVERLAP_COUNT",len(overlap))
 if overlap:print("STOP: SHARED_MESH_NODE; DO NOT DELETE")
 path="/opt/multiservis/auto_mesh_worker.py"
 spec=importlib.util.spec_from_file_location("mg_delete_worker_readonly",path)
 worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
 worker.load_api_environment()
 inventory=worker.inventory()
 approved={os.getenv("MESH_CENTRAL_SESSION_CONSENT_MESH_ID","").strip(),
           os.getenv("MESH_SERVICE_PRO_GROUP_ID","").strip()}-{""}
 print("APPROVED_GROUPS_CONFIGURED",len(approved))
 for label in ("OLD","CURRENT"):
  for node in sorted(nodes[label]):
   rec=inventory.get(node,[])
   print("INVENTORY",label,"NODE",node[:10]+"…","RECORDS",len(rec),
    "APPROVED_GROUP",bool(rec) and all(x.get("meshid") in approved for x in rec),
    "ONLINE",any(bool(x.get("conn")) for x in rec))
 print("OLD_MESH_REMAINING",sum(bool(inventory.get(node)) for node in nodes["OLD"]))
 print("CURRENT_MESH_REMAINING",sum(bool(inventory.get(node)) for node in nodes["CURRENT"]))
 print("SAFE_TO_ATTEMPT_OWNER_DELETE",bool(not overlap and approved and all(len(inventory.get(n,[]))<=1 and all(x.get("meshid") in approved for x in inventory.get(n,[])) for n in nodes["OLD"])))
print("=== END READ ONLY — NO MESH REMOVE, NO KEYGATE REVOCATION, NO SQL MUTATION ===")
PY