#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
print("=== MASTER 1.5 / ASUS POST-BETA21 OWNER AND MESH / READ-ONLY ===")
with engine.connect() as db:
 rows=db.execute(text("""
   SELECT p.installation_id,p.status AS installation_status,l.plan_code,l.lifecycle
   FROM guard.pending_installations p
   JOIN guard.license_links l ON l.installation_id=p.installation_id
   WHERE upper(p.hostname)='ROG'
 """)).mappings().all()
 if len(rows)!=1:raise SystemExit("STOP: ASUS_NOT_UNIQUE")
 r=rows[0]
 iid=r["installation_id"]
 print("ASUS_INSTALLATION",r["installation_status"],"PLAN",r["plan_code"],"LIFECYCLE",r["lifecycle"])
 print("OWNER_MODE",lic._owner_effective_entitlement_mode(db,iid))
 tables=["owner_mesh_group_sync","owner_profile_execution_receipts","owner_profile_reports","owner_profile_transitions","workshop_mesh_nodes"]
 for table in tables:
  columns=db.execute(text("""
    SELECT column_name FROM information_schema.columns
    WHERE table_schema='guard' AND table_name=:t ORDER BY ordinal_position
  """),{"t":table}).scalars().all()
  if not columns:
   print(table.upper(),"TABLE_ABSENT");continue
  print(table.upper()+"_COLS",",".join(columns))
  if "installation_id" not in columns:continue
  safe=[c for c in columns if c in (
    "requested_group","status","target_mesh_id","observed_mesh_id",
    "attempts","revision","last_error","requested_at","confirmed_at",
    "reported_at","created_at","updated_at","state","target_mode",
    "execution_result","receipt_status","mesh_node_id")]
  if not safe:continue
  q=text("SELECT "+",".join('\"'+c+'\"' for c in safe)+
         " FROM guard."+table+" WHERE installation_id=:iid LIMIT 3")
  try:
   records=db.execute(q,{"iid":iid}).mappings().all()
   for rec in records:
    cleaned={k:("[MESH_NODE_PRESENT]" if k=="mesh_node_id" and v else v)
       for k,v in dict(rec).items()}
    print(table.upper()+"_STATE",cleaned)
   if not records:print(table.upper()+"_STATE","NONE")
  except Exception as e:
   print(table.upper()+"_READ_ERROR",type(e).__name__)
print("=== NO CHANGE / READONLY_COMPLETE ===")
PY
