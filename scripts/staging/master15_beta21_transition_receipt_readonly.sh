#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
print("=== MASTER15 / ASUS SIGNED WINDOWS RECEIPT / READ ONLY ===")
with engine.connect() as db:
 ids=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).scalars().all()
 if len(ids)!=1:raise SystemExit("STOP: ASUS_NOT_UNIQUE")
 iid=ids[0]
 for name in ("workshop_profile_transitions","owner_mesh_group_sync"):
  cols=db.execute(text("""
   SELECT column_name FROM information_schema.columns
   WHERE table_schema='guard' AND table_name=:table ORDER BY ordinal_position
  """),{"table":name}).scalars().all()
  if not cols: print(name,"TABLE_ABSENT");continue
  safe=[x for x in ("state","target_mode","status","requested_group","revision","attempts","last_error","created_at","expires_at","requested_at","attempted_at","confirmed_at","updated_at") if x in cols]
  records=db.execute(text("SELECT "+",".join('"'+x+'"' for x in safe)+
                          " FROM guard."+name+" WHERE installation_id=:iid"),{"iid":iid}).mappings().all()
  print(name.upper(),"ROWS",len(records))
  for r in records:print(name.upper()+"_STATE",dict(r))
 for name in ("owner_profile_grants","owner_profile_reports","owner_profile_receipts"):
  cols=db.execute(text("""
   SELECT count(*) FROM information_schema.tables
   WHERE table_schema='guard' AND table_name=:table
  """),{"table":name}).scalar_one()
  print(name.upper()+"_TABLE",bool(cols))
print("=== END / NO CHANGES ===")
PY
