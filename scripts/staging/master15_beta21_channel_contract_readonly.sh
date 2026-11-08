#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import inspect,os
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_updates as updates
print("=== MASTER 1.5 / LIVE BETA CHANNEL CONTRACT (READ ONLY) ===")
for name in ("_normalized_channel","_resolve_channel","_semver"):
 fn=getattr(updates,name,None)
 if fn is None: print("MISSING_FUNCTION",name);continue
 src=inspect.getsource(fn)
 if len(src)>12500: raise SystemExit("UNEXPECTED_LARGE_FUNCTION_"+name)
 print("FUNCTION",name,"\n"+src)
print("CHANNEL_ENV_NAMES",[k for k in os.environ if "CHANNEL" in k or "BETA" in k or "PILOT" in k])
with engine.connect() as db:
 rows=db.execute(text("""
 SELECT p.installation_id,p.hostname,p.status AS install_status,
        l.release_channel AS owner_release_channel,l.plan_code,l.lifecycle
 FROM guard.pending_installations p
 LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
 WHERE upper(p.hostname)='ROG'
 """)).mappings().all()
 if len(rows)!=1: raise SystemExit("ROG_NOT_UNIQUE")
 r=rows[0]
 iid=r["installation_id"]
 actual,returned_iid=updates._resolve_channel(db,str(iid))
 print("ROG_LICENSE_CHANNEL",r["owner_release_channel"])
 print("ROG_UPDATER_CHANNEL",actual)
 print("ROG_UPDATER_ID_MATCH",str(returned_iid)==str(iid))
 print("ROG_PLAN",r["plan_code"],"LIFECYCLE",r["lifecycle"])
 print("BETA21_CATALOG_ENTRY_EXISTS",bool(db.execute(text("SELECT 1 FROM guard.release_versions WHERE version='0.3.46-beta.21' LIMIT 1")).first()))
 for name in ("release_channel","channel"):
  try:
   rows2=db.execute(text(f"SELECT {name},is_current FROM guard.installations WHERE installation_external_id=:iid"),{"iid":iid}).mappings().all()
   print("INSTALLATIONS_"+name.upper(),[(x[name],x["is_current"]) for x in rows2])
  except Exception as e: print("INSTALLATIONS_"+name.upper()+"_UNAVAILABLE",type(e).__name__)
print("=== CHANNEL CONTRACT COMPLETE; ZERO MUTATIONS ===")
PY
