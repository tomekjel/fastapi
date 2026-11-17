#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import collections,re,subprocess
from uuid import UUID
from sqlalchemy import text
from app.database import engine
ASUS=UUID("7c8470c9-6e81-48a4-be7c-f75ec2cb4c6d")
LENOVO=UUID("cce9ab4a-bf6a-4135-a6bc-f0486e65e0c3")
print("=== OWNER MESH — ASUS PRO + LENOVO STANDARD / READ ONLY ===")
with engine.connect() as db:
 def cols(t):
  return set(db.execute(text("SELECT column_name FROM information_schema.columns WHERE table_schema=:schema AND table_name=:table"),{"schema":"guard","table":t}).scalars())
 for name,iid,host in (("ASUS",ASUS,"ROG"),("LENOVO",LENOVO,"THINKPAD")):
  print("=== DEVICE",name,"===")
  rows=db.execute(text("""SELECT p.hostname,p.status as discovery_status,p.last_seen_at,
    l.lifecycle,l.plan_code,l.release_channel,l.app_version,l.rebind_pending,
    l.accepted_at,l.valid_until
    FROM guard.pending_installations p LEFT JOIN guard.license_links l
    ON l.installation_id=p.installation_id WHERE p.installation_id=:iid"""),{"iid":iid}).mappings().all()
  if len(rows)!=1 or str(rows[0]["hostname"]).upper()!=host:
   print("STOP_DEVICE_MISMATCH",name);continue
  print("LICENSE_AND_DISCOVERY",dict(rows[0]))
  for table in ("owner_mesh_group_sync","workshop_profile_transitions","workshop_mesh_nodes","installations"):
   fields=cols(table)
   key="installation_id" if "installation_id" in fields else "installation_external_id" if "installation_external_id" in fields else None
   if not key:
    print("TABLE",table,"NO_INSTALLATION_KEY");continue
   select=[c for c in ("requested_group","target_mode","state","status","attempts","last_error","revision","updated_at","created_at","expires_at","requested_at","target_mesh_id","observed_mesh_id","mesh_node_id","mesh_last_verified_node_id") if c in fields]
   if not select:continue
   q="SELECT "+",".join('"'+c+'"' for c in select)+" FROM guard."+table+" WHERE "+key+"=:iid LIMIT 6"
   try:
    items=db.execute(text(q),{"iid":iid}).mappings().all()
    print("TABLE",table,"ROWS",len(items))
    for r in items:
     print("ROW",table,{k:("PRESENT" if v else "ABSENT") if "node_id" in k or "mesh_id" in k else str(v) if v is not None else None for k,v in r.items()})
   except Exception as ex:
    print("TABLE_READ_ERROR",table,type(ex).__name__)
  try:
   from app.routers import master15_owner_mesh_sync_engine as sync
   if name=="LENOVO":
    print("STANDARD_WINDOWS_SHUTDOWN_PROOF",sync._verified_standard_shutdown(db,iid))
  except Exception as ex:print("SYNC_ENGINE_READ_ERROR",type(ex).__name__)
print("=== SERVER OWNER/WINDOWS HTTP (LAST 3H) ===")
r=subprocess.run(["journalctl","-u","multiservis-api.service","--since","3 hours ago","--no-pager","-o","cat"],capture_output=True,text=True,timeout=25)
c=collections.Counter()
pattern=re.compile(r'"(?:GET|POST) (/v1/multi-guard/(?:owner-profile-[\w-]+|discovery/[\w-]+)|/multiguard/panel/licenses-grid[^ ]*) HTTP/1\.1" (\d{3})')
for line in r.stdout.splitlines():
 m=pattern.search(line)
 if m:c[(m.group(1),m.group(2))]+=1
for (route,status),count in sorted(c.items()):print("HTTP",route,status,count)
print("=== END READ ONLY ===")
PY
