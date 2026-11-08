#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import ast, os, json, subprocess
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mc
from app.routers import multiguard_license as lic

print("=== OWNER CSRF CHECK SOURCE (REDACTED) ===")
p=Path("/opt/multiservis/app/routers/multiguard_license.py")
src=p.read_text().splitlines()
for begin,end in ((5890,5917),(6150,6160)):
  for n in range(begin,end+1):
    line=src[n-1]
    if any(k in line.lower() for k in ("password","secret","auth_key")):
      line="[REDACTED]"
    print(f"{n}: {line[:250]}")
print("=== OWNER WORKSHOP CSRF SIGNATURE ===")
import inspect
for name in ("_workshop_csrf","_panel_auth","_panel_csrf","_panel_token"):
  f=getattr(lic,name,None)
  if f is not None:
    print(name,inspect.signature(f))
print("=== MESH CLI MOVE SYNTAX READONLY ===")
pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip())
if pid>0:
  for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
      k,v=pair.split(b"=",1)
      os.environ[k.decode("utf8","replace")]=v.decode("utf8","replace")
with engine.connect() as db:
  r=db.execute(text("""SELECT s.target_mesh_id,s.observed_mesh_id,n.mesh_node_id
      FROM guard.owner_mesh_group_sync s
      LEFT JOIN guard.workshop_mesh_nodes n ON n.installation_id=s.installation_id
      ORDER BY s.updated_at DESC LIMIT 1""")).mappings().first()
  if r:
    for key,prefix in (("mesh_node_id","node"),("target_mesh_id","mesh")):
      try:
        mc._auto_mesh_identifier(r[key],prefix)
        print(key+": VALID")
      except Exception as exc:
        print(key+": INVALID "+type(exc).__name__)
    print("target_is_service:",r["target_mesh_id"]==os.getenv("MESH_SERVICE_PRO_GROUP_ID","").strip())
    print("observed_is_target:",r["observed_mesh_id"]==r["target_mesh_id"])
for name in ("MoveToDeviceGroup","ListDevices"):
  try:
    cmd=mc._auto_mesh_command(name) if name=="MoveToDeviceGroup" else mc._base_command()
    print(name+"_builder: PASS")
  except Exception as exc:
    print(name+"_builder:",type(exc).__name__)
print("=== DIAGNOSTIC COMPLETE ===")
PY
