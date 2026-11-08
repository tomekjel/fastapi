#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import hashlib
import os
import subprocess
from pathlib import Path
from uuid import uuid4
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_updates as updates
print("=== MASTER 1.5 / EXISTING BETA21 / READ ONLY ===")
with engine.connect() as db:
  ids=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).scalars().all()
  if len(ids)!=1: raise SystemExit("STOP: ASUS_NOT_UNIQUE")
  iid=ids[0]
  channel,_=updates._resolve_channel(db,str(iid))
  print("ASUS_CHANNEL:",channel)
  rows=db.execute(text("""
    SELECT v.id,v.version,v.channel,v.status,v.rollout_percent,
           a.download_url,a.sha256,a.signature,a.size_bytes
    FROM guard.release_versions v
    LEFT JOIN guard.release_artifacts a ON a.release_id=v.id
    WHERE v.version='0.3.46-beta.21'
    ORDER BY v.channel
  """)).mappings().all()
  print("RELEASE_ROWS:",len(rows))
  for x in rows:
    print("RELEASE:",x['channel'],x['status'],"rollout",x['rollout_percent'],
          "artifact",bool(x['download_url']),"sha",x['sha256'],
          "signature",bool(x['signature']),"size",x['size_bytes'])
    if x['channel']=='BETA' and x['download_url']:
      filename=x['download_url'].rsplit('/',1)[-1]
      file=Path(updates._RELEASE_ROOT)/x['version']/x['channel']/filename
      print("BETA_ASSET_PRESENT:",file.is_file())
      if file.is_file():
        print("BETA_ASSET_SHA_MATCH:",hashlib.sha256(file.read_bytes()).hexdigest()==x['sha256'])
pid=subprocess.check_output(['systemctl','show','multiservis-api.service','-p','MainPID','--value'],text=True).strip()
if not pid.isdigit() or int(pid)<2:raise SystemExit("STOP: NO_API_PID")
settings=dict(entry.split(b'=',1) for entry in Path('/proc/'+pid+'/environ').read_bytes().split(b'\x00') if b'=' in entry)
allow=settings.get(b'MG15_BETA21_ASUS_INSTALLATION',b'').decode()
print("API_ASUS_ONLY_ENV_PRESENT:",bool(allow))
print("API_ASUS_ONLY_ENV_MATCH:",allow==str(iid))
print("ASUS_ONLY_CODE_PRESENT:","MG15_ASUS_BETA21_PILOT" in Path(updates.__file__).read_text(encoding='utf-8'))
def manifest(installation):
  url="http://127.0.0.1:8000/multiguard/releases/windows/x86_64/0.3.46-beta.20"
  try:
    with urlopen(Request(url,headers={"X-Multi-Guard-Installation":str(installation)}),timeout=12) as res:
      import json
      return res.status,(json.loads(res.read()) if res.status==200 else {})
  except HTTPError as ex: return ex.code,{}
for label,id in [('ASUS',iid),('UNKNOWN',uuid4())]:
  code,value=manifest(id)
  print(label+"_MANIFEST_HTTP:",code,"VERSION:",value.get('version','NONE'),"CHANNEL:",value.get('channel','NONE'))
print("=== READ ONLY COMPLETE ===")
PY
