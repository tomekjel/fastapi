#!/usr/bin/env bash
# Read-only live MeshCentral discovery; do not print credentials, device IDs or tokens.
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import os,subprocess,json,sys
from pathlib import Path
# Read service's existing environment without printing secrets; same config as production.
pidtext=subprocess.check_output(["systemctl","show","--property=MainPID","--value","multiservis-api.service"],text=True).strip()
pid=int(pidtext)
if pid<=0: raise SystemExit("STOP: FastAPI service not running")
env={}
for pair in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
    if b"=" in pair:
        k,v=pair.split(b"=",1)
        env[k.decode("utf-8","replace")]=v.decode("utf-8","replace")
os.environ.update(env)
print("=== CONFIG PRESENT (NO VALUES) ===")
for k in ("MESH_CENTRAL_SESSION_CONSENT_MESH_ID","MESH_SERVICE_PRO_GROUP_ID",
          "MESH_CENTRAL_MESHCTRL_PATH","MESH_CENTRAL_URL","MESH_CENTRAL_LOGIN_USER",
          "MESH_CENTRAL_LOGIN_KEY_FILE","MESH_CENTRAL_LOGIN_PASS"):
    print(k+":", "SET" if os.environ.get(k,"").strip() else "MISSING")
print("=== LIVE MESHCTRL READ-ONLY ===")
from app.routers import multiguard_meshcentral as mc
cmd=mc._base_command()
if cmd.count("DeviceSharing")!=1: raise SystemExit("STOP: unexpected MeshCtrl command")
cmd[cmd.index("DeviceSharing")]="ListDevices"
cmd += ["--json"]
try:
    out=mc._run(cmd)
except Exception as exc:
    # Avoid leaking output which could contain sensitive CLI arguments
    print("LISTDEVICES_FAILED:",type(exc).__name__)
    raise SystemExit(2)
try:
    data=json.loads(out)
except ValueError:
    print("LISTDEVICES_UNEXPECTED_JSON")
    raise SystemExit(2)
if isinstance(data,list):
    records=data
    print("JSON_TOP_LEVEL: list")
elif isinstance(data,dict):
    print("JSON_TOP_LEVEL_KEYS:",sorted(data)[:16])
    records=next((v for v in data.values() if isinstance(v,list)),[])
else:
    raise SystemExit("LISTDEVICES_UNEXPECTED_TYPE")
print("RECORD_COUNT:",len(records))
if records and isinstance(records[0],dict):
    print("RECORD_FIELDS:",sorted(records[0].keys()))
    print("GROUP_RELATED_FIELDS:",
          sorted(k for k in records[0] if any(x in k.lower() for x in ("mesh","group","node","device"))))
print("=== READONLY_DONE ===")
PY
