#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import os, pathlib, subprocess
from uuid import UUID
from sqlalchemy import text
from fastapi import HTTPException

print("=== MASTER110 ASUS DELETE — KEYGATE FROM LIVE SERVICE ENV (READ ONLY) ===")
result=subprocess.run(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True,capture_output=True,check=True)
pid=result.stdout.strip()
if not pid.isdigit() or int(pid)<=0:
    raise SystemExit("STOP: FASTAPI_MAIN_PID_NOT_FOUND")
raw=(pathlib.Path("/proc")/pid/"environ").read_bytes()
env={}
for item in raw.split(b"\x00"):
    if b"=" in item:
        k,v=item.split(b"=",1)
        env[k.decode(errors="replace")]=v.decode(errors="replace")
name="MULTIGUARD_KEYGATE_LICENSES_TOKEN"
if not env.get(name):
    raise SystemExit("STOP: LIVE_FASTAPI_TOKEN_MISSING")
# Same token as real service; only this transient process sees it.
# NEVER print token, request authorization headers, upstream response body.
os.environ[name]=env[name]
if env.get("MULTIGUARD_KEYGATE_BASE_URL"):
    os.environ["MULTIGUARD_KEYGATE_BASE_URL"]=env["MULTIGUARD_KEYGATE_BASE_URL"]
if env.get("MULTIGUARD_CONFIG_FILE"):
    os.environ["MULTIGUARD_CONFIG_FILE"]=env["MULTIGUARD_CONFIG_FILE"]
print("PASS: LIVE_SERVICE_TOKEN_LOADED_IN_TRANSIENT_PROCESS (REDACTED)")
from app.database import engine
from app.routers import multiguard_license as lic
old=UUID("a29b7aba-fb1f-48cb-8f22-3eadc2aa4727")
active=UUID("d521b000-5351-4026-aca0-d5e8ca373849")
with engine.connect() as db:
    rows=db.execute(text("""
       SELECT l.id,l.lifecycle,l.keygate_license_id,l.installation_id,p.hostname
       FROM guard.license_links l JOIN guard.pending_installations p
       ON p.installation_id=l.installation_id
       WHERE l.id IN (:old,:active)
    """),{"old":old,"active":active}).mappings().all()
assert len(rows)==2 and all(r["hostname"]=="ROG" for r in rows), "STOP: WRONG_DEVICE_SET"
assert next(r for r in rows if r["id"]==old)["lifecycle"]=="REVOKED", "STOP: OLD_LICENSE_CHANGED"
assert next(r for r in rows if r["id"]==active)["lifecycle"]=="ACTIVE", "STOP: CURRENT_LICENSE_CHANGED"
for r in rows:
    label="OLD_REVOKED" if r["id"]==old else "CURRENT_ACTIVE"
    try:
        obj=lic._keygate_license(str(r["keygate_license_id"]))
        print(label,"KEYGATE_STATUS",str(obj.get("status","UNKNOWN")).upper() if isinstance(obj,dict) else "BAD_RESPONSE_TYPE")
    except HTTPException as exc:
        # Error body may contain internal infrastructure details: suppress it.
        print(label,"KEYGATE_HTTP",exc.status_code,"ERROR_BODY_REDACTED")
    except Exception as exc:
        print(label,"KEYGATE_ERROR",type(exc).__name__)
print("=== END READ ONLY — NO REVOKE, NO DELETE, NO MESH MOVE ===")
PY
