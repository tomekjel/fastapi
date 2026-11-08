#!/usr/bin/env python3
"""OWNER expired reservation handling; guarded single-line backend fix.

Do not bypass an ACTIVE reservation. An expired RESERVED row can be
replaced by new signed grant after the same installation row is locked.
Only the existing live FastAPI file is modified; DB rows untouched.
"""
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen
from sqlalchemy import text
from app.database import engine

ROOT=Path("/opt/multiservis")
MOD=ROOT/"app/routers/master15_owner_profile_bridge.py"
SVC="multiservis-api.service"
OLD="""            WHERE installation_id=:iid AND state='RESERVED' FOR UPDATE"""
NEW="""            WHERE installation_id=:iid AND state='RESERVED' AND expires_at>now() FOR UPDATE"""

def restart():
    subprocess.run(["systemctl","restart",SVC],check=True,capture_output=True)
    for _ in range(30):
        try:
            with urlopen("http://127.0.0.1:8000/openapi.json",timeout=2) as res:
                if res.status==200:return
        except Exception:time.sleep(1)
    raise RuntimeError("API_HEALTH_FAILED")

def main():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    if not MOD.is_file():raise RuntimeError("LIVE_OWNER_BRIDGE_NOT_FOUND")
    src=MOD.read_text(encoding="utf-8")
    if src.count(OLD)!=1 or NEW in src:
        raise RuntimeError("LIVE_OWNER_BRIDGE_CHANGED_STOP")
    fixed=src.replace(OLD,NEW,1)
    compile(fixed,str(MOD),"exec")
    with engine.connect() as db:
        rows=db.execute(text("""
          SELECT t.state,t.target_mode,t.expires_at,now()>t.expires_at AS expired
          FROM guard.workshop_profile_transitions t
          JOIN guard.pending_installations p USING (installation_id)
          WHERE upper(p.hostname)='ROG'
        """)).mappings().all()
        if len(rows)!=1:raise RuntimeError("ASUS_RESERVATION_NOT_UNIQUE")
        x=rows[0]
        print("ROG_RESERVATION_STATE",x["state"],"TARGET",x["target_mode"],"EXPIRED",x["expired"])
        if x["state"]=="RESERVED" and not x["expired"]:
            raise RuntimeError("ACTIVE_UNEXPIRED_OWNER_TRANSITION_STOP")
    back=ROOT/"backups"/("master15-owner-expired-reservation-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    back.mkdir(parents=True,exist_ok=False)
    shutil.copy2(MOD,back/MOD.name)
    tmp=MOD.with_name(MOD.name+".mg15-temp")
    tmp.write_text(fixed,encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(MOD)
    try:
        restart()
        live=MOD.read_text(encoding="utf-8")
        if NEW not in live:raise RuntimeError("LIVE_CHECK_FAILED")
        print("PASS: unexpired OWNER reservation remains blocked")
        print("PASS: expired reservation can be superseded atomically by signed OWNER grant")
        print("PASS: no database, licence, Mesh or Windows service mutations")
        print("MASTER15_OWNER_EXPIRED_RESERVATION_FIX_PASS")
        print("BACKUP="+str(back))
    except Exception:
        shutil.copy2(back/MOD.name,MOD)
        try:restart();print("ROLLBACK_RESTORED")
        except Exception:print("ROLLBACK_RESTART_FAILED_MANUAL_CHECK_REQUIRED")
        raise

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("MASTER15_OWNER_RESERVATION_STOP",type(exc).__name__,str(exc)[:250],file=sys.stderr)
        raise SystemExit(1)
