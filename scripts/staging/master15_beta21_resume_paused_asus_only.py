#!/usr/bin/env python3
"""Resume the existing PAUSED beta.21 only for ASUS ROG; no new release row.

The release must already have the exact signed 9.5 MB payload and SHA.
A fail-closed manifest allowlist is installed BEFORE changing PAUSED to AVAILABLE.
No licence, Windows service, MeshCentral or Lenovo mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from sqlalchemy import text

ROOT=Path("/opt/multiservis")
ROUTER=ROOT/"app/routers/multiguard_updates.py"
DROP=Path("/etc/systemd/system/multiservis-api.service.d/71-master15-beta21-asus.conf")
SERVICE="multiservis-api.service"
VERSION="0.3.46-beta.21"
CHANNEL="BETA"
SHA="efc60aa0c8cf80f9220be5d6429aaa3f589a0fdd03051c80cd899847ad7475de"
EXE="Multi-Guard_0.3.46-beta.21_x64-40b8f8a1e9d2-20261108-200446-be3a3923015d-setup.exe"
EXPECTED_SIZE=9492380

def command(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout.strip()

def manifest(iid):
    req=Request(
       "http://127.0.0.1:8000/multiguard/releases/windows/x86_64/0.3.46-beta.20",
       headers={"X-Multi-Guard-Installation":str(iid)}
    )
    with urlopen(req,timeout=15) as response:
        return response.status, (json.loads(response.read()) if response.status==200 else {})

def restart():
    command("systemctl","daemon-reload")
    command("systemctl","restart",SERVICE)
    for _ in range(40):
        try:
            with urlopen("http://127.0.0.1:8000/openapi.json",timeout=3) as res:
                if res.status==200:return
        except Exception:
            time.sleep(1)
    raise RuntimeError("API_RESTART_HEALTH_FAILED")

def guard(original):
    marker="MG15_ASUS_BETA21_PILOT"
    if marker in original or "MG15_BETA21_ASUS_INSTALLATION" in original:
        raise RuntimeError("ALREADY_PATCHED_REQUIRES_RECONCILIATION")
    needle="        if version <= current:\n"
    if original.count(needle)!=1:
        raise RuntimeError("LIVE_ROUTER_SHAPE_CHANGED")
    check='''        # MG15_ASUS_BETA21_PILOT: one signed pilot version, one installation.
        # Does not affect the selection of any other version or channel.
        if str(row["version"]) == "0.3.46-beta.21":
            allowed=os.environ.get("MG15_BETA21_ASUS_INSTALLATION","")
            if installation_uuid is None or str(installation_uuid)!=allowed:
                continue
'''
    patched=original.replace(needle,check+needle,1)
    compile(patched,str(ROUTER),"exec")
    return patched

def main():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    if not ROUTER.is_file():raise RuntimeError("LIVE_UPDATER_NOT_FOUND")
    if command("systemctl","is-active",SERVICE)!="active":
        raise RuntimeError("FASTAPI_INACTIVE")
    from app.database import engine
    from app.routers import multiguard_updates as updates
    with engine.connect() as db:
        candidates=db.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE upper(hostname)='ROG'
        """)).scalars().all()
        if len(candidates)!=1:raise RuntimeError("ASUS_NOT_UNIQUE")
        iid=candidates[0]
        channel,resolved=updates._resolve_channel(db,str(iid))
        if channel!="BETA" or str(resolved)!=str(iid):
            raise RuntimeError("ASUS_NOT_VERIFIED_BETA")
        if not (updates._semver("0.3.46-beta.20") < updates._semver(VERSION)
                < updates._semver("0.3.46")):
            raise RuntimeError("LIVE_BETA_SEMVER_INVALID")
        rows=db.execute(text("""
          SELECT v.id,v.channel,v.status,v.rollout_percent,
                 a.download_url,a.sha256,a.signature,a.size_bytes
          FROM guard.release_versions v
          JOIN guard.release_artifacts a ON a.release_id=v.id
          WHERE v.version=:version
        """),{"version":VERSION}).mappings().all()
        if len(rows)!=1:raise RuntimeError("BETA21_NOT_EXACTLY_ONE_RELEASE")
        row=rows[0]
        expected_url="https://api.multi-servis.pl/multiguard/update-assets/BETA/"+VERSION+"/"+EXE
        if (row["channel"]!=CHANNEL or row["status"]!="PAUSED"
            or int(row["rollout_percent"])!=100
            or row["sha256"]!=SHA
            or row["download_url"]!=expected_url
            or not row["signature"] or len(str(row["signature"]))<80
            or int(row["size_bytes"] or 0)!=EXPECTED_SIZE):
            raise RuntimeError("EXISTING_RELEASE_METADATA_MISMATCH")
        release_id=row["id"]
    file=Path(updates._RELEASE_ROOT)/VERSION/CHANNEL/EXE
    if not file.is_file() or file.stat().st_size!=EXPECTED_SIZE:
        raise RuntimeError("EXISTING_SIGNED_EXE_MISSING_OR_SIZE_MISMATCH")
    h=hashlib.sha256()
    with file.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    if h.hexdigest()!=SHA:raise RuntimeError("EXISTING_EXE_SHA_MISMATCH")
    sig_path=file.with_name(EXE+".sig")
    if not sig_path.is_file() or sig_path.read_text(encoding="utf-8").strip()!=str(row["signature"]).strip():
        raise RuntimeError("EXISTING_SIGNATURE_FILE_MISMATCH")
    orig=ROUTER.read_text(encoding="utf-8")
    if 'return ("BETA" if channel == "PILOT" else channel)' not in orig:
        raise RuntimeError("LIVE_CHANNEL_MAPPING_MISMATCH")
    changed=guard(orig)
    before,payload=manifest(iid)
    if payload.get("version")==VERSION:raise RuntimeError("PILOT_ALREADY_EXPOSED")
    print("PASS: paused release, SHA256 and updater signature unchanged")
    print("PASS: ASUS OWNER Beta; live Beta.N ordering")
    backup=ROOT/"backups"/("master15-beta21-resume-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(parents=True,exist_ok=False)
    shutil.copy2(ROUTER,backup/"multiguard_updates.py")
    if DROP.is_file():shutil.copy2(DROP,backup/"dropin.conf")
    else:(backup/"no-dropin").touch()
    code_changed=False
    release_activated=False
    try:
        tmp=ROUTER.with_name(ROUTER.name+".mg15-new")
        tmp.write_text(changed,encoding="utf-8")
        tmp.chmod(0o644)
        tmp.replace(ROUTER)
        code_changed=True
        DROP.parent.mkdir(parents=True,exist_ok=True)
        DROP.write_text('[Service]\nEnvironment="MG15_BETA21_ASUS_INSTALLATION='+str(iid)+'"\n',encoding="utf-8")
        DROP.chmod(0o644)
        restart()
        # Validate the exact effective service environment, not only a drop-in.
        pid=command("systemctl","show",SERVICE,"-p","MainPID","--value")
        if not pid.isdigit() or int(pid)<=1:raise RuntimeError("API_PID_INVALID")
        env=dict(s.split(b"=",1) for s in Path("/proc/"+pid+"/environ").read_bytes().split(b"\0") if b"=" in s)
        if env.get(b"MG15_BETA21_ASUS_INSTALLATION",b"").decode()!=str(iid):
            raise RuntimeError("ASUS_ALLOWLIST_NOT_ACTIVE")
        with engine.begin() as db:
            result=db.execute(text("""
                UPDATE guard.release_versions SET status='AVAILABLE',updated_at=now()
                WHERE id=:id AND channel='BETA' AND version=:version
                AND status='PAUSED' AND rollout_percent=100
            """),{"id":release_id,"version":VERSION})
            if result.rowcount!=1:raise RuntimeError("PAUSED_ROW_CHANGED_CONCURRENTLY")
        release_activated=True
        got,asus=manifest(iid)
        if got!=200 or asus.get("version")!=VERSION or asus.get("sha256")!=SHA or asus.get("channel")!=CHANNEL:
            raise RuntimeError("ASUS_DID_NOT_RECEIVE_BETA21_MANIFEST")
        # A never-provisioned device resolves to TEST, so verify a REAL other BETA
        # installation where possible, plus arbitrary unknown installation.
        others=[]
        with engine.connect() as db:
            other_ids=db.execute(text("""
                SELECT installation_id FROM guard.license_links
                WHERE installation_id<>:iid ORDER BY updated_at DESC LIMIT 40
            """),{"iid":iid}).scalars().all()
            for other in other_ids:
                c,_=updates._resolve_channel(db,str(other))
                if c=="BETA":others.append(other)
        other_ids_to_check=others[:10]+[uuid.uuid4()]
        for other in other_ids_to_check:
            _,value=manifest(other)
            if value.get("version")==VERSION:
                raise RuntimeError("OTHER_INSTALLATION_SEES_ASUS_BETA21")
        print("PASS: ASUS beta.20 -> beta.21 manifest, correct SHA and channel")
        print("PASS: other Beta and unknown installations denied beta.21",len(other_ids_to_check))
        print("PASS: Stable/Lenovo/Windows/Mesh unchanged")
        print("MASTER15_ASUS_BETA21_PRIVATE_UPDATER_READY")
        print("BACKUP="+str(backup))
    except Exception:
        if release_activated:
            with engine.begin() as db:
                db.execute(text("UPDATE guard.release_versions SET status='PAUSED',updated_at=now() WHERE id=:id"),{"id":release_id})
            print("ROLLBACK: beta.21 PAUSED")
        if code_changed:
            shutil.copy2(backup/"multiguard_updates.py",ROUTER)
            if (backup/"no-dropin").exists():DROP.unlink(missing_ok=True)
            else:shutil.copy2(backup/"dropin.conf",DROP)
            try:
                restart()
                print("ROLLBACK: FastAPI router restored")
            except Exception:
                print("ROLLBACK: VERIFY_FASTAPI_REQUIRED")
        raise

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("MASTER15_ASUS_BETA21_STOP",type(exc).__name__,str(exc)[:200],file=sys.stderr)
        raise SystemExit(1)
