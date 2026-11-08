#!/usr/bin/env python3
"""MASTER 1.5: one-ASUS-only beta.21 updater staging on LIVE Beta/Stable contract.

Run from LXC 103 as root, with GH_CONFIG_DIR for tomekjel.
NO Windows/SCM action. NO Mesh move. NO Lenovo/STABLE release.
"""
from __future__ import annotations
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from sqlalchemy import text

ROOT = Path("/opt/multiservis")
ROUTER = ROOT / "app/routers/multiguard_updates.py"
UNIT = "multiservis-api.service"
DROP = Path("/etc/systemd/system/multiservis-api.service.d/71-master15-beta21-asus.conf")
VERSION = "0.3.46-beta.21"
TAG = "v0.3.46-beta.21-ASUS-PRIVATE"
EXE = "Multi-Guard_0.3.46-beta.21_x64-40b8f8a1e9d2-20261108-200446-be3a3923015d-setup.exe"
SHA = "efc60aa0c8cf80f9220be5d6429aaa3f589a0fdd03051c80cd899847ad7475de"
BACKUP = ROOT / "backups" / ("master15-beta21-asus-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))

def run(*args: str) -> str:
    result = subprocess.run(list(args), check=True, text=True, capture_output=True)
    return result.stdout.strip()

def restart_api():
    run("systemctl","daemon-reload")
    run("systemctl","restart",UNIT)
    for _ in range(40):
        try:
            with urlopen("http://127.0.0.1:8000/openapi.json",timeout=2) as response:
                if response.status==200: return
        except Exception:
            time.sleep(1)
    raise RuntimeError("API_NOT_HEALTHY")

def read_manifest(iid: str) -> tuple[int,dict]:
    request=Request(
        "http://127.0.0.1:8000/multiguard/releases/windows/x86_64/0.3.46-beta.20",
        headers={"X-Multi-Guard-Installation":iid}
    )
    with urlopen(request,timeout=10) as response:
        code=response.status
        return code,json.loads(response.read()) if code==200 else {}

def patch_router(original: str) -> str:
    """The live server ALREADY has correct Beta.N SemVer and PILOT->BETA.

    Install only the one-device manifest guard. Refuse older/stale code,
    preventing accidental downgrade or a new global update policy.
    """
    if "MG15_BETA21_ASUS_INSTALLATION" in original:
        raise RuntimeError("PILOT_ALREADY_PATCHED_STOP")
    match='        if version <= current:\n'
    if original.count(match)!=1:
        raise RuntimeError("UNEXPECTED_PRODUCTION_RELEASE_LOOP")
    check='''        # MG15_ASUS_BETA21_PILOT: restrict this private version to the
        # exact OWNER installation. Other Stable/Beta updates are unaffected.
        if str(row["version"]) == "0.3.46-beta.21":
            allowed=os.environ.get("MG15_BETA21_ASUS_INSTALLATION","")
            if installation_uuid is None or str(installation_uuid)!=allowed:
                continue
'''
    patched=original.replace(match,check+match,1)
    compile(patched,str(ROUTER),"exec")
    return patched

def main() -> None:
    if os.geteuid()!=0:
        raise RuntimeError("ROOT_REQUIRED")
    if not ROUTER.is_file():
        raise RuntimeError("PRODUCTION_UPDATER_ROUTER_MISSING")
    if not run("systemctl","is-active",UNIT)=="active":
        raise RuntimeError("FASTAPI_NOT_ACTIVE")
    ROOT.mkdir(exist_ok=True)
    from app.database import engine
    from app.routers import multiguard_updates as current_updates

    with engine.connect() as db:
        candidates=db.execute(text("""
          SELECT installation_id FROM guard.pending_installations
          WHERE upper(hostname)='ROG'
        """)).scalars().all()
        if len(candidates)!=1:
            raise RuntimeError("ASUS_NOT_UNIQUE")
        iid=candidates[0]
        channel,_=current_updates._resolve_channel(db,str(iid))
        if channel != "BETA":
            raise RuntimeError("ASUS_NOT_BETA_IN_LIVE_UPDATER")
        # Production source of truth: OWNER PILOT is represented as BETA by\n        # the live updater. Never mutate edition or the selected channel.\n        if not (current_updates._semver("0.3.46-beta.20")\n                < current_updates._semver("0.3.46-beta.21")\n                < current_updates._semver("0.3.46")):\n            raise RuntimeError("LIVE_SEMVER_NOT_CORRECT")\n        print("PASS: live Beta.N SemVer and OWNER->BETA routing")\n        existing=db.execute(text("""
          SELECT id FROM guard.release_versions WHERE channel=:channel AND version=:version
        """),{"channel":channel,"version":VERSION}).scalar_one_or_none()
        if existing is not None:
            raise RuntimeError("BETA21_RELEASE_ALREADY_EXISTS")
    try:
        previous,previous_data=read_manifest(str(iid))
        print("CURRENT_ASUS_UPDATER_HTTP",previous)
    except Exception as exc:
        raise RuntimeError("CURRENT_UPDATER_NOT_AVAILABLE") from exc

    original=ROUTER.read_text(encoding="utf-8")\n    if "return (\"BETA\" if channel == \"PILOT\" else channel)" not in original:\n        raise RuntimeError("LIVE_BETA_MAPPING_CHANGED")
    patched=patch_router(original)
    BACKUP.mkdir(parents=True,exist_ok=False)
    shutil.copy2(ROUTER,BACKUP/"multiguard_updates.py")
    DROP.parent.mkdir(parents=True,exist_ok=True)
    if DROP.is_file():
        shutil.copy2(DROP,BACKUP/"systemd-dropin.conf")
    else:
        (BACKUP/"no-dropin").touch()

    # Download the two immutable, SHA-pinned private GitHub assets.
    print("=== DOWNLOAD EXACT PRIVATE ASUS BUILD ===")
    with tempfile.TemporaryDirectory(prefix="mg15-asus-beta21-") as d:
        run("gh","release","download",TAG,"--repo","tomekjel/multi-guard",
            "--pattern",EXE,"--pattern",EXE+".sig","--dir",d)
        exe=Path(d)/EXE
        sig=Path(d)/(EXE+".sig")
        if not exe.is_file() or not sig.is_file():
            raise RuntimeError("PRIVATE_ASSETS_INCOMPLETE")
        actual=hashlib.sha256(exe.read_bytes()).hexdigest()
        if actual!=SHA:
            raise RuntimeError("PRIVATE_ASSET_SHA256_MISMATCH")
        signature=sig.read_text(encoding="utf-8").strip()
        if len(signature)<80:
            raise RuntimeError("PRIVATE_UPDATER_SIGNATURE_MISSING")

        release_dir=Path(current_updates._RELEASE_ROOT)/VERSION/channel
        release_dir.mkdir(parents=True,exist_ok=True)
        target=release_dir/EXE
        if target.exists():
            raise RuntimeError("ASSET_ALREADY_PRESENT_STOP")
        shutil.copy2(exe,target)
        shutil.copy2(sig,release_dir/(EXE+".sig"))
        if hashlib.sha256(target.read_bytes()).hexdigest()!=SHA:
            raise RuntimeError("COPIED_SHA_MISMATCH")
        size=target.stat().st_size
    print("PASS: ASUS private assets SHA256 and updater signature")
    changed=False
    created=False
    release_id=None
    try:
        tmp=ROUTER.with_suffix(".py.mg15-new")
        tmp.write_text(patched,encoding="utf-8")
        os.chmod(tmp,0o644)
        tmp.replace(ROUTER)
        changed=True
        DROP.write_text(
            '[Service]\nEnvironment="MG15_BETA21_ASUS_INSTALLATION='+str(iid)+'"\n',
            encoding="utf-8"
        )
        os.chmod(DROP,0o644)
        restart_api()
        print("PASS: protected one-ASUS filter active in FastAPI")
        # Commit as AVAILABLE only after the live service has its allowlist.
        with engine.begin() as db:
            release_id=db.execute(text("""
              INSERT INTO guard.release_versions(
                version,channel,status,notes,rollout_percent,force_install,rollback_safe,published_at
              ) VALUES(
                :version,:channel,'AVAILABLE',
                'MASTER 1.5 ASUS only, Standard agent-disabled acknowledgement',
                100,FALSE,FALSE,now()
              ) RETURNING id
            """),{"version":VERSION,"channel":channel}).scalar_one()
            db.execute(text("""
              INSERT INTO guard.release_artifacts(
                release_id,target,arch,bundle_type,download_url,signature,sha256,size_bytes
              ) VALUES(
                :rid,'windows','x86_64','nsis',:url,:sig,:sha,:size
              )
            """),{
                "rid":release_id,
                "url":"https://api.multi-servis.pl/multiguard/update-assets/"+channel+"/"+VERSION+"/"+EXE,
                "sig":signature,"sha":SHA,"size":size,
            })
        created=True
        ok,payload=read_manifest(str(iid))
        if ok!=200 or payload.get("version")!=VERSION or payload.get("sha256")!=SHA:
            raise RuntimeError("ASUS_MANIFEST_INCORRECT")
        if payload.get("channel")!=channel:
            raise RuntimeError("ASUS_RELEASE_CHANNEL_MISMATCH")
        other_status,other_payload=read_manifest(str(uuid.uuid4()))
        if other_payload.get("version")==VERSION:
            raise RuntimeError("PRIVATE_RELEASE_VISIBLE_TO_OTHER_INSTALLATIONS")
        print("PASS: ASUS beta.20 sees beta.21 with signed SHA256")
        print("PASS: unknown/other device does not see beta.21")
        print("PASS: no remote access, Windows SCM, or Mesh group mutations")
        print("MASTER15_ASUS_BETA21_PRIVATE_UPDATER_READY")
        print("BACKUP="+str(BACKUP))
    except Exception:
        if created and release_id:
            with engine.begin() as db:
                db.execute(text("""
                    UPDATE guard.release_versions SET status='PAUSED'
                    WHERE id=:rid
                """),{"rid":release_id})
        if changed:
            shutil.copy2(BACKUP/"multiguard_updates.py",ROUTER)
            if (BACKUP/"no-dropin").exists():
                DROP.unlink(missing_ok=True)
            else:
                shutil.copy2(BACKUP/"systemd-dropin.conf",DROP)
            try:
                restart_api()
                print("ROLLBACK: prior FastAPI restored")
            except Exception:
                print("ROLLBACK: restart requires inspection")
        raise

if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print("MASTER15_ASUS_BETA21_STOP",type(exc).__name__,str(exc)[:180],file=sys.stderr)
        raise SystemExit(1)
