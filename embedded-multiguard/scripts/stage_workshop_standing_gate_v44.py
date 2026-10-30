#!/usr/bin/env python3
"""Fail-closed V4.4 unattended-service gate deployment.

Patches only 3 audited workshop module functions. Does not touch the OWNER
panel, sidebar, licence/KeyGate records, paid remote route, or Mesh config.
The original 3 functions MUST match their pinned GitHub AST exactly.
"""
from __future__ import annotations
import argparse
import ast
import copy
from datetime import datetime,timezone
import difflib
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path("/opt/multiservis")
ROUTERS=ROOT/"app/routers"
PROD=ROUTERS/"multiguard_workshop_remote.py"
LICENSE=ROUTERS/"multiguard_license.py"
THEME=ROUTERS/"multiguard_panel_theme.py"
OLD_COMMIT="6bb140972c50265ef551218aa6d3748274ead1e5"
NEW_COMMIT="12010d0913043ae4937a70d6e8b1a12d944d27e0"
OLD_GITBLOB="f6e490a60194025eaf5a94fa2a1994703d23002f"
NEW_GITBLOB="0b81780f6af50d5d8a3cc84bb94b19e6e8fe4c1a"
TARGETS=(
    "standing_authorization_record",
    "request_for_owner",
    "connect_for_owner",
)
PROTECTED_STATUS="https://api.multi-servis.pl/multiguard/panel/licenses-grid"

def git_blob(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def download(commit, expected):
    url=("https://raw.githubusercontent.com/tomekjel/fastapi/"+commit+
         "/embedded-multiguard/app/routers/multiguard_workshop_remote.py")
    with urllib.request.urlopen(url,timeout=25) as response:
        raw=response.read()
    if git_blob(raw)!=expected:
        raise RuntimeError("Pinned workshop source checksum mismatch")
    return raw.decode("utf-8")

def function_nodes(src):
    return {
        n.name:n for n in ast.parse(src).body
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
    }

def body(src,name):
    n=function_nodes(src).get(name)
    if n is None:
        raise RuntimeError("Missing workshop function "+name)
    lines=src.splitlines(keepends=True)
    return "".join(lines[n.lineno-1:n.end_lineno])

def ast_fingerprint(src,name):
    n=function_nodes(src).get(name)
    if n is None:
        raise RuntimeError("Missing audited function "+name)
    normalized=copy.deepcopy(n)
    normalized.decorator_list=[]
    return ast.dump(normalized,include_attributes=False)

def substitute(src,name,new_body):
    n=function_nodes(src).get(name)
    if n is None or n.decorator_list:
        raise RuntimeError("Unexpected workshop function decorators: "+name)
    lines=src.splitlines(keepends=True)
    return "".join(lines[:n.lineno-1])+new_body.rstrip()+"\n"+"".join(lines[n.end_lineno:])

def preview_mismatch(original,actual,name):
    before=body(original,name).splitlines()
    after=body(actual,name).splitlines()
    print("PRODUCTION FUNCTION DIFFERS:",name)
    print("PINNED LINES:",len(before),"LIVE LINES:",len(after))
    print("LIVE SHA256:",hashlib.sha256("\n".join(after).encode()).hexdigest())
    for i,line in enumerate(difflib.unified_diff(
            before,after,fromfile="pinned-expected",tofile="live-V4.4")):
        if i>=80:
            print("DIFF TRUNCATED")
            break
        print(line)
    raise RuntimeError("Unrecognized production function: abort before writes")

def overlay(live,original,updated):
    for name in TARGETS:
        if ast_fingerprint(live,name)!=ast_fingerprint(original,name):
            preview_mismatch(original,live,name)
    changed=live
    for name in TARGETS:
        changed=substitute(changed,name,body(updated,name))
    before=function_nodes(live)
    after=function_nodes(changed)
    if set(before)!=set(after):
        raise RuntimeError("Workshop function set changed")
    for name in set(before)-set(TARGETS):
        if ast_fingerprint(live,name)!=ast_fingerprint(changed,name):
            raise RuntimeError("Unexpected change to workshop code: "+name)
    compile(changed,str(PROD),"exec")
    for marker in (
        "standing_authorization_record_valid(grant, standing)",
        "standing_authorization_record(db, iid, lock=True)",
        "scope = standing[\"device_scope\"]",
        "standing_authorization_record_valid(grant, renewed)",
        "meshcentral.revoke_share(node,share.public_id)",
    ):
        if marker not in changed:
            raise RuntimeError("Expected mandatory service gate missing: "+marker)
    return changed

def panel_status():
    request=urllib.request.Request(
        PROTECTED_STATUS,headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(request,timeout=8) as result:
            return result.status
    except urllib.error.HTTPError as err:
        return err.code

def ensure_no_open_remote_sessions():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as db:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            exists=db.execute(text("SELECT to_regclass(:table)"),
                              {"table":table}).scalar_one_or_none()
            if exists is None:
                continue
            active=db.execute(text(
                "SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
                " OR mesh_public_id IS NOT NULL"
            )).scalar_one()
            if active:
                raise RuntimeError("Active/unrevoked shares prevent deployment: "+
                                   table+" "+str(active))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    if not PROD.is_file():
        raise RuntimeError("Production workshop module missing")
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in LICENSE.read_text():
        raise RuntimeError("OWNER selected-mode hard stop missing")
    original=download(OLD_COMMIT,OLD_GITBLOB)
    updated=download(NEW_COMMIT,NEW_GITBLOB)
    live=PROD.read_text()
    changed=overlay(live,original,updated)
    before=panel_status()
    if before not in (401,403):
        raise RuntimeError("Protected OWNER panel response unexpected: "+str(before))
    print("V4.4 WORKSHOP SOURCE: MATCHED PINNED AUDITED FUNCTIONS")
    print("OWNER + DEVICE OPT-IN: MANDATORY BEFORE UNATTENDED SESSION")
    print("FINAL SHARE: FOR SHARE AUTHORIZATION LOCK")
    print("CUSTOMER CONSENT: UNCHANGED")
    print("V4.4 / KEYGATE / LICENCE RECORDS / MESH CONFIG: UNCHANGED")
    if not args.apply:
        print("WORKSHOP CONSENT PREFLIGHT: PASS (DRY RUN)")
        return
    ensure_no_open_remote_sessions()
    backup=ROOT/("backup-mg-standing-consent-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700,exist_ok=False)
    shutil.copy2(PROD,backup/PROD.name)
    modified=False
    try:
        fd,temp=tempfile.mkstemp(prefix=".mg-standing-",dir=ROUTERS)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as out:
                out.write(changed)
            os.chmod(temp,0o644)
            os.replace(temp,PROD)
            modified=True
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],
                       check=True,timeout=45)
        for attempt in range(15):
            active=subprocess.run(
                ["systemctl","is-active","--quiet","multiservis-api.service"],
                check=False,timeout=8).returncode==0
            if active and panel_status()==before:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI or OWNER access changed")
        print("STANDING CONSENT GATE: APPLIED")
        print("OWNER + DEVICE CONSENT: REQUIRED")
        print("V4.4 / KEYGATE / MESH / LICENCE ROWS: UNCHANGED")
        print("BACKUP:",backup)
    except Exception:
        if modified:
            shutil.copy2(backup/PROD.name,PROD)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
