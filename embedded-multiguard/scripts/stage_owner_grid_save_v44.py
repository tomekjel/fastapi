#!/usr/bin/env python3
"""Guarded backend-only OWNER Save upgrade on known V4.4 production.

Never overwrites the grid HTML/CSS, key or licensing records. Compares the
live Save/extension functions to a pinned known base by parsed syntax.
An unexpected local change aborts before writing anything. New paid/service
term mutations remain explicitly disabled by default, independent of this
installation; production mode-switch remains permanently hard-stopped at
its separate route while additional integration work is unfinished.
"""
from __future__ import annotations
import argparse, ast, copy, difflib, hashlib, os, shutil
import subprocess, tempfile, time, urllib.error, urllib.request
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path("/opt/multiservis")
ROUTERS=ROOT/"app/routers"
LICENSE=ROUTERS/"multiguard_license.py"
POLICY=ROUTERS/"multiguard_entitlement_modes.py"
THEME=ROUTERS/"multiguard_panel_theme.py"
OLD_SOURCE_COMMIT="82192cb6fb7ecfe6a3dffc2afbb417510e2dc04b"
OLD_SOURCE_BLOB="e1f191e52e763626b5f99565329a8eba9aa93ea3"
NEW_SOURCE_COMMIT="959af04086e59fe2d0057affddf2c13046cb13e0"
NEW_SOURCE_BLOB="3d6cd74897ba5a426dafb3a89dbb833f3d4e7ba2"
OLD_POLICY_BLOB="986a113ce82ccb1b094bcef7ba27d22b36d7011c"
NEW_POLICY_BLOB="295b46f5d116ccf910da8a12f6cc0d722392c6b7"
POLICY_COMMIT="4a5de60495457abbb533c4915e507c5244476569"
THEME_SHA256="0e63d2c54ddb5036237aa2ba53ca4c73e71aa86e23c24280e1001dddd1d778d7"

def gitblob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def fetch(commit,file,sha):
    url=("https://raw.githubusercontent.com/tomekjel/fastapi/"+commit+
         "/embedded-multiguard/app/routers/"+file)
    with urllib.request.urlopen(url,timeout=25) as r:
        data=r.read()
    if gitblob(data)!=sha:
        raise RuntimeError("Pinned source changed: "+file)
    return data.decode("utf-8")

def node(src,name):
    matches=[x for x in ast.parse(src).body
             if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))
             and x.name==name]
    if len(matches)!=1:
        raise RuntimeError(f"Expected exactly one function {name}; got {len(matches)}")
    return matches[0]

def canon(src,name):
    x=copy.deepcopy(node(src,name))
    x.name="CANONICAL_OWNER_FUNCTION"
    x.decorator_list=[]
    return ast.dump(x,include_attributes=False)

def body(src,name):
    n=node(src,name)
    return "".join(src.splitlines(keepends=True)[n.lineno-1:n.end_lineno])

def replace(src,name,text):
    n=node(src,name)
    rows=src.splitlines(keepends=True)
    return "".join(rows[:n.lineno-1])+text.rstrip()+"\n"+"".join(rows[n.end_lineno:])

def compare_or_abort(actual,canonical,actual_name,reference_name):
    if canon(actual,actual_name)==canon(canonical,reference_name):
        return
    local=body(actual,actual_name).splitlines()
    pinned=body(canonical,reference_name).splitlines()
    if local:
        local[0]=local[0].replace(actual_name,"OWNER_FUNCTION")
    if pinned:
        pinned[0]=pinned[0].replace(reference_name,"OWNER_FUNCTION")
    print("NON-MATCHING PRODUCTION FUNCTION:",actual_name)
    print("LOCAL LENGTH:",len(local),"KNOWN BASE LENGTH:",len(pinned))
    print("LOCAL SHA256:",hashlib.sha256("\n".join(local).encode()).hexdigest())
    print("KNOWN SHA256:",hashlib.sha256("\n".join(pinned).encode()).hexdigest())
    diff=difflib.unified_diff(pinned,local,fromfile="pinned-base",tofile="live-V4.4")
    for index,line in enumerate(diff):
        if index>=90:
            print("DIFF TRUNCATED: 90 LINES")
            break
        print(line)
    raise RuntimeError("V4.4 Save differs from pinned base: no files changed")

def prepare(live,old,new):
    compare_or_abort(live,old,"panel_grid_save_row","panel_grid_save")
    compare_or_abort(live,old,"_extend_active_license","_extend_active_license")
    upgraded=body(new,"panel_grid_save").replace(
        "def panel_grid_save(", "def panel_grid_save_row(",1)
    # This is an exact function-only splice; all existing decorators, grid
    # rendering, safe delete, sidebar, KeyGate and Mesh paths are untouched.
    combined=replace(live,"panel_grid_save_row",upgraded)
    combined=replace(combined,"_extend_active_license",
                     body(new,"_extend_active_license"))
    compile(combined,str(LICENSE),"exec")
    for protected in ("panel_licenses_grid","panel_grid_archive_license_safe",
                      "panel_revoke_license","panel_grid_save_name",
                      "panel_grid_save_channel","panel_grid_extend_license"):
        before_names={x.name for x in ast.parse(live).body
                      if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
        after_names={x.name for x in ast.parse(combined).body
                     if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))}
        if (protected in before_names)!=(protected in after_names):
            raise RuntimeError("Protected V4.4 function inserted/removed: "+protected)
        if protected in before_names and canon(live,protected)!=canon(combined,protected):
            raise RuntimeError("Unexpected modified V4.4 function: "+protected)
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in combined:
        raise RuntimeError("Stage2 mode-switch lock not preserved")
    return combined

def status():
    req=urllib.request.Request(
        "https://api.multi-servis.pl/multiguard/panel/licenses-grid",
        headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as r:return r.status
    except urllib.error.HTTPError as e:return e.code

def no_open_sessions():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as c:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            if c.execute(text("SELECT to_regclass(:t)"),{"t":table}).scalar_one_or_none() is None:
                continue
            opened=c.execute(text("SELECT count(*) FROM "+table+
                    " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')")).scalar_one()
            if opened:raise RuntimeError(f"Live sessions in {table}: {opened}; no restart")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--apply",action="store_true")
    args=p.parse_args()
    if hashlib.sha256(THEME.read_bytes()).hexdigest()!=THEME_SHA256:
        raise RuntimeError("V4.4 sidebar theme not pinned; abort")
    current=LICENSE.read_text()
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in current:
        raise RuntimeError("Stage2 OWNER mode switch lock missing")
    old=fetch(OLD_SOURCE_COMMIT,"multiguard_license.py",OLD_SOURCE_BLOB)
    new=fetch(NEW_SOURCE_COMMIT,"multiguard_license.py",NEW_SOURCE_BLOB)
    policy_source=fetch(POLICY_COMMIT,"multiguard_entitlement_modes.py",NEW_POLICY_BLOB)
    if gitblob(POLICY.read_bytes())!=OLD_POLICY_BLOB:
        raise RuntimeError("Live term policy version unexpected; abort")
    changed=prepare(current,old,new)
    compile(policy_source,str(POLICY),"exec")
    before=status()
    if before not in (401,403):
        raise RuntimeError(f"OWNER panel baseline changed: {before}")
    print("GRID SAVE V4.4: FUNCTION SHAPE PASS")
    print("PAID EXTENSION + STALE EXPIRY: PREPARED")
    print("CLIENT PAID / OWNER SERVICE: SEPARATE")
    print("V4.4 GRID HTML / CSS: ORIGINAL, UNCHANGED")
    print("OWNER MODE SWITCH: HARD DISABLED")
    print("PAID PERPETUAL: UNAVAILABLE WITHOUT KEYGATE SUPPORT")
    if not args.apply:
        print("DRY RUN: NO CHANGES")
        return

    # This installs only dormant backend capabilities. The two independent
    # feature flags must both be explicitly enabled later in a separate step.
    for name in ("MULTIGUARD_OWNER_GRID_PAID_TERM_ENABLED",
                 "MULTIGUARD_OWNER_GRID_SERVICE_ENABLED"):
        if os.getenv(name,"false").lower() in ("true","1","yes"):
            raise RuntimeError("Grid mutation flag is already enabled: "+name)
    no_open_sessions()
    backup=ROOT/("backup-mg-owner-save-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(LICENSE,backup/LICENSE.name)
    shutil.copy2(POLICY,backup/POLICY.name)
    written=False
    try:
        for path,bytes_ in ((LICENSE,changed.encode()),(POLICY,policy_source.encode())):
            fd,tmp=tempfile.mkstemp(prefix=".mg-owner-save-",dir=ROUTERS)
            try:
                with os.fdopen(fd,"wb") as w:w.write(bytes_)
                os.chmod(tmp,0o644)
                os.replace(tmp,path)
                written=True
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],timeout=40,check=True)
        for attempt in range(14):
            active=subprocess.run(
                ["systemctl","is-active","--quiet","multiservis-api.service"],
                check=False,timeout=8).returncode==0
            if active and status()==before:break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI health verification failed")
        print("OWNER GRID SAVE BACKEND: INSTALLED (FLAGS OFF)")
        print("KEYGATE / MESH / LICENCE ROWS: UNCHANGED")
        print("V4.4 GRID: UNCHANGED")
        print("BACKUP:",backup)
    except Exception:
        if written:
            shutil.copy2(backup/LICENSE.name,LICENSE)
            shutil.copy2(backup/POLICY.name,POLICY)
            subprocess.run(["systemctl","restart","multiservis-api.service"],timeout=40,check=False)
        raise

if __name__=="__main__":
    main()
