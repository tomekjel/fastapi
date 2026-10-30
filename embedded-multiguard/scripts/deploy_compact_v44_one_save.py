#!/usr/bin/env python3
"""Deploy compact V4.4 date popup and one OWNER Save without payment prompts.

Patch ONLY _mg_v44_grid_transform and _owner_v44_grid_term_selection,
add _mg_v44_owner_apply_term. Legacy V4.4 table CSS and all other source
functions are unchanged. No licence/KeyGate/Mesh mutations during deploy.
"""
from __future__ import annotations
import argparse
import ast
from datetime import datetime, timezone
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
APP=ROOT/"app/routers/multiguard_license.py"
URL="https://api.multi-servis.pl/multiguard/panel/licenses-grid"
UI_REF="bcdb6dc49b7704493cc8d3d0df2f3a254a7d590e"
UI_BLOB="ca4983cca1a37a668139a9dc1f5e1bf007baa583"
OWNER_REF="6571e91ff0ae0f67e72ecebead24c65a01d4c704"
OWNER_BLOB="c71da4e0e98c8bd07ff4d6539d643edfa9d05678"

def blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def get_source(commit, name, expected):
    url=("https://raw.githubusercontent.com/tomekjel/fastapi/"+commit+
         "/embedded-multiguard/scripts/"+name)
    with urllib.request.urlopen(url,timeout=25) as res:
        data=res.read()
    if blob(data)!=expected:
        raise RuntimeError("Niezgodna suma kontrolna pomocnika: "+name)
    compile(data,name,"exec")
    return data.decode()

def functions(source):
    return {n.name:n for n in ast.parse(source).body
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def function_source(source,name):
    node=functions(source).get(name)
    if node is None:
        raise RuntimeError("Brakuje wymaganej funkcji: "+name)
    lines=source.splitlines(keepends=True)
    return "".join(lines[node.lineno-1:node.end_lineno])

def replace_fn(source,name,new_text):
    node=functions(source)[name]
    lines=source.splitlines(keepends=True)
    return "".join(lines[:node.lineno-1])+new_text.rstrip()+"\n"+"".join(lines[node.end_lineno:])

def prepare(before,ui,backend):
    defs=functions(before)
    required=(
        "_mg_v44_grid_transform","_mg_v44_grid_response",
        "_owner_v44_grid_term_selection","panel_grid_save_row",
        "panel_licenses_grid","_keygate_set_valid_until",
    )
    if any(x not in defs for x in required):
        raise RuntimeError("Produkcja nie odpowiada zatwierdzonej V4.4")
    if "_mg_v44_owner_apply_term" in defs:
        raise RuntimeError("Nowa poprawka jest już wdrożona.")
    old=function_source(before,"_owner_v44_grid_term_selection")
    start=old.find('    elif action in ("PAID_EXTEND", "PAID_CALENDAR"):')
    finish=old.find('    else:\n        raise HTTPException(409,',start)
    if start<0 or finish<0 or 'payment_confirmed != "yes"' not in old[start:finish]:
        raise RuntimeError("Nie rozpoznano starego wymagania płatności.")
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in before:
        raise RuntimeError("Brak blokady SERVICE w produkcji.")
    # The owner Save itself is explicit authorization. No "paid" assertion.
    replacement='''    elif action in ("PAID_EXTEND", "PAID_CALENDAR"):
        end = plan["valid_until"]
        _mg_v44_owner_apply_term(
            iid, operation_id, row["valid_until"], end, choice,
        )
'''
    old=old[:start]+replacement+old[finish:]
    new=replace_fn(before,"_owner_v44_grid_term_selection",old)
    new=replace_fn(new,"_mg_v44_grid_transform",
                   function_source(ui,"_mg_v44_grid_transform"))
    new=new.rstrip()+"\n\n"+backend.strip()+"\n"
    compile(new,str(APP),"exec")
    after=functions(new)
    if set(after)-set(defs)!={"_mg_v44_owner_apply_term"}:
        raise RuntimeError("Zmieniona lista funkcji aplikacji.")
    for name in defs:
        if name in ("_owner_v44_grid_term_selection","_mg_v44_grid_transform"):
            continue
        if ast.dump(defs[name],include_attributes=False)!=ast.dump(
            after[name],include_attributes=False
        ):
            raise RuntimeError("Naruszono chronioną funkcję: "+name)
    return new

def status():
    req=urllib.request.Request(URL,headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code

def live_preview(ui):
    """Actual production HTML; fake CSRF only within this CLI Python process."""
    import importlib
    import sys
    from unittest.mock import patch
    sys.path.insert(0,str(ROOT))
    module=importlib.import_module("app.routers.multiguard_license")
    with patch.object(module,"_workshop_csrf",return_value="V44-RENDER-ONLY"):
        response=module.panel_licenses_grid()
    if response.status_code!=200:
        raise RuntimeError("Błąd renderowania oryginalnego panelu.")
    ns={}
    exec(compile(ui,"<compact-owner-renderer>","exec"),ns)
    transformed=ns["_mg_v44_grid_transform"](response.body.decode())
    for required in ("data-mg-compact=\"yes\"","data-month=\"12\"",
                     "data-month=\"6\"","data-month=\"3\"",
                     'type="date"','name="term_choice"'):
        if required not in transformed:
            raise RuntimeError("Brak nowej kontrolki: "+required)
    if "Potwierdzam otrzymanie płatności" in transformed:
        raise RuntimeError("Stara kontrolka płatności nie została usunięta.")
    print("LIVE V4.4: COMPACT DATE / 12-6-3 / CALENDAR / ONE SAVE PASS")

def sessions_closed():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as con:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            if con.execute(text("SELECT to_regclass(:table)"),
                           {"table":table}).scalar_one_or_none() is None:
                continue
            n=con.execute(text("SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
            )).scalar_one()
            if n:
                raise RuntimeError("Aktywna sesja zdalna. Restart zablokowany: "+table)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--apply",action="store_true")
    a=p.parse_args()
    ui=get_source(UI_REF,"compact_v44_grid_renderer.py",UI_BLOB)
    backend=get_source(OWNER_REF,"compact_v44_owner_term.py",OWNER_BLOB)
    source=APP.read_text()
    changed=prepare(source,ui,backend)
    code=status()
    if code not in (401,403):
        raise RuntimeError("Brak oczekiwanej ochrony logowania OWNER.")
    live_preview(ui)
    print("V4.4 ORIGINAL TABLE/CSS: PRESERVED")
    print("PAYMENT CHECKBOX / EXTRA CONFIRMATION: REMOVED")
    print("OWNER SAVE: 3/6/12 OR CALENDAR, NO PAYMENT ASSERTION")
    print("SERVICE RIGHTS SWITCH: STILL BLOCKED")
    if not a.apply:
        print("COMPACT V4.4: PREFLIGHT PASS (NO WRITES)")
        return
    sessions_closed()
    backup=ROOT/("backup-mg-v44-compact-fix-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(APP,backup/APP.name)
    wrote=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-v44-compact-",dir=APP.parent)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as out:
                out.write(changed)
            os.chmod(tmp,0o644)
            os.replace(tmp,APP)
            wrote=True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],check=True,timeout=45)
        for _ in range(16):
            active=subprocess.run(["systemctl","is-active","--quiet","multiservis-api.service"],
                                  check=False,timeout=8).returncode==0
            if active and status()==code:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI lub panel OWNER nie uruchomił się.")
        print("COMPACT V4.4: APPLIED")
        print("TABLE:",URL)
        print("NO KEYGATE/MESH/LICENSE MUTATION ON DEPLOY")
        print("BACKUP:",backup)
    except Exception:
        if wrote:
            shutil.copy2(backup/APP.name,APP)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
