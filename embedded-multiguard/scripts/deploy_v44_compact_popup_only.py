#!/usr/bin/env python3
"""Cosmetic-only V4.4 popup deploy: 4 square tiles and date field only.

Changes exactly one existing pure HTML transformer function, no paid/Service
handlers, licence data, KeyGate, Mesh or protected V4.4 layout. A strict AST
fingerprint verifies production equals the known previous deployed transformer.
Dry-run by default; --apply backs up and restarts API, rollback on failure.
"""
from __future__ import annotations
import argparse
import ast
from datetime import datetime,timezone
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
TARGET=ROOT/"app/routers/multiguard_license.py"
FUNC="_mg_v44_grid_transform"
PREV_REF="bcdb6dc49b7704493cc8d3d0df2f3a254a7d590e"
PREV_BLOB="ca4983cca1a37a668139a9dc1f5e1bf007baa583"
NEXT_REF="3131469a6502832b07da67b51d2de1dd35c83239"
NEXT_BLOB="b7ce364df824b364ce7f9d716a6a305f62393af0"
RENDERER="compact_v44_grid_renderer.py"
URL="https://api.multi-servis.pl/multiguard/panel/licenses-grid"

def blob(data:bytes)->str:
    return hashlib.sha1(
        b"blob "+str(len(data)).encode("ascii")+b"\0"+data
    ).hexdigest()

def fetch(ref:str,expected:str)->str:
    source=("https://raw.githubusercontent.com/tomekjel/fastapi/"
            +ref+"/embedded-multiguard/scripts/"+RENDERER)
    with urllib.request.urlopen(source,timeout=25) as reply:
        data=reply.read()
    if blob(data)!=expected:
        raise RuntimeError("Nieprawidłowa suma kontrolna pliku interfejsu.")
    compile(data,RENDERER,"exec")
    return data.decode("utf-8")

def defs(source):
    return {n.name:n for n in ast.parse(source).body
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def func_text(source,name):
    tree=defs(source)
    if name not in tree:
        raise RuntimeError("Brak funkcji w produkcji: "+name)
    node=tree[name]
    lines=source.splitlines(keepends=True)
    return "".join(lines[node.lineno-1:node.end_lineno])

def patched(original,old_ui,new_ui):
    a=defs(original)
    before=defs(old_ui)
    after=defs(new_ui)
    if FUNC not in a or FUNC not in before or FUNC not in after:
        raise RuntimeError("Nieoczekiwana funkcja widoku.")
    if ast.dump(a[FUNC],include_attributes=False)!=ast.dump(
            before[FUNC],include_attributes=False):
        raise RuntimeError("Produkcja ma inne kontrolki: bez zmian.")
    for needed in (
        "panel_licenses_grid","_mg_v44_grid_response",
        "panel_grid_save_row","_owner_v44_grid_term_selection",
        "_mg_v44_owner_apply_term",
    ):
        if needed not in a:
            raise RuntimeError("Produkcja nie ma wcześniejszej zatwierdzonej V4.4: "+needed)
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in original:
        raise RuntimeError("Nie rozpoznano ochrony SERVICE.")
    node=a[FUNC]
    lines=original.splitlines(keepends=True)
    result=("".join(lines[:node.lineno-1])+
            func_text(new_ui,FUNC).rstrip()+"\n"+
            "".join(lines[node.end_lineno:]))
    compile(result,str(TARGET),"exec")
    b=defs(result)
    if set(a)!=set(b):
        raise RuntimeError("Nieoczekiwana zmiana tras backendu.")
    for name in a:
        if name==FUNC:
            continue
        if ast.dump(a[name],include_attributes=False)!=ast.dump(
                b[name],include_attributes=False):
            raise RuntimeError("Zmieniono chronioną funkcję: "+name)
    return result

def panel_status():
    req=urllib.request.Request(URL,headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code

def live_preview(new_ui):
    import importlib
    import sys
    from unittest.mock import patch
    sys.path.insert(0,str(ROOT))
    m=importlib.import_module("app.routers.multiguard_license")
    # Do not read or change the production panel's authentication secrets.
    # Render only a temporary in-process HTML view with a dummy CSRF token.
    with patch.object(m,"_workshop_csrf",return_value="PREVIEW-ONLY"):
        with patch.object(m,FUNC,lambda text:text):
            response=m.panel_licenses_grid()
    if response.status_code!=200:
        raise RuntimeError("Nie można wyrenderować produkcyjnej tabeli.")
    ns={}
    exec(compile(new_ui,"<new-popup-pure>","exec"),ns)
    html=ns[FUNC](response.body.decode("utf-8"))
    for marker in (
        'data-month="12"','data-month="6"','data-month="3"',
        '>Bezterm.</button>','class="mg-compact-calendar" type="date"',
        "grid-template-columns:repeat(4,minmax(0,1fr))",
        "border-radius:0!important",
    ):
        if marker not in html:
            raise RuntimeError("Niepoprawny wygląd rozwijanego pola: "+marker)
    if "Wybierz konkretną datę" in html or "Potwierdzam otrzymanie płatności" in html:
        raise RuntimeError("Niedozwolony dodatkowy opis w okienku.")
    print("PRODUCTION LIVE GRID: FOUR COMPACT TILES AND DATE PASS")

def sessions():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as con:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            if con.execute(text("SELECT to_regclass(:t)"),
                           {"t":table}).scalar_one_or_none() is None:
                continue
            count=con.execute(text(
                "SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
            )).scalar_one()
            if count:
                raise RuntimeError("Aktywne sesje blokują restart: "+table)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--apply",action="store_true")
    args=p.parse_args()
    old=fetch(PREV_REF,PREV_BLOB)
    new=fetch(NEXT_REF,NEXT_BLOB)
    original=TARGET.read_text()
    candidate=patched(original,old,new)
    status=panel_status()
    if status not in (401,403):
        raise RuntimeError("Panel OWNER nie wymaga spodziewanego logowania.")
    live_preview(new)
    print("4 ROWNE PROSTOKATNE KAFLE: 12 / 6 / 3 / BEZTERM.")
    print("NIZEJ TYLKO POLE KALENDARZA")
    print("CALY ZAPIS I KEYGATE: BEZ ZMIAN")
    print("SERVICE: WCIĄŻ ZABLOKOWANY")
    if not args.apply:
        print("V4.4 EXPIRY POPUP: PREFLIGHT PASS (NO CHANGES)")
        return
    sessions()
    backup=ROOT/("backup-mg-v44-popup-"+
            datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(TARGET,backup/TARGET.name)
    wrote=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-v44-popup-",dir=TARGET.parent)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as output:
                output.write(candidate)
            os.chmod(tmp,0o644)
            os.replace(tmp,TARGET)
            wrote=True
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],
                       check=True,timeout=45)
        for _ in range(18):
            active=subprocess.run(
                ["systemctl","is-active","--quiet","multiservis-api.service"],
                check=False,timeout=10,
            ).returncode==0
            if active and panel_status()==status:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI lub strona OWNER nie przeszła kontroli.")
        print("V4.4 EXPIRY POPUP: APPLIED")
        print("TABLE:",URL)
        print("LICENCES, KEYGATE, MESH: NOT MODIFIED")
        print("BACKUP:",backup)
    except Exception:
        if wrote:
            shutil.copy2(backup/TARGET.name,TARGET)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
