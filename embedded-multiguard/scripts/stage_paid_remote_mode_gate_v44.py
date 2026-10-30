#!/usr/bin/env python3
"""Stage2 OWNER remote guard: preserve paid PRO consent while SERVICE selected.

Production patch only affects the customer-paid remote authorization gate.
It never changes an existing KeyGate licence, MeshCentral share or session.
It leaves the OWNER mode-switch route disabled, pending full integration.
"""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = Path("/opt/multiservis")
ROUTERS = ROOT / "app/routers"
PROD = ROUTERS / "multiguard_remote.py"
PROD_SHA256 = "fdf567edec7bdd79db80bbe495786622352afa0bef5b822a7a5396ba5d0bfc5a"
STAGE2_BACKUP = ROOT / "backup-mg-license-stage2-20261030-204405"
PANEL = "https://api.multi-servis.pl/multiguard/panel/licenses-grid"

# Same DB connection/transaction as the remote session request: the pending
# installation FOR SHARE lock prevents an OWNER switch racing a new session.
PAID_REMOTE_GATE = '''
def _owner_verified_paid_remote(connection, installation, now):
    """Fail-closed paid Pro authorization, independent of OWNER service mode."""
    if not _has_active_remote_pro(installation, now):
        return False
    internal_id = installation.get("installation_id") or installation.get("id")
    if internal_id is None:
        return False
    from app.routers import multiguard_license as owner_license
    paid = connection.execute(text("""
        SELECT l.plan_code,l.lifecycle,l.valid_until,l.installation_id
        FROM guard.license_links l
        JOIN guard.installations gi
          ON gi.installation_external_id=l.installation_id
        WHERE gi.id=:id
        ORDER BY (l.lifecycle='ACTIVE') DESC, l.valid_until DESC NULLS LAST
        LIMIT 1
    """), {"id":internal_id}).mappings().first()
    if not paid or paid["installation_id"] is None:
        return False
    # Hold the lock through the calling transaction: mode-change acquires
    # FOR UPDATE on this exact row before checking/opening remote sessions.
    enrolled = connection.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid AND status IN ('ASSIGNED','PROVISIONED')
        FOR SHARE
    """), {"iid":paid["installation_id"]}).scalar_one_or_none()
    if not enrolled:
        return False
    if owner_license._owner_effective_entitlement_mode(
        connection, paid["installation_id"]
    ) != "CLIENT":
        return False
    return bool(
        paid["plan_code"] == "multi_guard_pro"
        and paid["lifecycle"] == "ACTIVE"
        and paid["valid_until"] is not None
        and paid["valid_until"] > now
    )


def _owner_verified_service_remote(_connection, _installation, _now):
    """Paid remote path may NEVER grant unattended workshop remote access."""
    return False

'''

def digest(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def functions(source:str):
    t=ast.parse(source)
    return {n.name:n for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}

def extract(source:str, fn:str, *, decorators=False):
    entries=functions(source)
    if fn not in entries:
        raise RuntimeError("Missing remote function: "+fn)
    f=entries[fn]
    start=min([f.lineno]+[x.lineno for x in f.decorator_list]) if decorators else f.lineno
    return start,f.end_lineno

def rewrite(source, name, replacement):
    start,end=extract(source,name)
    lines=source.splitlines(keepends=True)
    return "".join(lines[:start-1])+replacement.rstrip()+"\n"+"".join(lines[end:])

def paid_remote_overlay(original: str)->tuple[str,tuple[str,...]]:
    entries=functions(original)
    if "_owner_verified_paid_remote" in entries or "_owner_verified_service_remote" in entries:
        raise RuntimeError("Paid remote OWNER gate already exists; refusing duplicate")
    if "_has_active_remote_pro" not in entries:
        raise RuntimeError("Legacy paid PRO permission helper not found")
    calls=[]
    for name,fn in entries.items():
        if name=="_has_active_remote_pro":
            continue
        legacy=[node for node in ast.walk(fn)
                if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name)
                and node.func.id=="_has_active_remote_pro"]
        if not legacy:
            continue
        body="".join(original.splitlines(keepends=True)[fn.lineno-1:fn.end_lineno])
        if "connection" not in body:
            raise RuntimeError("No transaction connection available in "+name)
        if not (name.startswith("panel_") or name in (
                "agent_remote_poll","agent_remote_decision","agent_remote_end",
                "create_remote_session","remote_session_detail",
                "remote_session_connect","remote_session_end")):
            raise RuntimeError("Unexpected paid authorization call site "+name)
        calls.append(name)
    if not calls:
        raise RuntimeError("No legacy remote callsites to protect")
    if "from sqlalchemy import text" not in original:
        raise RuntimeError("SQLAlchemy text import missing")
    # Replace ONLY whole call names in the audited functions. Every replacement
    # is followed by an AST assertion that no unguarded legacy call remains.
    changed=original
    for name in calls:
        start,end=extract(changed,name)
        lines=changed.splitlines(keepends=True)
        func="".join(lines[start-1:end])
        if "_has_active_remote_pro(" not in func:
            raise RuntimeError("Expected legacy gate missing: "+name)
        func=func.replace(
            "_has_active_remote_pro(",
            "_owner_verified_paid_remote(connection, "
        )
        changed=rewrite(changed,name,func)
    start,_=extract(changed,"_has_active_remote_pro")
    lines=changed.splitlines(keepends=True)
    changed="".join(lines[:start-1])+PAID_REMOTE_GATE+"\n"+"".join(lines[start-1:])
    # Keep original helper visible to our wrapper; no external route may call
    # the old helper directly.
    all_functions=functions(changed)
    for name,fn in all_functions.items():
        if name in ("_has_active_remote_pro","_owner_verified_paid_remote"):
            continue
        legacy=[x for x in ast.walk(fn) if isinstance(x,ast.Call)
                and isinstance(x.func,ast.Name)
                and x.func.id=="_has_active_remote_pro"]
        if legacy:
            raise RuntimeError("Legacy remote bypass survives in "+name)
    compile(changed,str(PROD),"exec")
    return changed,tuple(calls)

def check_status():
    req=urllib.request.Request(PANEL,headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code

def verify_production_shape():
    if not STAGE2_BACKUP.is_dir():
        raise RuntimeError("Expected stage2 backup missing")
    for name in ("multiguard_license.py","multiguard_panel_theme.py"):
        backup=STAGE2_BACKUP/name
        current=ROUTERS/name
        if not backup.is_file() or not current.is_file():
            raise RuntimeError("Protected V4.4 backup missing "+name)
        if name=="multiguard_panel_theme.py" and current.read_bytes()!=backup.read_bytes():
            raise RuntimeError("Protected 240px V4.4 theme changed")
    license_source=(ROUTERS/"multiguard_license.py").read_text()
    for marker in (
        "def _owner_effective_entitlement_mode(",
        "def _owner_select_effective_mode(",
        "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.",
        "def panel_grid_save_row(",
    ):
        if marker not in license_source:
            raise RuntimeError("Expected OWNER stage2 guard not installed: "+marker)
    if digest(PROD)!=PROD_SHA256:
        raise RuntimeError("Paid remote production changed unexpectedly: abort")

def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--apply",action="store_true")
    args=p.parse_args()
    verify_production_shape()
    prepared,calls=paid_remote_overlay(PROD.read_text())
    before=check_status()
    if before not in (401,403):
        raise RuntimeError("Protected panel does not return 401/403: abort")
    print("REMOTE MODE-GATE PREFLIGHT: PASS")
    print("PROTECTED ROUTES:", ", ".join(calls))
    print("PAID REMOTE: CLIENT MODE ONLY; SERVICE BYPASS BLOCKED")
    if not args.apply:
        print("DRY RUN: NO CHANGES")
        return

    backup=ROOT/("backup-mg-paid-remote-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(PROD,backup/PROD.name)
    written=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-paid-remote-",dir=ROUTERS)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as handle:
                handle.write(prepared)
            os.chmod(tmp,0o644)
            os.replace(tmp,PROD)
            written=True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],check=True,timeout=40)
        for _ in range(12):
            if check_status()==before and subprocess.run(
                ["systemctl","is-active","--quiet","multiservis-api.service"],
                check=False,timeout=8,
            ).returncode==0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI health or protected panel status changed")
        print("REMOTE MODE-GATE: APPLIED")
        print("OWNER MODE-SWITCH: STILL HARD-DISABLED")
        print("V4.4 / KEYGATE / MESH / LICENCE RECORDS: UNCHANGED")
        print("BACKUP:",backup)
    except Exception:
        if written:
            shutil.copy2(backup/PROD.name,PROD)
            subprocess.run(["systemctl","restart","multiservis-api.service"],check=False,timeout=40)
        raise

if __name__=="__main__":
    main()
