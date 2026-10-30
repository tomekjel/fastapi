#!/usr/bin/env python3
"""V4.4 surgical OWNER consent-invalidation guard.

Preserves all production UI, V4.4 row Save, KeyGate, Mesh and licences.
Adds only an import, standing-auth schema check and transactional invalidation
inside the existing _owner_select_effective_mode() body, before any real
CLIENT<->SERVICE selection or service grant mutation. Never enables switches.
Unknown production shapes stop before writing.
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

ROOT = Path("/opt/multiservis")
ROUTERS = ROOT / "app/routers"
LICENSE = ROUTERS / "multiguard_license.py"
WORKSHOP = ROUTERS / "multiguard_workshop_remote.py"
THEME = ROUTERS / "multiguard_panel_theme.py"
TARGET = "_owner_select_effective_mode"
PANEL_URL = "https://api.multi-servis.pl/multiguard/panel/licenses-grid"

IMPORT_ANCHOR = (
    "    from app.routers.multiguard_entitlement_modes import "
    "resolve_mode, service_valid_until\n"
)
IMPORT_CHANGE = (
    IMPORT_ANCHOR +
    "    from app.routers import multiguard_workshop_remote as workshop_remote\n"
)
SCHEMA_ANCHOR = "    _ensure_schema()\n    with engine.begin() as con:"
SCHEMA_CHANGE = (
    "    _ensure_schema()\n"
    "    # Standing approvals must exist before changing effective rights.\n"
    "    workshop_remote._schema()\n"
    "    with engine.begin() as con:"
)
GRANT_ANCHOR = (
    '        if target_mode == "SERVICE":\n'
    "            before = dict(grant) if grant else None"
)
GRANT_CHANGE = (
    "        # Actual OWNER rights transitions invalidate prior standing consent\n"
    "        # within the SAME transaction; no stale opt-in can reappear.\n"
    "        workshop_remote.invalidate_standing_authorization(\n"
    '            con, iid, "SERVICE_RIGHTS_CHANGED",\n'
    "        )\n\n"
    + GRANT_ANCHOR
)

def functions(source: str):
    return {
        n.name: n for n in ast.parse(source).body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

def target_text(source: str) -> str:
    n = functions(source).get(TARGET)
    if n is None:
        raise RuntimeError("OWNER mode selection function is missing")
    lines = source.splitlines(keepends=True)
    return "".join(lines[n.lineno-1:n.end_lineno])

def replace_unique(s, old, new, label):
    found = s.count(old)
    if found != 1:
        raise RuntimeError(f"OWNER consent {label}: expected one anchor, got {found}")
    return s.replace(old, new, 1)

def patch(source: str) -> tuple[str,bool]:
    fn = target_text(source)
    changes = (
        "workshop_remote._schema()" in fn,
        "workshop_remote.invalidate_standing_authorization(" in fn,
    )
    if changes == (True, True):
        return source, True
    if any(changes):
        raise RuntimeError("Partial or unknown standing-consent patch: no writes")
    for marker in (
        "with engine.begin() as con:",
        "guard.remote_sessions",
        "guard.workshop_remote_sessions",
        "mesh_public_id IS NOT NULL",
        "SELECT selected_mode FROM guard.owner_entitlement_selections",
        "WHERE installation_id=:iid FOR UPDATE",
        'if current == target_mode:',
        "if active:",
        "INSERT INTO guard.owner_entitlement_selections(",
        "INSERT INTO guard.owner_license_mode_transitions(",
    ):
        if marker not in fn:
            raise RuntimeError("Missing audited OWNER safety guard: "+marker)
    # Both client and workshop remote session paths must reject unrevoked
    # public shares. A single surviving marker does not prove both are safe.
    if fn.count("mesh_public_id IS NOT NULL") != 2:
        raise RuntimeError("Missing audited two-mode Mesh share safeguards")
    fn = replace_unique(fn, IMPORT_ANCHOR, IMPORT_CHANGE, "import")
    fn = replace_unique(fn, SCHEMA_ANCHOR, SCHEMA_CHANGE, "schema")
    fn = replace_unique(fn, GRANT_ANCHOR, GRANT_CHANGE, "transaction")
    if not (fn.index("if active:") <
            fn.index("workshop_remote.invalidate_standing_authorization(") <
            fn.index("INSERT INTO guard.owner_entitlement_selections(")):
        raise RuntimeError("Standing revocation insertion order unsafe")

    nodes_before = functions(source)
    n = nodes_before[TARGET]
    lines = source.splitlines(keepends=True)
    after = "".join(lines[:n.lineno-1])+fn.rstrip()+"\n"+"".join(lines[n.end_lineno:])
    compile(after, str(LICENSE), "exec")
    nodes_after = functions(after)
    if set(nodes_before) != set(nodes_after):
        raise RuntimeError("Unexpected V4.4 route definitions")
    for name in nodes_before:
        if name == TARGET:
            continue
        if ast.dump(nodes_before[name],include_attributes=False) != ast.dump(
            nodes_after[name],include_attributes=False
        ):
            raise RuntimeError("Protected V4.4 function changed: "+name)
    return after, False

def protected_panel_status():
    req = urllib.request.Request(PANEL_URL, headers={"Cache-Control":"no-cache"})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code

def verify_workshop():
    src = WORKSHOP.read_text()
    nodes = functions(src)
    fn = nodes.get("invalidate_standing_authorization")
    if fn is None:
        raise RuntimeError("Production standing consent invalidation function missing")
    rows = src.splitlines()
    body = "\n".join(rows[fn.lineno-1:fn.end_lineno])
    for marker in (
        'SELECT revoked_at',
        'FOR UPDATE',
        'SET revoked_at=:now',
        "workshop_standing_remote_audit",
        'SERVICE_RIGHTS_CHANGED',
    ):
        if marker not in body:
            raise RuntimeError("Production standing revocation unsafe: "+marker)
    if "def _schema(" not in src:
        raise RuntimeError("Workshop standing schema missing")

def no_open_shares():
    import sys
    sys.path.insert(0,str(ROOT))
    from app.database import engine
    from sqlalchemy import text
    with engine.connect() as con:
        for table in ("guard.remote_sessions","guard.workshop_remote_sessions"):
            if con.execute(text("SELECT to_regclass(:t)"),
                           {"t":table}).scalar_one_or_none() is None:
                continue
            number = con.execute(text(
                "SELECT count(*) FROM "+table+
                " WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')"
                " OR mesh_public_id IS NOT NULL"
            )).scalar_one()
            if number:
                raise RuntimeError("Open or unreconciled Mesh share: "+table+" "+str(number))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    if not LICENSE.is_file() or not WORKSHOP.is_file():
        raise RuntimeError("Missing protected V4.4 source")
    if "STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET." not in LICENSE.read_text():
        raise RuntimeError("OWNER switch safety interlock not installed")
    verify_workshop()
    original = LICENSE.read_text()
    changed, already = patch(original)
    if already:
        print("OWNER CONSENT INVALIDATION: ALREADY INSTALLED, NO CHANGES")
        return
    baseline = protected_panel_status()
    if baseline not in (401,403):
        raise RuntimeError("Protected panel unexpectedly publicly accessible")
    print("OWNER CONSENT INVALIDATION PREFLIGHT: PASS")
    print("REAL MODE CHANGES: OLD STANDING CONSENT REVOKED IN SAME TRANSACTION")
    print("PAID LICENCE / CLIENT CONSENT / MESH / V4.4 HTML: UNCHANGED")
    if not args.apply:
        print("DRY RUN: NO CHANGES")
        return
    for setting in (
        "MULTIGUARD_MODE_SWITCH_ENABLED",
        "MULTIGUARD_OWNER_GRID_SERVICE_ENABLED",
    ):
        if os.getenv(setting,"false").strip().lower() in ("true","1","yes"):
            raise RuntimeError("New-owner-mode feature already enabled: "+setting)
    no_open_shares()
    backup=ROOT/("backup-mg-owner-consent-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700,exist_ok=False)
    shutil.copy2(LICENSE,backup/LICENSE.name)
    wrote=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-owner-consent-",dir=ROUTERS)
        try:
            with os.fdopen(fd,"w",encoding="utf-8") as out:
                out.write(changed)
            os.chmod(tmp,0o644)
            os.replace(tmp,LICENSE)
            wrote=True
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        subprocess.run(["systemctl","restart","multiservis-api.service"],check=True,timeout=45)
        for _ in range(15):
            active=subprocess.run(["systemctl","is-active","--quiet","multiservis-api.service"],
                                   timeout=8).returncode==0
            if active and protected_panel_status()==baseline:
                break
            time.sleep(1)
        else:
            raise RuntimeError("FastAPI or protected OWNER panel verification failed")
        print("OWNER CONSENT INVALIDATION: APPLIED")
        print("MODE SWITCH: STILL DISABLED")
        print("V4.4 / KEYGATE / MESH / EXISTING LICENCES: UNCHANGED")
        print("BACKUP:",backup)
    except Exception:
        if wrote:
            shutil.copy2(backup/LICENSE.name,LICENSE)
            subprocess.run(["systemctl","restart","multiservis-api.service"],
                           check=False,timeout=45)
        raise

if __name__=="__main__":
    main()
