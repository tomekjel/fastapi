#!/usr/bin/env python3
"""Surgical V4.4 production compatibility overlay for MultiGuard OWNER.

Pinned input hashes; install only after all preflight assertions and compilation.
Switching modes is deliberately hard-disabled until remote session and Mesh
entrypoints are separately integrated. This script does NOT issue any licence.
"""
from __future__ import annotations
import argparse
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
sys.path.insert(0, str(ROOT))
ROUTERS = ROOT / "app/routers"
SRC = {
    "multiguard_license.py": "d201458f3313f1001f9c212138c60c66c85d161b121137c1ea54943ffc602708",
    "multiguard_workshop_remote.py": "36495260f57854d493cff25c80415cca69d8bfbe83ac315b87b48771d5f4de9d",
    "multiguard_panel_theme.py": "0e63d2c54ddb5036237aa2ba53ca4c73e71aa86e23c24280e1001dddd1d778d7",
}
PINNED_GH_REF = "82192cb6fb7ecfe6a3dffc2afbb417510e2dc04b"
GH_BLOB_SHA = {
    "multiguard_license.py": "e1f191e52e763626b5f99565329a8eba9aa93ea3",
    "multiguard_workshop_remote.py": "f6e490a60194025eaf5a94fa2a1994703d23002f",
}
PANEL_PATH = "/multiguard/panel/licenses-grid"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()

def load_pinned_source(name: str) -> str:
    uri = (
        "https://raw.githubusercontent.com/tomekjel/fastapi/"
        + PINNED_GH_REF + "/embedded-multiguard/app/routers/" + name
    )
    with urllib.request.urlopen(uri, timeout=25) as response:
        raw = response.read()
    if GH_BLOB_SHA[name] != git_blob_sha(raw):
        raise RuntimeError("Pinned GitHub source digest mismatch: " + name)
    return raw.decode("utf-8")

def locate_function(source: str, name: str, decorators: bool = False):
    tree = ast.parse(source)
    matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == name]
    if len(matches) != 1:
        raise RuntimeError("Missing/ambiguous function: " + name)
    n = matches[0]
    start = min([n.lineno]+[d.lineno for d in n.decorator_list]) if decorators else n.lineno
    return start, n.end_lineno

def get_function(source: str, name: str, decorators: bool = False) -> str:
    start, end = locate_function(source, name, decorators)
    return "".join(source.splitlines(keepends=True)[start-1:end])

def replace_function(source: str, name: str, replacement: str) -> str:
    start, end = locate_function(source, name)
    rows = source.splitlines(keepends=True)
    return "".join(rows[:start-1]) + replacement.rstrip()+"\n" + "".join(rows[end:])

def insert_before(source: str, name: str, replacement: str) -> str:
    start, _ = locate_function(source, name, decorators=True)
    rows = source.splitlines(keepends=True)
    return "".join(rows[:start-1]) + replacement.rstrip()+"\n\n" + "".join(rows[start-1:])

def amend_once(source: str, old: str, new: str, context: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError(f"Production anchor for {context} count={source.count(old)} expected=1")
    return source.replace(old,new,1)

def produce_license(production: str, upstream: str) -> str:
    names = {n.name for n in ast.parse(production).body
             if isinstance(n, (ast.FunctionDef,ast.AsyncFunctionDef))}
    for name in ("_owner_effective_entitlement_mode","_owner_select_effective_mode",
                 "panel_owner_select_effective_mode"):
        if name in names:
            raise RuntimeError("Already integrated; refuse to duplicate: " + name)

    mode_selector = get_function(upstream,"_owner_effective_entitlement_mode")
    # Installations marked assigned/provisioned are never treated as SERVICE
    # automatically, even in a partially inconsistent database.
    needle = """          EXISTS (SELECT 1 FROM guard.license_links
                  WHERE installation_id=:iid) AS paid_link,"""
    patched = """          (EXISTS (SELECT 1 FROM guard.license_links
                   WHERE installation_id=:iid)
            OR EXISTS (SELECT 1 FROM guard.pending_installations p
                       WHERE p.installation_id=:iid
                         AND p.status IN ('ASSIGNED','PROVISIONED'))) AS paid_link,"""
    mode_selector = amend_once(mode_selector,needle,patched,"default customer mode")
    production = insert_before(production,"_workshop_grant", mode_selector)

    discovery = get_function(production, "discovery_assignment")
    upstream_discovery = get_function(upstream, "discovery_assignment")
    begin = upstream_discovery.find("    # Explicit OWNER service mode takes precedence")
    finish = upstream_discovery.find('    reception_id = pending.get("assigned_reception_id")',begin)
    if begin < 0 or finish < 0:
        raise RuntimeError("Missing approved upstream discovery service switch")
    service_section = upstream_discovery[begin:finish]
    if "selected_mode == \"SERVICE\"" not in service_section:
        raise RuntimeError("Service override branch is malformed")
    discovery = amend_once(
        discovery,
        '    reception_id = pending.get("assigned_reception_id")',
        service_section + '    reception_id = pending.get("assigned_reception_id")',
        "discovery assignment mode override",
    )
    production = replace_function(production,"discovery_assignment",discovery)

    refresh = get_function(production,"refresh")
    if "_owner_effective_entitlement_mode" in refresh:
        raise RuntimeError("Paid refresh already switched")
    refresh = amend_once(
        refresh,
        "    link = _authenticate_installation(req)\n",
        """    link = _authenticate_installation(req)
    # A signed service lease must never be overwritten by paid refresh.
    with engine.connect() as mode_con:
        if _owner_effective_entitlement_mode(mode_con, link["installation_id"]) == "SERVICE":
            raise HTTPException(409, "Właściciel wybrał tryb serwisowy.")
""",
        "paid refresh",
    )
    production = replace_function(production,"refresh",refresh)

    # The OWNER route is intentionally inert until the full remote/Mesh
    # transition guard has been verified separately, never a fake UI button.
    switcher = get_function(upstream,"_owner_select_effective_mode")
    route = get_function(upstream,"panel_owner_select_effective_mode",decorators=True)
    route = amend_once(
        route,
        "    from app.routers.multiguard_panel_settings import _token_valid",
        """    # STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.
    raise HTTPException(409, "Przełączanie trybów wymaga ukończenia integracji Mesh i Windows.")
    from app.routers.multiguard_panel_settings import _token_valid""",
        "stage2 hard stop",
    )
    production = insert_before(production,"panel_grid_save_row",switcher+"\n\n"+route)
    ast.parse(production)
    return production

def produce_workshop(production: str, upstream: str) -> str:
    for name in ("_grant","remote_entitlement_mode"):
        production = replace_function(production,name,get_function(upstream,name))
    # An inconsistent pending assignment without an existing paid link
    # must not silently enable service remote rights.
    production = amend_once(
        production,
        """                 CASE WHEN EXISTS (
                   SELECT 1 FROM guard.license_links l
                   WHERE l.installation_id=p.installation_id
                 ) THEN 'CLIENT' ELSE 'SERVICE' END) AS owner_mode""",
        """                 CASE WHEN p.status IN ('ASSIGNED','PROVISIONED')
                    OR EXISTS (
                   SELECT 1 FROM guard.license_links l
                   WHERE l.installation_id=p.installation_id
                 ) THEN 'CLIENT' ELSE 'SERVICE' END) AS owner_mode""",
        "workshop fail-closed fallback",
    )
    ast.parse(production)
    return production

def sql_bootstrap():
    # DDL only: creates tables, does not edit or assign any existing rights.
    from sqlalchemy import text
    from app.database import engine
    ddl = [
        """CREATE TABLE IF NOT EXISTS guard.owner_entitlement_selections (
             installation_id UUID PRIMARY KEY REFERENCES guard.pending_installations(installation_id)
                ON DELETE CASCADE,
             selected_mode TEXT NOT NULL CHECK (selected_mode IN ('CLIENT','SERVICE')),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
           )""",
        """CREATE TABLE IF NOT EXISTS guard.owner_license_mode_transitions (
             id UUID PRIMARY KEY,
             installation_id UUID NOT NULL,
             license_link_id UUID REFERENCES guard.license_links(id),
             source_mode TEXT NOT NULL CHECK (source_mode IN ('STANDARD','PRO','SERVICE','NONE')),
             target_mode TEXT NOT NULL CHECK (target_mode IN ('STANDARD','PRO','SERVICE','NONE')),
             target_valid_until TIMESTAMPTZ,
             state TEXT NOT NULL CHECK (state IN ('PREPARED','KEYGATE_REVOKED','LOCAL_APPLIED',
                      'COMPLETED','REQUIRES_RECONCILIATION','CANCELLED')),
             reason TEXT,
             created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
             last_error TEXT
           )""",
        """CREATE UNIQUE INDEX IF NOT EXISTS owner_license_mode_transitions_one_open
             ON guard.owner_license_mode_transitions (installation_id)
             WHERE state IN ('PREPARED','KEYGATE_REVOKED','LOCAL_APPLIED',
                  'REQUIRES_RECONCILIATION')""",
    ]
    with engine.begin() as c:
        for statement in ddl:
            c.execute(text(statement))
        expected = {
            "owner_entitlement_selections": {"installation_id","selected_mode","updated_at"},
            "owner_license_mode_transitions": {"id","installation_id","license_link_id",
                "source_mode","target_mode","target_valid_until","state","reason","created_at","updated_at","last_error"}
        }
        for name, cols in expected.items():
            found = {x[0] for x in c.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_schema='guard' AND table_name=:name
            """),{"name":name}).all()}
            if not cols.issubset(found):
                raise RuntimeError("Incompatible existing SQL schema: "+name)
    with engine.connect() as c:
        selected_service = c.execute(text("""
            SELECT count(*) FROM guard.owner_entitlement_selections
            WHERE selected_mode='SERVICE'
        """)).scalar_one()
        if selected_service:
            raise RuntimeError("Existing explicit SERVICE selections: refuse to change runtime until reconciled")
    print("OWNER LICENCE MODE TABLES: READY (NO LICENCE ROWS CHANGED)")

def status_url() -> int:
    req = urllib.request.Request(
        "https://api.multi-servis.pl/multiguard/panel/licenses-grid",
        headers={"Cache-Control":"no-cache"},
    )
    try:
        with urllib.request.urlopen(req,timeout=8) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code

def apply(prepared: dict[str,str], previous_status: int):
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = ROOT / ("backup-mg-license-stage2-"+now)
    backup.mkdir(mode=0o700)
    for name in SRC:
        shutil.copy2(ROUTERS/name,backup/name)
    files_written = []
    try:
        sql_bootstrap()
        for name, contents in prepared.items():
            fd, temp = tempfile.mkstemp(prefix=".mg-stage2-",dir=ROUTERS)
            with os.fdopen(fd,"w",encoding="utf-8") as f:
                f.write(contents)
            os.chmod(temp,0o644)
            os.replace(temp,ROUTERS/name)
            files_written.append(name)
        subprocess.run(["systemctl","restart","multiservis-api.service"],check=True,timeout=40)
        healthy=False
        for _ in range(12):
            try:
                now_status = status_url()
                if now_status == previous_status:
                    healthy=True
                    break
            except Exception:
                pass
            time.sleep(1)
        service_active = subprocess.run(
            ["systemctl","is-active","--quiet","multiservis-api.service"],
            check=False,timeout=10,
        ).returncode == 0
        if not healthy or not service_active:
            raise RuntimeError("Backend failed service-active or panel HTTP health check")
        print("STAGE2 CORE: APPLIED")
        print("MODE SWITCH ROUTE: HARD-DISABLED")
        print("PANEL V4.4: UNMODIFIED")
        print("EXISTING ENTITLEMENT RECORDS: UNMODIFIED")
        print("KEYGATE / MESH: NO MUTATIONS")
        print("BACKUP:",backup)
    except Exception:
        print("STAGE2 ERROR: ROLLING BACK PYTHON FILES",file=sys.stderr)
        for name in files_written:
            shutil.copy2(backup/name,ROUTERS/name)
        if files_written:
            subprocess.run(["systemctl","restart","multiservis-api.service"],check=False,timeout=40)
        raise

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true",help="Install only after preflight")
    args = parser.parse_args()
    for name,digest in SRC.items():
        raw = (ROUTERS/name).read_bytes()
        if sha256(raw)!=digest:
            raise RuntimeError(f"Production checksum mismatch for {name}: abort, no writes")
    module = (ROUTERS/"multiguard_entitlement_modes.py")
    if not module.is_file() or "def service_valid_until(" not in module.read_text():
        raise RuntimeError("Stage1 pure policy missing")
    upstream_license=load_pinned_source("multiguard_license.py")
    upstream_workshop=load_pinned_source("multiguard_workshop_remote.py")
    prepared={
        "multiguard_license.py":produce_license(
            (ROUTERS/"multiguard_license.py").read_text(),upstream_license),
        "multiguard_workshop_remote.py":produce_workshop(
            (ROUTERS/"multiguard_workshop_remote.py").read_text(),upstream_workshop),
    }
    for name,src in prepared.items():
        compile(src,str(ROUTERS/name),"exec")
    # These production functions are frozen: preserve HTML V4.4, archive,
    # revoke, existing paid extension and all table save operations exactly.
    untouched = (
        "panel_licenses_grid", "panel_grid_archive_license_safe",
        "panel_revoke_license", "panel_grid_save_row",
        "panel_grid_save_name", "panel_grid_save_channel",
        "panel_grid_extend_license",
    )
    original_grid = (ROUTERS/"multiguard_license.py").read_text()
    for name in untouched:
        before = get_function(original_grid,name,decorators=True)
        after = get_function(prepared["multiguard_license.py"],name,decorators=True)
        if before != after:
            raise RuntimeError("Protected V4.4 OWNER function changed: "+name)
    baseline=status_url()
    # OWNER panel is protected: depending on the authentication layer an
    # anonymous request returns either 401 (unauthenticated) or 403 (forbidden).
    # Do not accept 200, redirects or 5xx: the protected baseline must remain.
    if baseline not in (401, 403):
        raise RuntimeError(f"Unexpected protected-panel HTTP status {baseline}; refusing to install")
    print(f"PROTECTED PANEL HTTP BASELINE: {baseline} (must match after restart)")
    print("STAGE2 PREFLIGHT: PASS")
    print("BACKEND PATCH: COMPILES; CSS/THEME NOT MODIFIED")
    if not args.apply:
        print("DRY RUN ONLY; NO CHANGES")
        return
    apply(prepared,baseline)

if __name__ == "__main__":
    main()
