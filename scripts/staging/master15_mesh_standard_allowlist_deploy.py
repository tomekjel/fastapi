#!/usr/bin/env python3
"""MASTER 1.5 narrowly extend the existing MeshCtrl destination allowlist to the
already configured STANDARD group, then invoke ASUS-only guarded move/verify.

The original authorization predicate is retained unmodified for every target
other than the independently validated MESH_STANDARD_GROUP_ID.
Fail closed if deployed code differs from the expected single NotIn guard.
"""
from __future__ import annotations
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_meshcentral as mesh
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers import multiguard_license as license
from app.routers.master15_owner_mesh_group_policy import Group,validate_groups

LIVE=Path("/opt/multiservis/app/routers/multiguard_meshcentral.py")
UNIT="multiservis-api.service"

def api_ready():
    # FastAPI local readiness: do not claim readiness before the process serves.
    from urllib.request import urlopen
    for _ in range(25):
        try:
            with urlopen("http://127.0.0.1:8000/openapi.json",timeout=2) as response:
                if response.status==200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError("FASTAPI_NOT_READY")

def restart():
    subprocess.run(["systemctl","restart",UNIT],check=True,timeout=45)
    api_ready()

def source_guard_patch(src):
    tree=ast.parse(src)
    functions=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="move_registered_node_to_group"]
    if len(functions)!=1:
        raise RuntimeError("MOVE_FUNCTION_NOT_UNIQUE")
    fn=functions[0]
    candidates=[]
    for stmt in ast.walk(fn):
        if not isinstance(stmt,ast.If):
            continue
        # The exact rejection must be solely an allowlist membership check.
        found=False
        for child in stmt.body:
            if isinstance(child,ast.Raise) and isinstance(child.exc,ast.Call):
                call=child.exc
                if (isinstance(call.func,ast.Name) and call.func.id=="MeshCentralError"
                    and call.args and isinstance(call.args[0],ast.Constant)
                    and call.args[0].value=="Docelowa grupa nie jest zatwierdzona dla Multi-Guard."):
                    found=True
        if found:
            candidates.append(stmt)
    if len(candidates)!=1:
        raise RuntimeError("TARGET_APPROVAL_GUARD_NOT_UNIQUE")
    condition=candidates[0].test
    if not (isinstance(condition,ast.Compare) and len(condition.ops)==1
            and isinstance(condition.ops[0],ast.NotIn)
            and isinstance(condition.left,ast.Name) and condition.left.id=="group"
            and len(condition.comparators)==1):
        raise RuntimeError("TARGET_APPROVAL_GUARD_NOT_SIMPLE_NOT_IN")
    # A precise, single-condition extension. All existing checks remain in
    # effect for all groups; only an independently validated configured
    # Standard group may evade this specific two-group allowlist denial.
    lines=src.splitlines(keepends=True)
    original_line=condition.lineno-1
    if condition.lineno!=condition.end_lineno:
        raise RuntimeError("MULTILINE_APPROVAL_GUARD_UNSUPPORTED")
    line=lines[original_line]
    original=line[condition.col_offset:condition.end_col_offset]
    new_condition="(("+original+") and (group != os.environ['MESH_STANDARD_GROUP_ID']))"
    lines[original_line]=line[:condition.col_offset]+new_condition+line[condition.end_col_offset:]
    updated="".join(lines)
    compile(updated,str(LIVE),"exec")
    if updated.count("MESH_STANDARD_GROUP_ID")!=src.count("MESH_STANDARD_GROUP_ID")+1:
        raise RuntimeError("UNEXPECTED_ALLOWLIST_PATCH")
    return updated

def main():
    if os.geteuid()!=0:raise RuntimeError("ROOT_REQUIRED")
    if len(sys.argv)!=2:raise RuntimeError("NEED_ASUS_MOVE_SCRIPT_PATH")
    move_script=Path(sys.argv[1])
    if not move_script.is_file():raise RuntimeError("MOVE_SCRIPT_MISSING")
    # Validate the test pilot before changing any production source.
    pid=int(subprocess.check_output(["systemctl","show","-p","MainPID","--value",UNIT],text=True).strip())
    if pid<2:raise RuntimeError("API_NOT_ACTIVE")
    for kv in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        if b"=" in kv:
            key,value=kv.split(b"=",1)
            if key.startswith(b"MESH_"):
                os.environ[key.decode()]=value.decode()
    ids=validate_groups(os.environ)
    if not (ids[Group.STANDARD]!=ids[Group.SERVICE] and ids[Group.STANDARD]!=ids[Group.CLIENT]):
        raise RuntimeError("STANDARD_GROUP_NOT_DISTINCT")
    with engine.connect() as db:
        rows=db.execute(text("""
            SELECT p.installation_id,p.hostname,s.status,s.requested_group,
                   s.target_mesh_id,s.attempts
            FROM guard.pending_installations p
            JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
            WHERE upper(p.hostname)='ROG'
        """)).mappings().all()
        if len(rows)!=1:raise RuntimeError("ASUS_ROG_NOT_UNIQUE")
        r=rows[0]
        desired,target=sync._current_owner_target(db,r["installation_id"])
        if (r["requested_group"]!="NONE" or desired!="NONE" or target!=ids[Group.STANDARD]
            or r["target_mesh_id"]!=target or r["status"] not in ("RETRY","OK")
            or not sync._verified_standard_shutdown(db,r["installation_id"])):
            raise RuntimeError("SIGNED_STANDARD_GATE_NOT_SATISFIED")
    src=LIVE.read_text(encoding="utf-8")
    updated=source_guard_patch(src)
    # Validate current state exactly before touching file.
    if not callable(getattr(mesh,"move_registered_node_to_group",None)):
        raise RuntimeError("LIVE_MESH_MOVE_HELPER_MISSING")
    backup=Path("/opt/multiservis/backups")/(
        "master15-standard-mesh-allowlist-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    )
    backup.mkdir(parents=True,exist_ok=False)
    shutil.copy2(LIVE,backup/LIVE.name)
    staged=LIVE.with_name(LIVE.name+".master15-staged")
    staged.write_text(updated,encoding="utf-8")
    shutil.copymode(LIVE,staged)
    # Atomic replacement avoids half-written Python modules.
    staged.replace(LIVE)
    applied=True
    try:
        restart()
        print("PASS: MeshCtrl approved-target guard now explicitly permits independently configured Standard")
        print("BACKUP:",backup)
        result=subprocess.run(
            [sys.executable,str(move_script)],cwd="/opt/multiservis",text=True,
            capture_output=True,timeout=90,check=False,
            env=os.environ.copy(),
        )
        # The child prints no secrets; do not forward unknown exception details.
        for line in (result.stdout+"\n"+result.stderr).splitlines():
            if any(item in line for item in (
                "PASS:","ROG_MESH_BEFORE","SOURCE_MESH_TYPE","MESH_MOVE_COMMAND",
                "MESH_MOVE_REDACTED_REASON","MESH_MOVE_NOT_CONFIRMED",
                "STATUS_UNCHANGED","MASTER15_ASUS_STANDARD_MESH_REPAIR",
                "MESH_MOVE_NOT","OWNER Standard","NO_LICENSE",
            )):
                print(line[:320])
        if result.returncode:
            raise RuntimeError("ASUS_MESH_MOVE_OR_READBACK_FAILED")
        if "MASTER15_ASUS_STANDARD_MESH_REPAIR_PASS" not in result.stdout:
            raise RuntimeError("ASUS_MESH_POSTCHECK_NOT_CONFIRMED")
        print("MASTER15_STANDARD_ALLOWLIST_AND_MOVE_PASS")
        print("PASS: durable three-group allowlist; live API restarted")
        print("PASS: ASUS ROG in Standard; OWNER Standard / Brak zdalnego")
        print("PASS: no changes to customer devices or Windows services")
    except Exception:
        # Preserve original implementation if no verified postcheck. The
        # move script itself ensures no false OWNER OK on failed move.
        if applied:
            shutil.copy2(backup/LIVE.name,LIVE)
            try:restart();print("ROLLBACK: previous MeshCentral adapter restored")
            except Exception:print("ROLLBACK_API_RESTART_FAILED_REQUIRES_MANUAL_INTERVENTION")
        raise

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("MASTER15_STANDARD_ALLOWLIST_AND_MOVE_STOP",
              type(exc).__name__,str(exc)[:160],file=sys.stderr)
        raise SystemExit(1)
