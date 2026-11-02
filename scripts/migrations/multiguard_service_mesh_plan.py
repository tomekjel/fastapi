#!/usr/bin/env python3
"""One safe FastAPI endpoint for Multi-Guard SERVICE Mesh plan (read-only).

Uses configured MESH_SERVICE_PRO_GROUP_ID; refuses to guess a group.
Requires authenticated discovery identity AND effective SERVICE rights.
Does not enable license switch, sign bootstrap, or start unattended access.
"""
import ast
from datetime import datetime, timezone
from pathlib import Path
import shutil

p=Path("app/routers/multiguard_workshop_remote.py")
s=p.read_text(encoding="utf-8")
needle='@router.post("/agent/workshop/mesh-provisioning-plan")'
if needle in s:
    print("ALREADY_PRESENT; inspect implementation before changing")
    raise SystemExit(0)
anchor='@router.post("/agent/workshop/standing/status"'
if anchor not in s:
    raise SystemExit("ABORT: unknown production router layout")
addition='''
@router.post("/agent/workshop/mesh-provisioning-plan")
def workshop_mesh_provisioning_plan(request: WorkshopAuth):
    """Read-only plan; a response does not grant unattended access."""
    import os
    import re
    import uuid
    _schema()
    _authenticate(request)
    with engine.connect() as db:
        mode = license._owner_effective_entitlement_mode(
            db, uuid.UUID(str(request.installationId))
        )
        grant = _grant(db, request.installationId)
    if mode != "SERVICE" or not _eligible(grant):
        raise HTTPException(403, "Wymagane aktywne SERVICE.")
    mesh_group = os.environ.get("MESH_SERVICE_PRO_GROUP_ID", "").strip()
    if not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", mesh_group):
        raise HTTPException(503, "Nie skonfigurowano zatwierdzonej grupy SERVICE MeshCentral.")
    return {
        "requestId": request.requestId,
        "mode": "SERVICE_PRO",
        "meshGroupId": mesh_group,
        "requiredAgentProfile": "SERVICE_PRO",
        "unattendedAuthorized": False,
    }

'''
updated=s.replace(anchor,addition+anchor,1)
ast.parse(updated)
backup=p.with_name(p.name+".backup-service-mesh-plan-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
shutil.copy2(p,backup)
p.write_text(updated,encoding="utf-8")
print("PATCH_OK",backup)
print("NOTE: SERVICE mode flag and unattended access unchanged")
