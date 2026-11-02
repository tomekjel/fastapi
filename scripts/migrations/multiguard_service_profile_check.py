#!/usr/bin/env python3
"""Install a read-only, fail-closed SERVICE Windows profile preflight endpoint.

No new DB tables, reservations or license writes. Active remote sessions block
the staging request. Existing mode rights and registered agent identity required.
"""
from pathlib import Path
import ast
import shutil
from datetime import datetime,timezone
p=Path("app/routers/multiguard_workshop_remote.py")
s=p.read_text(encoding="utf-8")
needle='@router.post("/agent/workshop/profile-transition-check")'
if needle in s:
    print("ALREADY_PRESENT")
    raise SystemExit(0)
anchor='@router.post("/agent/workshop/standing/status"'
if anchor not in s: raise SystemExit("ABORT: unknown router structure")
code='''
class WorkshopProfileTransitionCheck(WorkshopAuth):
    targetMode: str


@router.post("/agent/workshop/profile-transition-check")
def workshop_profile_transition_check(request: WorkshopProfileTransitionCheck):
    """Authorize only dormant staging after checking the current server mode."""
    import uuid
    _schema()
    _authenticate(request)
    if request.targetMode != "SERVICE_PRO":
        raise HTTPException(400, "Nieprawidłowy docelowy profil Windows.")
    iid = uuid.UUID(str(request.installationId))
    with engine.begin() as db:
        mode = license._owner_effective_entitlement_mode(db, iid)
        grant = _grant(db, iid)
        if mode != "SERVICE" or not _eligible(grant):
            raise HTTPException(403, "SERVICE nie jest aktywną licencją.")
        # The profile change must never occur while remote viewing is active.
        busy_client = db.execute(text("""
            SELECT 1 FROM guard.remote_sessions
            WHERE installation_id=:iid
              AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
            LIMIT 1
        """), {"iid":iid}).first()
        busy_service = db.execute(text("""
            SELECT 1 FROM guard.workshop_remote_sessions
            WHERE installation_id=:iid
              AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
            LIMIT 1
        """), {"iid":iid}).first()
        if busy_client or busy_service:
            raise HTTPException(409, "Zakończ aktywne sesje zdalne.")
    return {"requestId":request.requestId,"targetMode":"SERVICE_PRO","allowed":True}


'''
u=s.replace(anchor,code+anchor,1)
ast.parse(u)
backup=p.with_name(p.name+".backup-profile-check-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
shutil.copy2(p,backup)
p.write_text(u,encoding="utf-8")
print("PATCH_OK",backup)
print("NO LICENSE CHANGE; NO REMOTE ACCESS ACTIVATION")
