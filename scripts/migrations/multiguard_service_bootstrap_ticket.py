#!/usr/bin/env python3
"""Install authenticated short-lived SERVICE bootstrap ticket endpoint.
Only for already authorized, bound and locally attested devices.
No license writes, no Mesh modifications, no unattended authorization.
"""
from pathlib import Path
from datetime import datetime,timezone
import ast,shutil
p=Path("app/routers/multiguard_workshop_remote.py")
s=p.read_text(encoding="utf-8")
marker='@router.post("/agent/workshop/standing/bootstrap-ticket")'
anchor='@router.post("/agent/workshop/standing/status"'
if marker in s:
 print("ALREADY_PRESENT");raise SystemExit(0)
if anchor not in s:raise SystemExit("STOP: unexpected production module")
addition='''
@router.post("/agent/workshop/standing/bootstrap-ticket")
def workshop_service_bootstrap_ticket(request: WorkshopAuth):
    """60-second device-specific signed enrollment ticket, not remote consent."""
    import base64
    import json
    import os
    import re
    import uuid
    from datetime import timedelta
    _schema()
    _authenticate(request)
    iid = uuid.UUID(str(request.installationId))
    with engine.connect() as db:
        mode = license._owner_effective_entitlement_mode(db, iid)
        grant = _grant(db, iid)
        record = standing_authorization_record(db, iid) if _eligible(grant) else None
    if mode != "SERVICE" or not _eligible(grant) or not grant.get("mesh_node_id"):
        raise HTTPException(403, "Brak aktywnej serwisowej autoryzacji.")
    if (not record or record["owner_approved_at"] is None
        or record["revoked_at"] is not None
        or record["local_opt_in_attested_at"] is None
        or record["approved_mesh_node_id"] != grant["mesh_node_id"]):
        raise HTTPException(403, "Brak zgody OWNER lub lokalnej zgody na SERVICE.")
    consent = str(record["prior_consent_sha256"] or "")
    if not re.fullmatch(r"[0-9a-f]{64}", consent):
        raise HTTPException(403, "Nieprawidłowy zapis wcześniejszej zgody.")
    group = os.environ.get("MESH_SERVICE_PRO_GROUP_ID", "").strip()
    if not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}", group):
        raise HTTPException(503, "Grupa SERVICE nie jest skonfigurowana.")
    issued = _now()
    claims = {
        "schemaVersion": 1, "kind": "MG_SERVICE_PRO_BOOTSTRAP_V1",
        "installationId": str(iid), "deviceId": str(request.deviceId),
        "requestId": str(request.requestId), "nonce": str(uuid.uuid4()),
        "profile": "SERVICE_PRO", "meshGroupId": group,
        "priorConsentSha256": consent,
        "issuedAt": issued.isoformat(),
        "expiresAt": (issued + timedelta(seconds=45)).isoformat(),
        "enrollmentOnly": True, "unattendedAuthorized": False,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    signature = license._signing_key().sign(payload.encode("utf-8"))
    return {"requestId": request.requestId, "ticket": {
        "payload": payload, "signatureB64": base64.b64encode(signature).decode("ascii")
    }}


'''
changed=s.replace(anchor,addition+anchor,1)
ast.parse(changed)
backup=p.with_name(p.name+".backup-bootstrap-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
shutil.copy2(p,backup)
p.write_text(changed,encoding="utf-8")
print("PATCH_OK",backup)
print("NOTE: activation is not enabled; prior authorization mandatory")
