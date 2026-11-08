#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
print("=== MASTER 1.5 / STANDARD ASUS READONLY ===")
with engine.connect() as db:
    rows=db.execute(text("""
        SELECT p.installation_id, p.hostname, p.status AS installation_status,
               l.lifecycle,l.plan_code,l.rebind_pending,
               l.accepted_at IS NOT NULL AS accepted,
               l.valid_until > now() AS unexpired,
               l.credential_sha256 IS NOT NULL AS credential_present
        FROM guard.pending_installations p
        LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
        WHERE upper(p.hostname)='ROG'
        ORDER BY p.last_seen_at DESC
        LIMIT 5
    """)).mappings().all()
    for n,r in enumerate(rows,1):
        print("DEVICE",n,"HOST",r["hostname"],"INSTALLATION",r["installation_status"],"LIFECYCLE",r["lifecycle"],
              "PLAN",r["plan_code"],"ACCEPTED",r["accepted"],"UNEXPIRED",r["unexpired"],
              "CREDENTIAL_PRESENT",r["credential_present"],"REBIND",r["rebind_pending"])
        try:
            mode=lic._owner_effective_entitlement_mode(db,r["installation_id"])
            print("OWNER_MODE",mode)
        except Exception as exc:
            print("OWNER_MODE_ERROR",type(exc).__name__)
        reservation=db.execute(text("""
            SELECT state,target_mode,expires_at>now() AS unexpired
            FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid
        """),{"iid":r["installation_id"]}).mappings().first()
        print("RESERVATION",dict(reservation) if reservation else "NONE")
        sessions=db.execute(text("""
            SELECT
            (SELECT count(*) FROM guard.workshop_remote_sessions
              WHERE installation_id=:iid AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')) as service,
            (SELECT count(*) FROM guard.remote_sessions rs
              JOIN guard.installations gi ON gi.id=rs.installation_id
              WHERE gi.installation_external_id=:iids AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')) as client
        """),{"iid":r["installation_id"],"iids":str(r["installation_id"])}).mappings().first()
        print("OPEN_SESSIONS",dict(sessions))
    if not rows: print("ROG_NOT_FOUND")
print("=== END READONLY ===")
PY
