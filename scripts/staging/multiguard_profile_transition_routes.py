"""Multi-Guard service-profile transitions: authenticated reservation lifecycle.

This module is deliberately isolated from payments and license changes.
The OWNER switch must remain disabled until server-side session admission
also checks active reservations and a Windows integration test has passed.
"""
from uuid import uuid4, UUID
from fastapi import APIRouter, HTTPException
from sqlalchemy import text
from app.routers import multiguard_workshop_remote as wr

router = APIRouter(prefix="/multiguard", tags=["service-profile-transition"])

class ProfileRequest(wr.WorkshopAuth):
    targetMode: str

class FinishRequest(ProfileRequest):
    reservationId: UUID
    succeeded: bool

def authenticate_transition(req):
    """Authenticate a registered device in either owner mode.

    _authenticate rejects CLIENT after OWNER has switched out of SERVICE.
    That must not prevent the machine from disabling the SERVICE profile.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    when = req.sentAt
    if when.tzinfo is None or abs((now - when).total_seconds()) > 300:
        raise HTTPException(401, "Wygasłe uwierzytelnienie przełączenia.")
    pending = wr.license._authenticate_pending(
        str(req.installationId), req.deviceId, req.discoveryCredential
    )
    if pending["status"] in ("ARCHIVED", "UNINSTALLED", "IGNORED"):
        raise HTTPException(403, "Instalacja nieaktywna.")
    if req.targetMode == "SERVICE_PRO":
        wr._authenticate(req)
    elif req.targetMode != "CLIENT":
        raise HTTPException(400, "Nieprawidłowy profil Windows.")


def check(db, req):
    if req.targetMode not in ("SERVICE_PRO", "CLIENT"):
        raise HTTPException(400, "Nieprawidłowy profil Windows.")
    grant = wr._grant(db, req.installationId)
    # OWNER may have selected CLIENT before Windows finishes restoring its
    # dormant profile; do not deadlock the safe SERVICE -> CLIENT recovery.
    if req.targetMode == "SERVICE_PRO" and not wr._eligible(grant):
        raise HTTPException(403, "Brak aktywnej licencji SERVICE.")
    if req.targetMode == "CLIENT" and (
        not grant or grant["owner_mode"] not in ("CLIENT", "SERVICE")
    ):
        raise HTTPException(403, "Brak uprawnienia do przywrócenia profilu klienta.")
    iid = req.installationId
    # Workshop rows use the canonical UUID. Customer Pro sessions use
    # guard.installations.id, a different UUID. Check each exact scope.
    if db.execute(text("""
        SELECT 1 FROM guard.workshop_remote_sessions
        WHERE installation_id=:iid
          AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        LIMIT 1
    """), {"iid": iid}).first():
        raise HTTPException(409, "Najpierw zamknij sesję serwisową.")
    if db.execute(text("""
        SELECT 1 FROM guard.remote_sessions rs
        JOIN guard.installations gi ON gi.id=rs.installation_id
        WHERE gi.installation_external_id=:iid_text
          AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        LIMIT 1
    """), {"iid_text": str(iid)}).first():
        raise HTTPException(409, "Najpierw zamknij sesję klienta Pro.")

def refuse_while_transition_reserved(db, installation_id):
    """Shared guard for BOTH customer Pro and SERVICE session admission.

    Called inside the same transaction, after locking the installation row.
    A stale/expired reservation is intentionally NOT treated as released:
    only explicit finish or OWNER recovery can settle it.
    """
    row = db.execute(text("""
        SELECT reservation_id FROM guard.workshop_profile_transitions
        WHERE installation_id=:iid AND state='RESERVED'
        LIMIT 1
    """), {"iid": installation_id}).first()
    if row:
        raise HTTPException(409, "Trwa zmiana profilu Windows; połączenie zablokowane.")


def schema(db):
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS guard.workshop_profile_transitions (
            installation_id UUID PRIMARY KEY,
            reservation_id UUID NOT NULL UNIQUE,
            target_mode TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL,
            state TEXT NOT NULL DEFAULT 'RESERVED'
        )
    """))

@router.post("/agent/workshop/profile-transition-begin")
def begin(req: ProfileRequest):
    wr._schema()
    authenticate_transition(req)
    with wr.engine.begin() as db:
        schema(db)
        # Serialize with other transitions for the same installation.
        installation = db.execute(text(
            "SELECT installation_id FROM guard.pending_installations "
            "WHERE installation_id=:iid FOR UPDATE"
        ), {"iid":req.installationId}).scalar_one_or_none()
        if installation is None:
            raise HTTPException(404, "Instalacja nie istnieje.")
        check(db, req)
        row = db.execute(text("""
            SELECT reservation_id FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' FOR UPDATE
        """), {"iid":req.installationId}).first()
        if row:
            raise HTTPException(409, "Poprzednie przełączenie wymaga zakończenia.")
        rid = uuid4()
        db.execute(text("""
            INSERT INTO guard.workshop_profile_transitions
              (installation_id,reservation_id,target_mode,expires_at,state)
            VALUES (:iid,:rid,:target,now()+interval '10 minutes','RESERVED')
            ON CONFLICT (installation_id) DO UPDATE SET
              reservation_id=EXCLUDED.reservation_id,
              target_mode=EXCLUDED.target_mode,
              created_at=now(),expires_at=EXCLUDED.expires_at,state='RESERVED'
        """), {"iid":req.installationId,"rid":rid,"target":req.targetMode})
    return {"requestId":req.requestId,"targetMode":req.targetMode,
            "allowed":True,"reservationId":str(rid)}

@router.post("/agent/workshop/profile-transition-finish")
def finish(req: FinishRequest):
    wr._schema()
    authenticate_transition(req)
    with wr.engine.begin() as db:
        schema(db)
        row=db.execute(text("""
            SELECT reservation_id,target_mode,state,expires_at
            FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":req.installationId}).mappings().first()
        if not row or row["reservation_id"] != req.reservationId or row["target_mode"] != req.targetMode:
            raise HTTPException(409,"Rezerwacja nie odpowiada instalacji.")
        if row["state"] != "RESERVED":
            raise HTTPException(409,"Rezerwacja została już zakończona.")
        # Expiry is never automatic approval to open new remote sessions.
        # An expired reservation requires OWNER reconciliation.
        from datetime import datetime, timezone
        if row["expires_at"] <= datetime.now(timezone.utc):
            raise HTTPException(409,"Rezerwacja wygasła. Wymagana kontrola OWNER.")
        db.execute(text("""
            UPDATE guard.workshop_profile_transitions SET state=:state
            WHERE installation_id=:iid
        """),{"iid":req.installationId,"state":"COMPLETED" if req.succeeded else "ABORTED"})
    return {"requestId":req.requestId,"targetMode":req.targetMode,"released":True}

@router.post("/agent/workshop/profile-transition-recovery-status")
def recovery_status(req: wr.WorkshopAuth):
    wr._schema()
    authenticate_transition(req)
    with wr.engine.begin() as db:
        schema(db)
        row=db.execute(text("""
            SELECT reservation_id,target_mode,created_at,state
            FROM guard.workshop_profile_transitions WHERE installation_id=:iid
        """),{"iid":req.installationId}).mappings().first()
    return {"requestId":req.requestId,"pending":bool(row and row["state"]=="RESERVED"),
            "reservationId":str(row["reservation_id"]) if row else None,
            "targetMode":row["target_mode"] if row else None,
            "ownerRecoveryApproved":False}

class RecoverRequest(ProfileRequest):
    reservationId: UUID
    verifiedProfile: str
    localConfirmation: bool

@router.post("/agent/workshop/profile-transition-recover")
def recover(req: RecoverRequest):
    # Never trust a local assertion by itself as proof of administrator
    # authorization. Separate OWNER approval workflow is still required.
    authenticate_transition(req)
    raise HTTPException(409, "Odzyskanie wymaga odrębnego zatwierdzenia OWNER.")

