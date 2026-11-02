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

def check(db, req):
    if req.targetMode not in ("SERVICE_PRO", "CLIENT"):
        raise HTTPException(400, "Nieprawidłowy profil Windows.")
    grant = wr._grant(db, req.installationId)
    if not wr._eligible(grant):
        raise HTTPException(403, "Brak aktywnej licencji SERVICE.")
    iid = req.installationId
    for table in ("guard.remote_sessions", "guard.workshop_remote_sessions"):
        if db.execute(text(
            "SELECT 1 FROM " + table +
            " WHERE installation_id=:iid AND status IN "
            "('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE') LIMIT 1"
        ), {"iid": iid}).first():
            raise HTTPException(409, "Najpierw zamknij sesję zdalną.")

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
    wr._authenticate(req)
    with wr.engine.begin() as db:
        schema(db)
        # Serialize with other transitions for the same installation.
        db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE installation_id=:iid FOR UPDATE"),
                   {"iid":req.installationId}).first()
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
    wr._authenticate(req)
    with wr.engine.begin() as db:
        schema(db)
        row=db.execute(text("""
            SELECT reservation_id,target_mode,state
            FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":req.installationId}).mappings().first()
        if not row or row["reservation_id"] != req.reservationId or row["target_mode"] != req.targetMode:
            raise HTTPException(409,"Rezerwacja nie odpowiada instalacji.")
        if row["state"] != "RESERVED":
            raise HTTPException(409,"Rezerwacja została już zakończona.")
        db.execute(text("""
            UPDATE guard.workshop_profile_transitions SET state=:state
            WHERE installation_id=:iid
        """),{"iid":req.installationId,"state":"COMPLETED" if req.succeeded else "ABORTED"})
    return {"requestId":req.requestId,"targetMode":req.targetMode,"released":True}

@router.post("/agent/workshop/profile-transition-recovery-status")
def recovery_status(req: wr.WorkshopAuth):
    wr._schema()
    wr._authenticate(req)
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
    wr._authenticate(req)
    raise HTTPException(409, "Odzyskanie wymaga odrębnego zatwierdzenia OWNER.")

