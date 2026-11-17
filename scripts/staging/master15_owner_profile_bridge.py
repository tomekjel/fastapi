"""MASTER 1.5 / 3-of-6: optional bridge for the EXISTING OWNER/WORKSHOP backend.

This is NOT a replacement license router. Register beside the currently
deployed routers only after verifying the live LXC schema. SERVICE grants are
intentionally unavailable until first-local-consent and OWNER mode handling
is wired end to end in the Windows broker.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.routers import multiguard_license as license
from app.routers import multiguard_workshop_remote as workshop
from app.routers.multiguard_owner_profile_grant import create_profile_transition_grant

router = APIRouter(prefix="/v1/multi-guard", tags=["owner-profile-bridge"])

class Identity(BaseModel):
    requestId: str = Field(min_length=8, max_length=128)
    nonce: str = Field(min_length=8, max_length=128)
    sentAt: datetime
    installationId: UUID
    deviceId: str = Field(min_length=16, max_length=128)
    installationCredential: str = Field(min_length=32, max_length=512)
    appVersion: str = Field(default="", max_length=100)

class TransitionReport(Identity):
    reservationId: UUID
    succeeded: bool
    observedProfile: str

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _identity_guard(req: Identity) -> None:
    delta = req.sentAt
    if delta.tzinfo is None or abs((_now()-delta.astimezone(timezone.utc)).total_seconds()) > 120:
        raise HTTPException(401, "Wygasłe żądanie OWNER.")

def _authenticated_link(db, req: Identity):
    row = db.execute(text("""
        SELECT * FROM guard.license_links
        WHERE installation_id=:iid AND device_id=:device_id FOR UPDATE
    """), {"iid":req.installationId,"device_id":req.deviceId}).mappings().first()
    digest=hashlib.sha256(req.installationCredential.encode("utf-8")).hexdigest()
    if not row or not row.get("credential_sha256") or not hmac.compare_digest(
        str(row["credential_sha256"]),digest):
        raise HTTPException(401,"Instalacja nie jest uwierzytelniona.")
    return row

def _owner_target(db, iid: UUID, link) -> str:
    # Existing production function uses the real owner_entitlement_selections
    # and pending_installations tables (not the heartbeat mirror).
    if license._owner_effective_entitlement_mode(db,iid) != "CLIENT":
        raise HTTPException(409, "OWNER nie wybrał trybu klienta.")
    if link["lifecycle"] != "ACTIVE" or link.get("rebind_pending"):
        raise HTTPException(409, "Licencja klienta nie jest aktywna.")
    expires = link.get("valid_until")
    if not expires or expires <= _now() or not link.get("accepted_at"):
        raise HTTPException(409, "Licencja klienta wygasła.")
    if link["plan_code"] == "multi_guard_pro": return "PRO"
    if link["plan_code"] == "multi_guard": return "STANDARD"
    raise HTTPException(409,"Nieznana edycja OWNER.")

@router.post("/owner-profile-grant")
def owner_profile_grant(req:Identity):
    """Single-use signed grant, using existing workshop reservation table."""
    _identity_guard(req)
    workshop._schema()
    # Commercial KeyGate verification precedes creating a reservation.
    # No response-supplied target or Windows command is accepted.
    with workshop.engine.begin() as db:
        pending=db.execute(text("""
            SELECT installation_id,status FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":req.installationId}).mappings().first()
        if not pending or pending["status"] in ("ARCHIVED","UNINSTALLED","IGNORED"):
            raise HTTPException(409,"Instalacja nie jest aktywna.")
        link=_authenticated_link(db,req)
        target=_owner_target(db,req.installationId,link)
        # Existing helper checks both session kinds. Existing session-admission
        # routes also reject a RESERVED profile transition.
        workshop._service_transition_sessions(db,req.installationId)
        occupied=db.execute(text("""
            SELECT reservation_id FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid AND state='RESERVED' FOR UPDATE
        """),{"iid":req.installationId}).scalar_one_or_none()
        if occupied:
            raise HTTPException(409,"Poprzednie przełączenie nadal trwa.")
        # A newly provisioned installation may reach this authenticated OWNER
        # profile broker without an owner_mesh_group_sync row. Bootstrap its
        # saved OWNER target BEFORE issuing the Windows reservation, so the
        # subsequently verified SCM report cannot predate the sync request.
        # Never rewrite an existing revision on every routine licence poll.
        from app.routers import master15_owner_mesh_sync_engine as mesh_sync
        mesh_sync.ensure_schema(db)
        existing_sync = db.execute(text("""
            SELECT requested_group FROM guard.owner_mesh_group_sync
            WHERE installation_id=:iid
        """), {"iid":req.installationId}).scalar_one_or_none()
        if existing_sync is None:
            mesh_sync.queue_after_owner_save(db, req.installationId)
        rid=uuid4()
        db.execute(text("""
            INSERT INTO guard.workshop_profile_transitions
              (installation_id,reservation_id,target_mode,expires_at,state)
            VALUES (:iid,:rid,:target,now()+interval '10 minutes','RESERVED')
            ON CONFLICT (installation_id) DO UPDATE SET
              reservation_id=EXCLUDED.reservation_id,
              target_mode=EXCLUDED.target_mode,
              created_at=now(),
              expires_at=EXCLUDED.expires_at,
              state='RESERVED'
        """),{"iid":req.installationId,"rid":rid,"target":target})
        grant=create_profile_transition_grant(
            installation_id=req.installationId,
            device_id=req.deviceId,
            target=target,
            request_id=rid,
            signing_key=license._signing_key(),
        )
    return {"requestId":req.requestId,"reservationId":str(rid),"grant":grant}

def _sync_standard_after_verified_ack(iid: UUID, reservation_id: UUID) -> None:
    """Run only after the signed Windows receipt was accepted and committed."""
    import logging
    from app.routers import master15_owner_mesh_sync_engine as sync
    try:
        with workshop.engine.begin() as db:
            # The signed Windows report may be the first occasion on which a
            # freshly provisioned Standard installation enters OWNER Mesh sync.
            # If the sync row is created AFTER the completed Windows report,
            # its default requested_at would be newer than the report's
            # created_at. _verified_standard_shutdown would then reject that
            # very report forever as "stale".
            sync.ensure_schema(db)
            previous = db.execute(text("""
                SELECT revision,requested_group,requested_at
                FROM guard.owner_mesh_group_sync
                WHERE installation_id=:iid FOR UPDATE
            """), {"iid":iid}).mappings().first()
            sync.queue_after_owner_save(db, iid)
            if previous is None:
                # Bind this initial request to the exact independently verified
                # completed Standard reservation, never to a past receipt on an
                # existing OWNER revision. The row is installation-scoped.
                db.execute(text("""
                    UPDATE guard.owner_mesh_group_sync s
                    SET requested_at=t.created_at
                    FROM guard.workshop_profile_transitions t
                    WHERE s.installation_id=:iid
                      AND t.installation_id=s.installation_id
                      AND t.reservation_id=:reservation_id
                      AND s.requested_group='NONE'
                      AND s.status='WAITING'
                      AND t.state='COMPLETED'
                      AND t.target_mode='STANDARD'
                      AND t.created_at IS NOT NULL
                      AND t.created_at < s.requested_at
                """), {"iid":iid, "reservation_id":reservation_id})
            # A prior failed Standard attempt is automatically requeued.
            sync.request_manual_retry(db, iid)
        sync.run_pending_installation(workshop.engine, iid)
    except Exception:
        logging.getLogger("multiguard.owner.mesh").exception(
            "Standard group sync after verified Windows receipt failed")


@router.post("/owner-profile-report")
def owner_profile_report(req:TransitionReport, background_tasks: BackgroundTasks):
    """Release only the matching verified Standard/Pro transition."""
    _identity_guard(req)
    workshop._schema()
    with workshop.engine.begin() as db:
        db.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":req.installationId}).one()
        link=_authenticated_link(db,req)
        reservation=db.execute(text("""
            SELECT reservation_id,target_mode,state,expires_at
            FROM guard.workshop_profile_transitions
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":req.installationId}).mappings().first()
        if (not reservation or reservation["state"]!="RESERVED"
            or reservation["reservation_id"]!=req.reservationId):
            raise HTTPException(409,"Rezerwacja OWNER jest nieaktualna.")
        if reservation["expires_at"]<=_now():
            raise HTTPException(409,"Rezerwacja OWNER wygasła.")
        expected={"STANDARD":"ClientDormant","PRO":"ClientRunning"}
        target=str(reservation["target_mode"])
        if not req.succeeded or expected.get(target)!=req.observedProfile:
            raise HTTPException(409,"Windows SCM nie potwierdził profilu OWNER.")
        if _owner_target(db,req.installationId,link)!=target:
            raise HTTPException(409,"Edycja OWNER zmieniła się podczas przełączania.")
        db.execute(text("""
            UPDATE guard.workshop_profile_transitions SET state='COMPLETED'
            WHERE installation_id=:iid AND reservation_id=:rid AND state='RESERVED'
        """),{"iid":req.installationId,"rid":req.reservationId})
    if target == "STANDARD":
        background_tasks.add_task(_sync_standard_after_verified_ack, req.installationId, req.reservationId)
    return {"requestId":req.requestId,"reservationId":str(req.reservationId),
            "state":"COMPLETED","admissionBlocked":False}
