"""OWNER-only workshop PRO remote sessions, separated from KeyGate licences.

The 0.3.42 BETA Windows client authenticates with its existing discovery
credential. No commercial licence, synthetic KeyGate key, or remote access
without an explicit per-session desktop consent is created here.
"""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner
from app.routers import multiguard_license as license
from app.routers import multiguard_meshcentral as meshcentral
from app.routers import multiguard_remote as paid_remote

router = APIRouter(prefix="/multiguard", tags=["multi-guard-workshop-remote"])
_lock = threading.Lock()
_ready = False
OPEN = ("REQUESTED", "CONSENTED", "CONNECT_READY", "ACTIVE")


class WorkshopAuth(BaseModel):
    requestId: str = Field(min_length=8, max_length=128)
    nonce: str = Field(min_length=8, max_length=128)
    sentAt: datetime
    installationId: uuid.UUID
    deviceId: str = Field(min_length=16, max_length=128)
    discoveryCredential: str = Field(min_length=32, max_length=512)


class WorkshopMeshEnrollment(WorkshopAuth):
    # Local MeshAgent registry NodeId, without domain or node/ prefix.
    meshNodeId: str = Field(min_length=64, max_length=64)


class WorkshopDecision(WorkshopAuth):
    sessionId: uuid.UUID
    allowDesktop: bool
    allowFiles: bool = False


class WorkshopEnd(WorkshopAuth):
    sessionId: uuid.UUID
    reason: str = Field(default="CLIENT_ENDED", max_length=80)


class WorkshopSupport(WorkshopAuth):
    localRequestId: uuid.UUID
    subject: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=6000)
    diagnosticsIncluded: bool = False
    diagnostics: Any = None


def _now():
    return datetime.now(timezone.utc)


def _schema():
    global _ready
    if _ready:
        return
    paid_remote._ensure_schema()
    with _lock:
        if _ready:
            return
        with engine.begin() as db:
            for query in (
                """CREATE TABLE IF NOT EXISTS guard.workshop_mesh_nodes (
                   installation_id UUID PRIMARY KEY
                     REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                   mesh_node_id TEXT NOT NULL UNIQUE,
                   updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_support_requests (
                   id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                   local_request_id UUID NOT NULL UNIQUE,
                   installation_id UUID NOT NULL
                     REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                   subject TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                   diagnostics_included BOOLEAN NOT NULL DEFAULT FALSE,
                   created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
                """CREATE INDEX IF NOT EXISTS ix_workshop_support_installation
                   ON guard.workshop_support_requests(installation_id,created_at DESC)""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_remote_sessions (
                   id UUID PRIMARY KEY,
                   installation_id UUID NOT NULL
                     REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                   subject TEXT NOT NULL DEFAULT 'Zdalna pomoc serwisowa',
                   requested_by_name TEXT NOT NULL DEFAULT 'OWNER',
                   status TEXT NOT NULL CHECK (status IN
                     ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE','DENIED',
                      'ENDED','EXPIRED','ERROR')),
                   requested_capabilities JSONB NOT NULL DEFAULT '["desktop"]'::jsonb,
                   granted_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
                   requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                   expires_at TIMESTAMPTZ NOT NULL,
                   consented_at TIMESTAMPTZ,connected_at TIMESTAMPTZ,
                   reconnect_until TIMESTAMPTZ,ended_at TIMESTAMPTZ,
                   last_activity_at TIMESTAMPTZ,
                   mesh_public_id TEXT,mesh_share_expires_at TIMESTAMPTZ,
                   last_error TEXT)""",
                """CREATE UNIQUE INDEX IF NOT EXISTS uq_workshop_remote_open
                   ON guard.workshop_remote_sessions(installation_id)
                   WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_remote_events (
                   id BIGSERIAL PRIMARY KEY,
                   session_id UUID NOT NULL REFERENCES guard.workshop_remote_sessions(id)
                     ON DELETE CASCADE,
                   event_type TEXT NOT NULL,actor_type TEXT NOT NULL,
                   occurred_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
            ):
                db.execute(text(query))
        _ready = True


def _grant(db, iid):
    return db.execute(text("""
        SELECT g.edition,g.enabled,p.status,p.installation_id,m.mesh_node_id
        FROM guard.pending_installations p
        LEFT JOIN guard.workshop_grants g ON g.installation_id=p.installation_id
        LEFT JOIN guard.workshop_mesh_nodes m ON m.installation_id=p.installation_id
        WHERE p.installation_id=:id
    """), {"id": iid}).mappings().first()


def _eligible(grant):
    return bool(
        grant and grant["edition"] == "PRO" and grant["enabled"]
        and grant["status"] not in ("ASSIGNED", "PROVISIONED", "ARCHIVED", "UNINSTALLED", "IGNORED")
    )


def _authenticate(request: WorkshopAuth):
    # Digest comparison and device binding are done by the existing registered
    # discovery identity; never create credentials during remote requests.
    now = _now()
    when = request.sentAt
    if when.tzinfo is None or abs((now - when).total_seconds()) > 300:
        raise HTTPException(401, "Wygasłe uwierzytelnienie żądania zdalnego.")
    pending = license._authenticate_pending(
        str(request.installationId), request.deviceId, request.discoveryCredential
    )
    if pending["status"] in ("ASSIGNED", "PROVISIONED", "ARCHIVED", "UNINSTALLED", "IGNORED"):
        raise HTTPException(403, "Instalacja nie ma aktywnego trybu serwisowego.")
    return pending


def _event(db, sid, code, actor="BACKEND"):
    db.execute(text("""
        INSERT INTO guard.workshop_remote_events(session_id,event_type,actor_type)
        VALUES (:id,:code,:actor)
    """), {"id": sid, "code": code, "actor": actor})


def _public(row):
    if row is None:
        return None
    # Wire-compatible with the 0.3.42 BETA RemoteSessionSnapshot.
    return {
        "sessionId": str(row["id"]),
        "supportRequestId": str(row["id"]),
        "status": row["status"],
        "technicianDisplayName": row["requested_by_name"],
        "subject": row["subject"],
        "requestedCapabilities": list(row["requested_capabilities"] or []),
        "grantedCapabilities": list(row["granted_capabilities"] or []),
        "requestedAt": paid_remote._iso(row["requested_at"]),
        "expiresAt": paid_remote._iso(row["expires_at"]),
        "consentedAt": paid_remote._iso(row["consented_at"]),
        "connectedAt": paid_remote._iso(row["connected_at"]),
        "endedAt": paid_remote._iso(row["ended_at"]),
        "reconnectUntil": paid_remote._iso(row["reconnect_until"]),
        "meshReady": bool(row["mesh_public_id"]),
        "lastError": row["last_error"],
    }


def _open(db, iid, *, entitlement_lost=False):
    """No SQL EXPIRED until MeshCentral confirms the old share is revoked."""
    grant = _grant(db, iid)
    active = db.execute(text("""
        SELECT * FROM guard.workshop_remote_sessions
        WHERE installation_id=:id AND status IN
             ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        FOR UPDATE
    """), {"id": iid}).mappings().first()
    if not active:
        return None
    now = _now()
    timeout = (
        active["status"] in ("REQUESTED", "CONSENTED") and active["expires_at"] < now
    ) or (
        active["status"] in ("CONNECT_READY", "ACTIVE")
        and active["mesh_share_expires_at"] is not None
        and active["mesh_share_expires_at"] < now
    )
    if timeout or entitlement_lost or not _eligible(grant):
        if active["mesh_public_id"]:
            if not grant or not grant["mesh_node_id"]:
                raise HTTPException(502, "Nie można potwierdzić cofnięcia linku MeshCentral.")
            try:
                meshcentral.revoke_share(grant["mesh_node_id"], active["mesh_public_id"])
            except meshcentral.MeshCentralError as exc:
                raise HTTPException(502, "Nie potwierdzono cofnięcia wygasłego dostępu.") from exc
        db.execute(text("""
            UPDATE guard.workshop_remote_sessions SET status='EXPIRED',
                ended_at=COALESCE(ended_at,:now),last_activity_at=:now,
                mesh_public_id=NULL,mesh_share_expires_at=NULL WHERE id=:sid
        """), {"now": now, "sid":active["id"]})
        _event(db, active["id"], "ENTITLEMENT_LOST" if entitlement_lost else "EXPIRED")
        return None
    return active


def close_before_rights_change(db, iid: uuid.UUID):
    """Called with guard.workshop_grants row locked in one DB transaction.

    If Mesh revoke fails, the surrounding SQL transaction rolls back and
    leaves the PRO entitlement in place for a retry instead of falsely
    claiming remote access was disabled.
    """
    _open(db, iid, entitlement_lost=True)


def request_for_owner(iid: uuid.UUID):
    """Called only from authenticated OWNER web form; no public route."""
    _schema()
    with engine.begin() as db:
        grant = _grant(db, iid)
        if not _eligible(grant):
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
        if not grant["mesh_node_id"]:
            raise HTTPException(409, "Najpierw powiąż komputer z MeshCentral.")
        if _open(db, iid):
            raise HTTPException(409, "Dla komputera istnieje już otwarta sesja.")
        sid = uuid.uuid4()
        db.execute(text("""
            INSERT INTO guard.workshop_remote_sessions(
                id,installation_id,status,expires_at,last_activity_at)
            VALUES (:sid,:iid,'REQUESTED',:expires,:now)
        """), {"sid":sid,"iid":iid,"expires":_now()+timedelta(minutes=5),"now":_now()})
        _event(db,sid,"OWNER_REQUESTED","TECHNICIAN")
        return sid


@router.post("/agent/workshop/mesh-enroll")
def workshop_mesh_enroll(request: WorkshopMeshEnrollment):
    """Identity-bound registration; OWNER never has to type MeshCentral node IDs."""
    _schema()
    _authenticate(request)
    local_id = request.meshNodeId
    if not re.fullmatch(r"[A-Za-z0-9@$]{64}", local_id):
        raise HTTPException(400, "Nieprawidłowy identyfikator MeshAgent.")
    domain = os.getenv("MESH_CENTRAL_DOMAIN_ID", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{0,64}", domain):
        raise HTTPException(503, "Nieprawidłowa domena MeshCentral.")
    node = f"node/{domain}/{local_id}"
    # Server-side read-only verification defeats guessed IDs and hostname
    # collisions; never trust the client-provided node ID without MeshCtrl.
    try:
        verified = meshcentral.verify_registered_node(node)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(503, "MeshCentral nie potwierdził rejestracji agenta.") from exc
    if not verified:
        raise HTTPException(409, "MeshAgent nie jest jeszcze zarejestrowany na serwerze.")
    with engine.begin() as db:
        # Serialize against OWNER revocation and PRO->STANDARD downgrade.
        grant_lock = db.execute(text("""
            SELECT enabled,edition FROM guard.workshop_grants
            WHERE installation_id=:id FOR UPDATE
        """), {"id":request.installationId}).mappings().first()
        if not grant_lock or not grant_lock["enabled"] or grant_lock["edition"] != "PRO":
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
        grant = _grant(db, request.installationId)
        if not _eligible(grant):
            raise HTTPException(403, "Instalacja nie ma aktywnego serwisowego Pro.")
        commercial = db.execute(text("""
            SELECT 1 FROM guard.installations
            WHERE mesh_node_id=:node AND is_current=TRUE LIMIT 1
        """), {"node":node}).first()
        if commercial:
            raise HTTPException(409, "Węzeł należy do innego typu instalacji.")
        assigned = db.execute(text("""
            SELECT mesh_node_id FROM guard.workshop_mesh_nodes
            WHERE installation_id=:iid FOR UPDATE
        """), {"iid":request.installationId}).scalar_one_or_none()
        if assigned and assigned != node:
            open_session = db.execute(text("""
                SELECT 1 FROM guard.workshop_remote_sessions
                WHERE installation_id=:iid
                  AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
                LIMIT 1
            """), {"iid":request.installationId}).first()
            if open_session:
                raise HTTPException(409, "Nie można zmieniać węzła podczas sesji.")
        db.execute(text("""
            INSERT INTO guard.workshop_mesh_nodes (installation_id,mesh_node_id)
            VALUES (:iid,:node)
            ON CONFLICT (installation_id) DO UPDATE
            SET mesh_node_id=EXCLUDED.mesh_node_id,updated_at=now()
        """), {"iid":request.installationId, "node":node})
    return {"requestId":request.requestId,"accepted":True,
            "meshReady":True,"serverTime":_now().isoformat()}


@router.post("/agent/workshop/support-request")
def workshop_support_request(request: WorkshopSupport):
    _schema()
    _authenticate(request)
    with engine.begin() as db:
        if not _eligible(_grant(db,request.installationId)):
            raise HTTPException(403,"Zgłoszenie serwisowe wymaga aktywnego Pro.")
        received = db.execute(text("""
            INSERT INTO guard.workshop_support_requests(
                local_request_id,installation_id,subject,description,diagnostics_included)
            VALUES (:local,:iid,:subject,:description,:diag)
            ON CONFLICT (local_request_id) DO NOTHING RETURNING id
        """),{
            "local":request.localRequestId,"iid":request.installationId,
            "subject":request.subject[:240],"description":request.description[:6000],
            "diag":bool(request.diagnosticsIncluded)
        }).scalar_one_or_none()
        # Do not persist diagnostics in this initial transport. The user
        # can submit reports through the dedicated opt-in diagnostics route.
    return {"requestId":request.requestId,"accepted":True,"duplicate":received is None,
            "serverTime":_now().isoformat()}


@router.post("/agent/workshop/remote/poll")
def workshop_remote_poll(request: WorkshopAuth):
    _schema()
    _authenticate(request)
    with engine.begin() as db:
        grant = _grant(db,request.installationId)
        row = _open(db,request.installationId,entitlement_lost=not _eligible(grant))
    return {"requestId":request.requestId,"serverTime":_now().isoformat(),
            "session":_public(row)}


@router.post("/agent/workshop/remote/decision")
def workshop_remote_decision(request: WorkshopDecision):
    _schema()
    _authenticate(request)
    if request.allowFiles and not request.allowDesktop:
        raise HTTPException(400,"Pliki wymagają zgody na pulpit.")
    expired = False
    with engine.begin() as db:
        if not _eligible(_grant(db,request.installationId)) and request.allowDesktop:
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
        row = db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions
            WHERE id=:sid AND installation_id=:iid FOR UPDATE
        """), {"sid":request.sessionId,"iid":request.installationId}).mappings().first()
        if not row:
            raise HTTPException(404,"Nie znaleziono żądania.")
        if row["status"]!="REQUESTED":
            raise HTTPException(409,"Żądanie nie oczekuje na decyzję.")
        if row["expires_at"]<_now():
            expired = True
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='EXPIRED',ended_at=:now WHERE id=:sid
            """),{"sid":row["id"],"now":_now()})
            _event(db,row["id"],"CONSENT_TIMEOUT")
        elif not request.allowDesktop:
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='DENIED',ended_at=:now WHERE id=:sid
            """),{"sid":row["id"],"now":_now()})
            _event(db,row["id"],"CLIENT_DENIED","CLIENT")
        else:
            allowed=["desktop"]+(["files"] if request.allowFiles else [])
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONSENTED',consented_at=:now,granted_capabilities=CAST(:caps AS jsonb)
                WHERE id=:sid
            """),{"sid":row["id"],"now":_now(),"caps":json.dumps(allowed)})
            _event(db,row["id"],"CLIENT_CONSENTED","CLIENT")
        updated = db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid
        """), {"sid":row["id"]}).mappings().one()
    if expired:
        return JSONResponse(status_code=410,content={"detail":"Zgoda na sesję wygasła."})
    return {"requestId":request.requestId,"serverTime":_now().isoformat(),
            "session":_public(updated)}


def _end(db, row, node):
    if row["mesh_public_id"]:
        if not node:
            raise HTTPException(502,"Brak węzła do cofnięcia udostępnienia.")
        try:
            meshcentral.revoke_share(node,row["mesh_public_id"])
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(502,"Nie potwierdzono zakończenia połączenia.") from exc
    db.execute(text("""
        UPDATE guard.workshop_remote_sessions SET status='ENDED',
            ended_at=COALESCE(ended_at,:now),last_activity_at=:now,
            mesh_public_id=NULL,mesh_share_expires_at=NULL WHERE id=:sid
    """),{"sid":row["id"],"now":_now()})


@router.post("/agent/workshop/remote/end")
def workshop_remote_end(request: WorkshopEnd):
    _schema()
    _authenticate(request)
    with engine.begin() as db:
        row=db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions
            WHERE id=:sid AND installation_id=:iid FOR UPDATE
        """),{"sid":request.sessionId,"iid":request.installationId}).mappings().first()
        if not row:
            raise HTTPException(404,"Nie znaleziono sesji.")
        grant=_grant(db,request.installationId)
        _end(db,row,grant["mesh_node_id"] if grant else None)
        _event(db,row["id"],"CLIENT_ENDED","CLIENT")
    return {"requestId":request.requestId,"serverTime":_now().isoformat(),
            "ended":True,"revokeConfirmed":True}


def end_for_owner(sid):
    _schema()
    with engine.begin() as db:
        row=db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid FOR UPDATE
        """),{"sid":sid}).mappings().first()
        if not row:
            raise HTTPException(404,"Nie znaleziono sesji.")
        grant=_grant(db,row["installation_id"])
        _end(db,row,grant["mesh_node_id"] if grant else None)
        _event(db,row["id"],"OWNER_ENDED","TECHNICIAN")
    return row["installation_id"]


def connect_for_owner(sid):
    _schema()
    with engine.begin() as db:
        row=db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid FOR UPDATE
        """),{"sid":sid}).mappings().first()
        if not row:
            raise HTTPException(404,"Nie znaleziono sesji.")
        grant=_grant(db,row["installation_id"])
        if not _eligible(grant):
            raise HTTPException(403,"Tryb serwisowy Pro jest nieaktywny.")
        if row["status"] not in ("CONSENTED","CONNECT_READY","ACTIVE"):
            raise HTTPException(409,"Klient nie wyraził zgody na pulpit.")
        if row["status"]=="CONSENTED" and row["expires_at"]<_now():
            # Leave state unchanged for retryable expiration reconciliation.
            raise HTTPException(410,"Zgoda na sesję wygasła.")
        if not grant["mesh_node_id"]:
            raise HTTPException(409,"Brak powiązania MeshCentral.")
        if "desktop" not in (row["granted_capabilities"] or []):
            raise HTTPException(409,"Nie udzielono zgody na pulpit.")
        node=grant["mesh_node_id"]
        previous=row["mesh_public_id"]
        caps=list(row["granted_capabilities"] or [])
        iid=row["installation_id"]
    if previous:
        try:
            meshcentral.revoke_share(node,previous)
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(502,"Nie potwierdzono cofnięcia poprzedniego linku.") from exc
    try:
        share=meshcentral.create_share(node,f"Multi-Servis {str(sid)[:8]}",caps,60)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(502, f"MeshCentral: {exc}") from exc
    try:
        with engine.begin() as db:
            row=db.execute(text("""
                SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid FOR UPDATE
            """),{"sid":sid}).mappings().first()
            grant=_grant(db,iid)
            if (not row or not _eligible(grant) or grant["mesh_node_id"]!=node
                    or row["status"] not in ("CONSENTED","CONNECT_READY","ACTIVE")):
                raise HTTPException(403,"Uprawnienie, węzeł lub zgoda zmieniły się.")
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONNECT_READY',mesh_public_id=:public,
                    mesh_share_expires_at=:expires,last_error=NULL,
                    last_activity_at=:now WHERE id=:sid
            """),{"sid":sid,"public":share.public_id,
                 "expires":_now()+timedelta(minutes=60),"now":_now()})
            _event(db,sid,"MESH_CREATED","MESH")
    except Exception:
        try:
            meshcentral.revoke_share(node,share.public_id)
        except meshcentral.MeshCentralError:
            pass
        raise
    return {"sessionId":str(sid),"url":share.url,
            "expiresAt":(_now()+timedelta(minutes=60)).isoformat(),
            "capabilities":caps}


def bind_for_owner(iid, node_id):
    _schema()
    node_id=node_id.strip()
    if not node_id.startswith("node/") or len(node_id)>300:
        raise HTTPException(400,"MeshCentral wymaga identyfikatora node/…")
    with engine.begin() as db:
        grant=_grant(db,iid)
        if not _eligible(grant):
            raise HTTPException(403,"Wymagany serwisowy Pro.")
        collision=db.execute(text("""
            SELECT 1 FROM guard.installations
            WHERE mesh_node_id=:node AND is_current=TRUE LIMIT 1
        """),{"node":node_id}).first()
        if collision:
            raise HTTPException(409, "Węzeł MeshCentral przypisany jest do innej licencji.")
        lock=db.execute(text("""
            SELECT id FROM guard.workshop_remote_sessions
            WHERE installation_id=:iid AND mesh_public_id IS NOT NULL FOR UPDATE
        """),{"iid":iid}).first()
        previous=grant["mesh_node_id"]
        if lock and previous!=node_id:
            raise HTTPException(409,"Najpierw zakończ udostępnioną sesję.")
        db.execute(text("""
            INSERT INTO guard.workshop_mesh_nodes(installation_id,mesh_node_id)
            VALUES (:iid,:node)
            ON CONFLICT (installation_id) DO UPDATE SET
               mesh_node_id=EXCLUDED.mesh_node_id,updated_at=now()
        """),{"iid":iid,"node":node_id})
    return {"meshNodeId":node_id}
