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
from typing import Any, Literal

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


class WorkshopStandingAttestation(WorkshopAuth):
    # Only an explicit, interactive GUI action may submit this command.
    # Discovery auth alone can never stand in for OWNER's separate approval.
    explicitConsent: Literal[True]
    acknowledgedConsentSha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkshopMeshEnrollment(WorkshopAuth):
    # Local MeshAgent registry NodeId, without domain or node/ prefix.
    meshNodeId: str = Field(min_length=64, max_length=64)


class WorkshopDecision(WorkshopAuth):
    sessionId: uuid.UUID
    allowDesktop: bool
    allowFiles: bool = False


class WorkshopSessionMeshEnrollment(WorkshopMeshEnrollment):
    sessionId: uuid.UUID


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
                """ALTER TABLE guard.workshop_mesh_nodes
                   ADD COLUMN IF NOT EXISTS session_id UUID""",
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
                # Existing sessions remain bound to interactive consent.
                # A standing session MUST carry its own explicit mode marker.
                """ALTER TABLE guard.workshop_remote_sessions
                   ADD COLUMN IF NOT EXISTS authorization_kind TEXT NOT NULL
                   DEFAULT 'SESSION_CONSENT'""",
                """CREATE UNIQUE INDEX IF NOT EXISTS uq_workshop_remote_open
                   ON guard.workshop_remote_sessions(installation_id)
                   WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_remote_events (
                   id BIGSERIAL PRIMARY KEY,
                   session_id UUID NOT NULL REFERENCES guard.workshop_remote_sessions(id)
                     ON DELETE CASCADE,
                   event_type TEXT NOT NULL,actor_type TEXT NOT NULL,
                   occurred_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
                # SERVICE PRO assignment alone never activates remote sharing.
                # Separate recorded approval and opt-in must bind the same node.
                """CREATE TABLE IF NOT EXISTS guard.workshop_standing_remote_authorizations (
                   installation_id UUID PRIMARY KEY
                     REFERENCES guard.workshop_grants(installation_id) ON DELETE CASCADE,
                   approved_mesh_node_id TEXT NOT NULL,
                   device_scope TEXT NOT NULL
                     CHECK (device_scope IN ('OWNED_WORKSHOP','CLIENT_DIAGNOSTIC')),
                   owner_approved_at TIMESTAMPTZ,
                   local_opt_in_attested_at TIMESTAMPTZ,
                   prior_consent_sha256 TEXT NOT NULL
                     CHECK (char_length(prior_consent_sha256) = 64),
                   revoked_at TIMESTAMPTZ,
                   created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                   updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
                """CREATE TABLE IF NOT EXISTS guard.workshop_standing_remote_audit (
                   id BIGSERIAL PRIMARY KEY,
                   installation_id UUID NOT NULL
                     REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                   action TEXT NOT NULL
                     CHECK (action IN ('OWNER_APPROVED','LOCAL_OPT_IN_ATTESTED','OWNER_REVOKED','SERVICE_RIGHTS_CHANGED')),
                   actor_type TEXT NOT NULL DEFAULT 'OWNER',
                   occurred_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
            ):
                db.execute(text(query))
        _ready = True


def _grant(db, iid):
    return db.execute(text("""
        SELECT g.edition,g.enabled,p.status,p.installation_id,m.mesh_node_id,m.session_id AS mesh_session_id
        FROM guard.pending_installations p
        LEFT JOIN guard.workshop_grants g ON g.installation_id=p.installation_id
        LEFT JOIN guard.workshop_mesh_nodes m ON m.installation_id=p.installation_id
        WHERE p.installation_id=:id
    """), {"id": iid}).mappings().first()


def remote_entitlement_mode(grant):
    """Read-only server truth, separate from Windows' possibly stale licence."""
    if not grant:
        return "UNREGISTERED"
    status = grant["status"]
    if status in ("ASSIGNED", "PROVISIONED"):
        return "CUSTOMER_LICENSE"
    if status in ("ARCHIVED", "UNINSTALLED", "IGNORED"):
        return "INACTIVE_INSTALLATION"
    if not grant["enabled"]:
        return "SERVICE_DISABLED"
    if grant["edition"] == "STANDARD":
        return "SERVICE_STANDARD"
    if grant["edition"] == "PRO":
        return "SERVICE_PRO"
    return "UNKNOWN_DENIED"


def _eligible(grant):
    return remote_entitlement_mode(grant) == "SERVICE_PRO"


def standing_authorization_record(db, installation_id):
    """Read-only: a SERVICE PRO grant alone never authorizes unattended access.

    Any later share must ALSO verify exact live node and pinned mesh group.
    """
    return db.execute(text("""
        SELECT approved_mesh_node_id, device_scope, owner_approved_at,
               local_opt_in_attested_at, prior_consent_sha256, revoked_at
        FROM guard.workshop_standing_remote_authorizations
        WHERE installation_id=:iid
    """), {"iid": installation_id}).mappings().first()


def standing_authorization_record_valid(grant, record):
    """Both separately recorded confirmations and exact node binding required."""
    if not _eligible(grant) or not grant.get("mesh_node_id") or not record:
        return False
    return bool(
        record["approved_mesh_node_id"] == grant["mesh_node_id"]
        and record["device_scope"] in ("OWNED_WORKSHOP", "CLIENT_DIAGNOSTIC")
        and record["owner_approved_at"] is not None
        and record["local_opt_in_attested_at"] is not None
        and record["revoked_at"] is None
        and isinstance(record["prior_consent_sha256"], str)
        and bool(re.fullmatch(r"[0-9a-f]{64}", record["prior_consent_sha256"]))
    )


def session_node_ready(grant, row):
    return bool(grant and row and grant.get("mesh_node_id")
                and grant.get("mesh_session_id") == row["id"])


def _can_replace_session_node(previous, installation_id):
    # Only retire a binding whose verified session has actually ended and
    # whose share was revoked. Legacy/manual/foreign bindings fail closed.
    return bool(previous and previous["installation_id"] == installation_id
                and previous["status"] in ("ENDED", "EXPIRED", "DENIED")
                and previous.get("ended_at") is not None
                and not previous.get("mesh_public_id"))


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
    # The identity token does not authorize the service-license API. Paid
    # customer PRO uses a separate KeyGate path with fresh local consent.
    if pending["status"] in ("ASSIGNED", "PROVISIONED"):
        raise HTTPException(
            409,
            "REMOTE_MODE_CUSTOMER_LICENSE: Ta instalacja ma licencję klienta. Zdalna pomoc wymaga ścieżki "
            "klienta Pro i każdorazowej zgody; sprawdź tryb licencji w MultiGuard.",
        )
    if pending["status"] in ("ARCHIVED", "UNINSTALLED", "IGNORED"):
        raise HTTPException(403, "Instalacja nieaktywna lub wycofana; zdalny dostęp zablokowany.")
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
        "expiresAt": paid_remote._iso(row.get("mesh_share_expires_at")
                                      if row["status"] in {"CONNECT_READY", "ACTIVE"}
                                      else row["expires_at"]),
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
        active["status"] in ("REQUESTED", "CONSENTED") and active["expires_at"] <= now
    ) or (
        active["status"] in ("CONNECT_READY", "ACTIVE")
        and (active["mesh_share_expires_at"] is None
             or active["mesh_share_expires_at"] <= now)
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


def prepare_standing_authorization_for_owner(iid,device_scope,receipt_sha256):
    """OWNER records prior written consent; cannot activate remote access.

    Requires separate on-device confirmation and the correct live MeshCentral
    group before unattended access can ever be enabled. Never accept a node
    identifier from this request: bind exclusively to the saved installation.
    """
    if device_scope not in ("OWNED_WORKSHOP","CLIENT_DIAGNOSTIC"):
        raise HTTPException(400,"Nieprawidłowy zakres zgody serwisowej.")
    if not isinstance(receipt_sha256,str) or not re.fullmatch(r"[0-9a-f]{64}",receipt_sha256):
        raise HTTPException(400,"Wymagany SHA-256 dokumentu zgody.")
    _schema()
    with engine.connect() as db:
        grant=_grant(db,iid)
    if not _eligible(grant) or not grant.get("mesh_node_id"):
        raise HTTPException(403,"Wymagana aktywna instalacja serwisowa Pro powiązana z MeshAgent.")
    pinned_node=grant["mesh_node_id"]
    try:
        if not meshcentral.verify_registered_node(pinned_node):
            raise HTTPException(409,"Nie potwierdzono węzła urządzenia w MeshCentral.")
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(502,"Nie można potwierdzić urządzenia w MeshCentral.") from exc
    with engine.begin() as db:
        # Lock before writing and revalidate against a concurrent licence
        # conversion or MeshAgent node change.
        db.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).first()
        db.execute(text("""
            SELECT installation_id FROM guard.workshop_grants
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).first()
        grant=_grant(db,iid)
        if not _eligible(grant) or grant.get("mesh_node_id")!=pinned_node:
            raise HTTPException(409,"Uprawnienia lub węzeł zmieniły się podczas potwierdzania.")
        previous=db.execute(text("""
            SELECT revoked_at FROM guard.workshop_standing_remote_authorizations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).mappings().first()
        if previous and previous["revoked_at"] is None:
            raise HTTPException(409,"Upoważnienie jest już zapisane; najpierw je cofnij.")
        db.execute(text("""
            INSERT INTO guard.workshop_standing_remote_authorizations
              (installation_id,approved_mesh_node_id,device_scope,
               owner_approved_at,local_opt_in_attested_at,
               prior_consent_sha256,revoked_at)
            VALUES (:iid,:node,:scope,:now,NULL,:receipt,NULL)
            ON CONFLICT (installation_id) DO UPDATE SET
              approved_mesh_node_id=EXCLUDED.approved_mesh_node_id,
              device_scope=EXCLUDED.device_scope,
              owner_approved_at=EXCLUDED.owner_approved_at,
              local_opt_in_attested_at=NULL,
              prior_consent_sha256=EXCLUDED.prior_consent_sha256,
              revoked_at=NULL,updated_at=now()
        """),{"iid":iid,"node":pinned_node,"scope":device_scope,
               "receipt":receipt_sha256,"now":_now()})
        db.execute(text("""
            INSERT INTO guard.workshop_standing_remote_audit
              (installation_id,action,actor_type)
            VALUES (:iid,'OWNER_APPROVED','OWNER')
        """),{"iid":iid})
    return {"recorded":True,"localDeviceConsentPending":True,
            "meshGroupVerificationPending":True,"unattendedReady":False}


def invalidate_standing_authorization(db, iid, reason):
    """Durably invalidate any prior authorization, never erase the audit trail.

    Called by OWNER explicit revocation or as part of the SAME transaction
    that removes service PRO rights. A future re-enablement requires entirely
    new independent approvals and an up-to-date local attestation.
    """
    if reason not in ("OWNER_REVOKED", "SERVICE_RIGHTS_CHANGED"):
        raise ValueError("Unrecognized standing authorization invalidation.")
    record = db.execute(text("""
        SELECT revoked_at
        FROM guard.workshop_standing_remote_authorizations
        WHERE installation_id=:iid FOR UPDATE
    """), {"iid": iid}).mappings().first()
    if not record or record["revoked_at"] is not None:
        return False
    db.execute(text("""
        UPDATE guard.workshop_standing_remote_authorizations
        SET revoked_at=:now,updated_at=:now
        WHERE installation_id=:iid AND revoked_at IS NULL
    """), {"iid":iid,"now":_now()})
    db.execute(text("""
        INSERT INTO guard.workshop_standing_remote_audit
          (installation_id,action,actor_type)
        VALUES (:iid,:action,'OWNER')
    """), {"iid":iid,"action":reason})
    return True


def revoke_standing_authorization_for_owner(iid):
    """OWNER may always revoke; MeshCentral failure is reported, never hidden.

    The database revocation COMMMITS even when an external share fails to
    revoke, so no later request can rely on this standing authorization.
    """
    _schema()
    share_failure = False
    with engine.begin() as db:
        # This locks the specific authorization before inspecting sessions.
        prior = db.execute(text("""
            SELECT revoked_at
            FROM guard.workshop_standing_remote_authorizations
            WHERE installation_id=:iid FOR UPDATE
        """), {"iid":iid}).mappings().first()
        if prior is None or prior["revoked_at"] is not None:
            return {"revoked":True,"previouslyActive":False,"shareRevokeConfirmed":True}
        try:
            _open(db,iid,entitlement_lost=True)
        except HTTPException as exc:
            # Do not rollback revocation just because MeshCentral is offline.
            # Clearly disclose to OWNER that old links may remain alive.
            if exc.status_code not in (502, 503):
                raise
            share_failure = True
        invalidate_standing_authorization(db,iid,"OWNER_REVOKED")
    if share_failure:
        raise HTTPException(
            502,
            "Stałe upoważnienie zapisano jako cofnięte, ale MeshCentral nie "
            "potwierdził zamknięcia poprzedniego linku. Wymagana kontrola sesji.",
        )
    return {"revoked":True,"previouslyActive":True,"shareRevokeConfirmed":True}


def close_before_rights_change(db, iid: uuid.UUID):
    """Called with guard.workshop_grants row locked in one DB transaction.

    If Mesh revoke fails, the surrounding SQL transaction rolls back and
    leaves the PRO entitlement in place for a retry instead of falsely
    claiming remote access was disabled.
    """
    _open(db, iid, entitlement_lost=True)
    invalidate_standing_authorization(db,iid,"SERVICE_RIGHTS_CHANGED")


def request_consent_for_owner(iid: uuid.UUID):
    """OWNER's explicit one-click request; NEVER unattended and no preexisting node.

    The dormant MeshAgent is enrolled only after the client independently
    accepts this specific server-created session. OWNER cannot set CONSENTED.
    """
    _schema()
    with engine.begin() as db:
        grant = _grant(db, iid)
        if not _eligible(grant):
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
        # Expire/revoke a stale session and forbid a second concurrent request.
        # A pre-consent MeshCentral node is deliberately NOT required.
        if _open(db, iid):
            raise HTTPException(409, "Dla komputera istnieje już otwarta sesja.")
        now = _now()
        sid = uuid.uuid4()
        db.execute(text("""
            INSERT INTO guard.workshop_remote_sessions(
                id,installation_id,status,expires_at,last_activity_at)
            VALUES (:sid,:iid,'REQUESTED',:expires,:now)
        """), {
            "sid": sid, "iid": iid,
            "expires": now + timedelta(minutes=5), "now": now,
        })
        _event(db, sid, "OWNER_REQUESTED", "TECHNICIAN")
        return sid


def request_for_owner(iid: uuid.UUID):
    """Create ONE short-lived desktop-only session from prior recorded consent.

    No standing grant, no separate local opt-in or no exact ONLINE node in
    its dedicated trusted MeshCentral group => deny before touching sessions.
    This never accepts a node or permission assertion supplied by a browser.
    """
    _schema()
    with engine.connect() as db:
        grant = _grant(db, iid)
        standing = (standing_authorization_record(db, iid)
                    if _eligible(grant) else None)
    if not standing_authorization_record_valid(grant, standing):
        raise HTTPException(
            403, "Brak ważnego, lokalnie potwierdzonego upoważnienia serwisowego Pro."
        )
    node = grant["mesh_node_id"]
    scope = standing["device_scope"]
    try:
        meshcentral.verify_standing_service_node(node, scope)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(
            409, "Wymagana potwierdzona usługa online w dedykowanej grupie MeshCentral."
        ) from exc
    with engine.begin() as db:
        # Follow the same grant -> standing -> session lock order as OWNER
        # rights revocation to prevent authorizing against stale grants.
        db.execute(text("""
            SELECT installation_id FROM guard.workshop_grants
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).first()
        db.execute(text("""
            SELECT installation_id FROM guard.workshop_standing_remote_authorizations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).first()
        grant = _grant(db, iid)
        standing = standing_authorization_record(db, iid)
        if (not standing_authorization_record_valid(grant, standing)
                or grant["mesh_node_id"] != node
                or standing["device_scope"] != scope):
            raise HTTPException(403,"Upoważnienie lub węzeł uległy zmianie.")
        if _open(db, iid):
            raise HTTPException(409,"Ten komputer ma już otwartą sesję.")
        if db.execute(text("""
            SELECT 1 FROM guard.remote_sessions
            WHERE installation_id=:iid AND mesh_public_id IS NOT NULL
              AND status IN ('CONNECT_READY','ACTIVE') LIMIT 1
        """),{"iid":iid}).first():
            raise HTTPException(409,"Trwa połączenie klienta Pro; zakończ je najpierw.")
        sid = uuid.uuid4()
        now = _now()
        # A prior local authorization (not a fake interactive decision) is
        # recorded in a separate column for every subsequent check/revoke.
        db.execute(text("""
            INSERT INTO guard.workshop_remote_sessions(
                id,installation_id,status,authorization_kind,
                requested_capabilities,granted_capabilities,
                requested_at,expires_at,consented_at,last_activity_at
            ) VALUES (
                :sid,:iid,'CONSENTED','STANDING_SERVICE',
                '["desktop"]'::jsonb,'["desktop"]'::jsonb,
                :now,:expires,:consent,:now
            )
        """),{"sid":sid,"iid":iid,"now":now,
               "expires":now+timedelta(minutes=5),
               "consent":standing["local_opt_in_attested_at"]})
        updated = db.execute(text("""
            UPDATE guard.workshop_mesh_nodes SET session_id=:sid,updated_at=:now
            WHERE installation_id=:iid AND mesh_node_id=:node
            RETURNING installation_id
        """),{"sid":sid,"now":now,"iid":iid,"node":node}).first()
        if not updated:
            raise HTTPException(409,"Nie potwierdzono stałego powiązania węzła serwisowego.")
        _event(db,sid,"STANDING_OWNER_REQUESTED","TECHNICIAN")
    return sid


@router.post("/agent/workshop/remote/mesh-enroll")
def workshop_session_mesh_enroll(request: WorkshopSessionMeshEnrollment):
    _schema()
    _authenticate(request)
    def validate(db, lock=False):
        grant = _grant(db, request.installationId)
        if not _eligible(grant):
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
        row = db.execute(text("SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid"
                              + (" FOR UPDATE" if lock else "")),
                         {"sid":request.sessionId}).mappings().first()
        paid_remote._require_transport_consent(row, request.installationId, _now())
        return grant
    with engine.connect() as db:
        validate(db)
    try:
        node = meshcentral.verify_session_node(request.meshNodeId, str(request.sessionId), persistent_service=True)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(409, "Serwer nie potwierdził jeszcze agenta tej sesji.") from exc
    with engine.begin() as db:
        db.execute(text("SELECT installation_id FROM guard.workshop_grants WHERE installation_id=:iid FOR UPDATE"),
                   {"iid":request.installationId})
        grant = validate(db, True)
        if grant.get("mesh_node_id") and grant.get("mesh_session_id") != request.sessionId:
            previous = db.execute(text("""SELECT * FROM guard.workshop_remote_sessions
                WHERE id=:sid FOR UPDATE"""),
                {"sid": grant.get("mesh_session_id")}).mappings().first()
            if not _can_replace_session_node(previous, request.installationId):
                raise HTTPException(409, "Poprzednie powiązanie agenta nie zostało bezpiecznie zakończone.")
        elif grant.get("mesh_node_id") not in (None, "", node):
            raise HTTPException(409, "Bieżąca sesja ma już innego agenta.")
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:node))"), {"node":node})
        # Same physical installation uses ONE long-lived MeshAgent SCM node
        # across both licence modes. Do not accept a different installation.
        if db.execute(text("""
            SELECT 1 FROM guard.installations
            WHERE mesh_node_id=:node AND id<>:iid LIMIT 1
        """), {"node":node, "iid":request.installationId}).first():
            raise HTTPException(409, "Agent jest przypisany do innej instalacji.")
        if db.execute(text("""SELECT 1 FROM guard.workshop_mesh_nodes
                WHERE mesh_node_id=:node AND installation_id<>:iid"""),
                {"node":node,"iid":request.installationId}).first():
            raise HTTPException(409, "Agent jest przypisany do innej instalacji serwisowej.")
        # A commercial session belonging to this same installation may
        # have an active public share: do not silently reuse the transport
        # while that viewer is still connected/authorized.
        if db.execute(text("""
            SELECT 1 FROM guard.remote_sessions
            WHERE installation_id=:iid AND mesh_public_id IS NOT NULL
              AND status IN ('CONNECT_READY','ACTIVE') LIMIT 1
        """), {"iid":request.installationId}).first():
            raise HTTPException(409, "Najpierw zakończ aktywne udostępnienie komercyjne.")
        db.execute(text("""INSERT INTO guard.workshop_mesh_nodes(installation_id,mesh_node_id,session_id)
            VALUES (:iid,:node,:sid) ON CONFLICT(installation_id) DO UPDATE
            SET mesh_node_id=EXCLUDED.mesh_node_id,session_id=EXCLUDED.session_id,updated_at=now()"""),
            {"iid":request.installationId,"node":node,"sid":request.sessionId})
        _event(db, request.sessionId, "SESSION_AGENT_VERIFIED", "CLIENT")
    return {"requestId":request.requestId,"sessionId":str(request.sessionId),"accepted":True}


@router.post("/agent/workshop/mesh-enroll")
def workshop_mesh_enroll(request: WorkshopMeshEnrollment):
    """Identity-bound registration; OWNER never has to type MeshCentral node IDs."""
    _schema()
    _authenticate(request)
    # Fail early for STANDARD/disabled installations; do not permit them to
    # flood the MeshCentral management CLI with arbitrary lookup requests.
    with engine.connect() as db:
        if not _eligible(_grant(db, request.installationId)):
            raise HTTPException(403, "Zdalna pomoc wymaga serwisowego Pro.")
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
        # Serialize the cross-mode association with commercial enrollment
        # using exactly the same advisory lock on the full MeshCentral node.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:node))"), {"node":node})
        commercial = db.execute(text("""
            SELECT 1 FROM guard.installations
            WHERE mesh_node_id=:node AND id<>:iid LIMIT 1
        """), {"node":node, "iid":request.installationId}).first()
        if commercial:
            raise HTTPException(409, "Węzeł należy do innego typu instalacji.")
        # Avoid destroying an already active commercial viewer when an
        # installation switches to workshop mode with the same service.
        if db.execute(text("""
            SELECT 1 FROM guard.remote_sessions
            WHERE installation_id=:iid AND mesh_public_id IS NOT NULL
              AND status IN ('CONNECT_READY','ACTIVE') LIMIT 1
        """), {"iid":request.installationId}).first():
            raise HTTPException(409, "Najpierw zakończ aktywne udostępnienie komercyjne.")
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
            INSERT INTO guard.workshop_mesh_nodes AS owned (installation_id,mesh_node_id)
            VALUES (:iid,:node)
            ON CONFLICT (installation_id) DO UPDATE
            SET mesh_node_id=EXCLUDED.mesh_node_id,
                session_id=CASE WHEN owned.mesh_node_id=EXCLUDED.mesh_node_id
                    THEN owned.session_id ELSE NULL END,
                updated_at=now()
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
            consented_at = _now()
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONSENTED',consented_at=:now,
                    expires_at=:consent_expires,
                    granted_capabilities=CAST(:caps AS jsonb)
                WHERE id=:sid
            """),{"sid":row["id"],"now":consented_at,
                  "consent_expires":consented_at+timedelta(minutes=5),
                  "caps":json.dumps(allowed)})
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
        if (row["status"] in ("CONNECT_READY", "ACTIVE")
                and (row["mesh_share_expires_at"] is None
                     or row["mesh_share_expires_at"] <= _now())):
            raise HTTPException(410, "Udostępnienie wygasło; rozpocznij nową sesję.")
        if row["status"]=="CONSENTED" and row["expires_at"]<_now():
            # Leave state unchanged for retryable expiration reconciliation.
            raise HTTPException(410,"Zgoda na sesję wygasła.")
        if not session_node_ready(grant, row):
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
    # MeshCentral starts the share lease during the external call, not when
    # the database transaction eventually commits. Never advertise a later
    # expiry than the remote service can guarantee.
    share_expires = _now() + timedelta(minutes=60)
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
            if share_expires <= _now():
                raise HTTPException(410, "Nowy link MeshCentral wygasł przed zapisem.")
            if (not row or not _eligible(grant) or not session_node_ready(grant, row)
                    or grant["mesh_node_id"]!=node or row.get("ended_at") is not None
                    or row["mesh_public_id"] != previous
                    or (row["status"] in ("CONNECT_READY", "ACTIVE")
                        and (row["mesh_share_expires_at"] is None
                             or row["mesh_share_expires_at"] <= _now()))
                    or row["status"] not in ("CONSENTED","CONNECT_READY","ACTIVE")
                    or "desktop" not in (row["granted_capabilities"] or [])
                    or list(row["granted_capabilities"] or []) != caps
                    or (row["status"] == "CONSENTED" and row["expires_at"] <= _now())):
                raise HTTPException(403,"Uprawnienie, węzeł lub zgoda zmieniły się.")
            db.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONNECT_READY',mesh_public_id=:public,
                    mesh_share_expires_at=:expires,last_error=NULL,
                    last_activity_at=:now WHERE id=:sid
            """),{"sid":sid,"public":share.public_id,
                 "expires":share_expires,"now":_now()})
            _event(db,sid,"MESH_CREATED","MESH")
    except Exception:
        try:
            meshcentral.revoke_share(node,share.public_id)
        except meshcentral.MeshCentralError:
            pass
        raise
    return {"sessionId":str(sid),"url":share.url,
            "expiresAt":share_expires.isoformat(),
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
               mesh_node_id=EXCLUDED.mesh_node_id,session_id=NULL,updated_at=now()
        """),{"iid":iid,"node":node_id})
    return {"meshNodeId":node_id}
