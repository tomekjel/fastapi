"""OWNER-managed, explicit-consent remote help for WORKSHOP/PRO.

Workshop discovery credentials are NEVER commercial installation credentials.
This module intentionally stores workshop sessions separately from paid-session
tables to preserve KeyGate and runtime-agent security boundaries.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner
from app.routers import multiguard_meshcentral as meshcentral
from app.routers.multiguard_license import _ensure_schema as _ensure_license_schema

router = APIRouter(prefix="/multiguard", tags=["multi-guard-workshop-remote"])
_LOCK = threading.Lock()
_READY = False


class WorkshopAgentAuth(BaseModel):
    requestId: str = Field(min_length=1, max_length=100)
    nonce: str = Field(min_length=1, max_length=100)
    sentAt: datetime
    installationId: uuid.UUID
    deviceId: str = Field(min_length=16, max_length=128)
    discoveryCredential: str = Field(min_length=32, max_length=512)


class WorkshopDecision(WorkshopAgentAuth):
    sessionId: uuid.UUID
    allowDesktop: bool
    allowFiles: bool = False


class WorkshopEnd(WorkshopAgentAuth):
    sessionId: uuid.UUID
    reason: str = Field(default="CLIENT_ENDED", max_length=80)


class OwnerWorkshopRequest(BaseModel):
    installationId: uuid.UUID
    requestFiles: bool = False
    subject: str = Field(default="Zdalna pomoc Multi-Servis", min_length=3, max_length=160)


class OwnerWorkshopMeshBind(BaseModel):
    installationId: uuid.UUID
    meshNodeId: str = Field(min_length=8, max_length=300)


def _ensure_schema():
    global _READY
    if _READY:
        return
    _ensure_license_schema()
    with _LOCK:
        if _READY:
            return
        with engine.begin() as con:
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.workshop_remote_nodes (
                    installation_id UUID PRIMARY KEY REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                    mesh_node_id TEXT NOT NULL UNIQUE,
                    bound_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.workshop_remote_sessions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    installation_id UUID NOT NULL REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
                    requested_by TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'REQUESTED'
                        CHECK (status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE','DENIED','ENDED','EXPIRED','ERROR')),
                    requested_capabilities JSONB NOT NULL DEFAULT '["desktop"]'::jsonb,
                    granted_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
                    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    consented_at TIMESTAMPTZ,
                    ended_at TIMESTAMPTZ,
                    last_activity_at TIMESTAMPTZ,
                    mesh_public_id TEXT,
                    mesh_share_expires_at TIMESTAMPTZ,
                    last_error TEXT
                )
            """))
            con.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_workshop_remote_one_open
                ON guard.workshop_remote_sessions(installation_id)
                WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
            """))
            con.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.workshop_remote_events (
                    id BIGSERIAL PRIMARY KEY,
                    session_id UUID NOT NULL REFERENCES guard.workshop_remote_sessions(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    data JSONB NOT NULL DEFAULT '{}'::jsonb
                )
            """))
        _READY = True


def _now():
    return datetime.now(timezone.utc)


def _iso(v):
    return v.isoformat() if v else None


def _audit(con, sid, name, actor, payload=None):
    con.execute(text("""
        INSERT INTO guard.workshop_remote_events(session_id,event_type,actor,data)
        VALUES(:sid,:name,:actor,CAST(:payload AS jsonb))
    """), {"sid": sid, "name": name, "actor": actor,
           "payload": json.dumps(payload or {}, ensure_ascii=False)})


def _authorized_pending(con, installation_id, device_id, secret, *, require_pro=True):
    """Authenticate discovery only against the exact pending installation.

    No commercial credential, paid runtime installation or KeyGate is touched.
    Recheck grant on *every* poll, consent, start and connect.
    """
    row = con.execute(text("""
        SELECT pi.installation_id,pi.device_id,pi.discovery_credential_sha256,
               pi.status, wg.enabled,wg.edition
        FROM guard.pending_installations pi
        LEFT JOIN guard.workshop_grants wg ON wg.installation_id=pi.installation_id
        WHERE pi.installation_id=:iid
    """), {"iid": installation_id}).mappings().first()
    if (not row or not hmac.compare_digest(str(row["device_id"]), str(device_id))
            or not hmac.compare_digest(str(row["discovery_credential_sha256"]),
                                       hashlib.sha256(secret.encode()).hexdigest())):
        raise HTTPException(401, "Nieprawidłowe poświadczenie instalacji serwisowej.")
    if require_pro and (not row["enabled"] or row["edition"] != "PRO"
                        or row["status"] in {"ARCHIVED", "UNINSTALLED", "ASSIGNED", "PROVISIONED"}):
        raise HTTPException(403, "Tryb serwisowy PRO nie jest aktywny.")
    return row


def _active_pro(con, iid):
    row = con.execute(text("""
        SELECT pi.installation_id,pi.status,wg.enabled,wg.edition,n.mesh_node_id
        FROM guard.pending_installations pi
        LEFT JOIN guard.workshop_grants wg ON wg.installation_id=pi.installation_id
        LEFT JOIN guard.workshop_remote_nodes n ON n.installation_id=pi.installation_id
        WHERE pi.installation_id=:iid
    """), {"iid": iid}).mappings().first()
    if not row:
        raise HTTPException(404, "Nie znaleziono instalacji.")
    if (not row["enabled"] or row["edition"] != "PRO"
            or row["status"] in {"ARCHIVED", "UNINSTALLED", "ASSIGNED", "PROVISIONED"}):
        raise HTTPException(403, "Instalacja nie ma aktywnego trybu serwisowego PRO.")
    return row


def _session(row):
    if not row:
        return None
    return {
        "sessionId": str(row["id"]),
        "supportRequestId": "",
        "status": row["status"],
        "technicianDisplayName": row["requested_by"],
        "subject": row["subject"],
        "requestedCapabilities": list(row["requested_capabilities"] or []),
        "grantedCapabilities": list(row["granted_capabilities"] or []),
        "requestedAt": _iso(row["requested_at"]),
        "expiresAt": _iso(row["expires_at"]),
        "consentedAt": _iso(row["consented_at"]),
        "connectedAt": None,
        "endedAt": _iso(row["ended_at"]),
        "reconnectUntil": None,
        "meshReady": bool(row["mesh_public_id"]),
        "lastError": row["last_error"],
    }


def _expire(con, iid):
    now = _now()
    con.execute(text("""
        UPDATE guard.workshop_remote_sessions
        SET status='EXPIRED',ended_at=COALESCE(ended_at,:now)
        WHERE installation_id=:iid
          AND ((status IN ('REQUESTED','CONSENTED') AND expires_at<:now)
               OR (status IN ('CONNECT_READY','ACTIVE') AND mesh_share_expires_at<:now))
    """), {"iid": iid, "now": now})


def _open(con, iid):
    _expire(con, iid)
    return con.execute(text("""
        SELECT * FROM guard.workshop_remote_sessions
        WHERE installation_id=:iid
          AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        ORDER BY requested_at DESC LIMIT 1
    """), {"iid": iid}).mappings().first()


@router.post("/agent/workshop/remote/poll")
def agent_workshop_poll(body: WorkshopAgentAuth):
    _ensure_schema()
    with engine.begin() as con:
        _authorized_pending(con, body.installationId, body.deviceId, body.discoveryCredential)
        row = _open(con, body.installationId)
        result = _session(row)
    return {"requestId": body.requestId, "serverTime": _iso(_now()), "session": result}


@router.post("/agent/workshop/remote/decision")
def agent_workshop_decision(body: WorkshopDecision):
    _ensure_schema()
    now = _now()
    with engine.begin() as con:
        _authorized_pending(con, body.installationId, body.deviceId, body.discoveryCredential)
        row = con.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions
            WHERE id=:sid AND installation_id=:iid FOR UPDATE
        """), {"sid": body.sessionId, "iid": body.installationId}).mappings().first()
        if not row:
            raise HTTPException(404, "Sesja nie istnieje.")
        if row["status"] != "REQUESTED" or row["expires_at"] < now:
            raise HTTPException(409, "Żądanie pomocy wygasło lub zostało już rozpatrzone.")
        if body.allowDesktop:
            requested = list(row["requested_capabilities"] or [])
            granted = ["desktop"] + (["files"] if body.allowFiles and "files" in requested else [])
            con.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONSENTED',consented_at=:now,
                    granted_capabilities=CAST(:granted AS jsonb),
                    expires_at=:expires
                WHERE id=:sid
            """), {"sid": body.sessionId, "now": now,
                   "granted": json.dumps(granted), "expires": now + timedelta(minutes=5)})
            _audit(con, body.sessionId, "CLIENT_CONSENTED", "CLIENT", {"granted": granted})
        else:
            con.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='DENIED',ended_at=:now WHERE id=:sid
            """), {"sid": body.sessionId, "now": now})
            _audit(con, body.sessionId, "CLIENT_DENIED", "CLIENT")
        updated = con.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid
        """), {"sid": body.sessionId}).mappings().one()
    return {"requestId": body.requestId, "serverTime": _iso(now), "session": _session(updated)}


def _end_session(sid, actor, reason):
    """Set END first, then revoke live Mesh link. Never report revoke success on failure."""
    with engine.begin() as con:
        row = con.execute(text("""
            SELECT s.*,n.mesh_node_id FROM guard.workshop_remote_sessions s
            LEFT JOIN guard.workshop_remote_nodes n ON n.installation_id=s.installation_id
            WHERE s.id=:sid FOR UPDATE OF s
        """), {"sid": sid}).mappings().first()
        if not row:
            raise HTTPException(404, "Sesja nie istnieje.")
        if row["status"] not in {"ENDED", "EXPIRED", "DENIED"}:
            con.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='ENDED',ended_at=now() WHERE id=:sid
            """), {"sid": sid})
            _audit(con, sid, "SESSION_ENDED", actor, {"reason": reason[:80]})
    if row["mesh_public_id"]:
        if not row["mesh_node_id"]:
            raise HTTPException(502, "Brak powiązania węzła do unieważnienia linku.")
        try:
            meshcentral.revoke_share(row["mesh_node_id"], row["mesh_public_id"])
        except meshcentral.MeshCentralError as exc:
            with engine.begin() as con:
                con.execute(text("""
                    UPDATE guard.workshop_remote_sessions
                    SET last_error=:error WHERE id=:sid
                """), {"sid": sid, "error": str(exc)[:500]})
                _audit(con, sid, "MESH_REVOKE_FAILED", "MESH")
            raise HTTPException(502, "Nie potwierdzono unieważnienia połączenia MeshCentral.") from exc
    return True


@router.post("/agent/workshop/remote/end")
def agent_workshop_end(body: WorkshopEnd):
    _ensure_schema()
    with engine.connect() as con:
        # Even a revoked grant may terminate a prior session.
        _authorized_pending(con, body.installationId, body.deviceId,
                            body.discoveryCredential, require_pro=False)
        found = con.execute(text("""
            SELECT id FROM guard.workshop_remote_sessions
            WHERE id=:sid AND installation_id=:iid
        """), {"sid": body.sessionId, "iid": body.installationId}).scalar_one_or_none()
    if not found:
        raise HTTPException(404, "Sesja nie istnieje.")
    _end_session(body.sessionId, "CLIENT", body.reason)
    return {"requestId": body.requestId, "serverTime": _iso(_now()), "ended": True}


@router.post("/workshop/remote-sessions")
def owner_start_workshop_remote(body: OwnerWorkshopRequest, user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    user_label = str(getattr(user, "display_name", None) or getattr(user, "username", None)
                     or "Multi-Servis OWNER")[:120]
    now = _now()
    with engine.begin() as con:
        grant = _active_pro(con, body.installationId)
        if not grant["mesh_node_id"]:
            raise HTTPException(409, "Brak powiązanego MeshAgent. Zdalna pomoc nie jest gotowa.")
        if _open(con, body.installationId):
            raise HTTPException(409, "Dla komputera istnieje już otwarta sesja.")
        sid = uuid.uuid4()
        capabilities = ["desktop"] + (["files"] if body.requestFiles else [])
        con.execute(text("""
            INSERT INTO guard.workshop_remote_sessions
            (id,installation_id,requested_by,subject,requested_capabilities,expires_at)
            VALUES (:sid,:iid,:requester,:subject,CAST(:cap AS jsonb),:expires)
        """), {"sid": sid, "iid": body.installationId, "requester": user_label,
               "subject": body.subject.strip(), "cap": json.dumps(capabilities),
               "expires": now + timedelta(minutes=3)})
        _audit(con, sid, "OWNER_REQUESTED", "OWNER", {"capabilities": capabilities})
        row = con.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid
        """), {"sid": sid}).mappings().one()
    return _session(row)


@router.get("/workshop/remote-sessions/{session_id}")
def owner_workshop_remote_detail(session_id: uuid.UUID,
                                 user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    with engine.connect() as con:
        row = con.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid
        """), {"sid": session_id}).mappings().first()
    if not row:
        raise HTTPException(404, "Sesja nie istnieje.")
    return _session(row)


@router.post("/workshop/remote-sessions/{session_id}/connect")
def owner_workshop_remote_connect(session_id: uuid.UUID,
                                  user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    now = _now()
    with engine.begin() as con:
        row = con.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions
            WHERE id=:sid FOR UPDATE
        """), {"sid": session_id}).mappings().first()
        if not row:
            raise HTTPException(404, "Sesja nie istnieje.")
        grant = _active_pro(con, row["installation_id"])
        if not grant["mesh_node_id"]:
            raise HTTPException(409, "Nie znaleziono powiązanego MeshAgent.")
        if row["status"] not in {"CONSENTED", "CONNECT_READY"}:
            raise HTTPException(409, "Klient nie wyraził aktualnej zgody na połączenie.")
        if row["status"] == "CONSENTED" and row["expires_at"] < now:
            raise HTTPException(410, "Zgoda wygasła.")
        granted = list(row["granted_capabilities"] or [])
        if "desktop" not in granted:
            raise HTTPException(403, "Nie ma zgody na pulpit.")
        old_public = row["mesh_public_id"]
        node = grant["mesh_node_id"]
    if old_public:
        try:
            meshcentral.revoke_share(node, old_public)
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(502, "Nie potwierdzono unieważnienia starego linku.") from exc
    try:
        share = meshcentral.create_share(node, "Multi-Servis " + str(session_id)[:8],
                                         granted, duration_minutes=15)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(502, "Nie udało się utworzyć bezpiecznego linku MeshCentral.") from exc
    try:
        with engine.begin() as con:
            # Recheck owner revocation and consent after the external call.
            row2 = con.execute(text("""
                SELECT status,granted_capabilities,expires_at
                FROM guard.workshop_remote_sessions WHERE id=:sid FOR UPDATE
            """), {"sid": session_id}).mappings().first()
            _active_pro(con, row["installation_id"])
            if not row2 or row2["status"] not in {"CONSENTED", "CONNECT_READY"}:
                raise HTTPException(409, "Zgoda została cofnięta.")
            if "desktop" not in list(row2["granted_capabilities"] or []):
                raise HTTPException(409, "Brak zgody na pulpit.")
            if row2["status"] == "CONSENTED" and row2["expires_at"] < _now():
                raise HTTPException(410, "Zgoda wygasła.")
            con.execute(text("""
                UPDATE guard.workshop_remote_sessions
                SET status='CONNECT_READY',mesh_public_id=:public_id,
                    mesh_share_expires_at=:expires,last_activity_at=now(),
                    last_error=NULL
                WHERE id=:sid
            """), {"sid": session_id, "public_id": share.public_id,
                   "expires": _now() + timedelta(minutes=15)})
            _audit(con, session_id, "MESH_SHARE_CREATED", "MESH",
                   {"capabilities": granted, "rotated": bool(old_public)})
    except Exception:
        try:
            meshcentral.revoke_share(node, share.public_id)
        except meshcentral.MeshCentralError:
            pass
        raise
    return {"sessionId": str(session_id), "url": share.url,
            "expiresAt": _iso(_now() + timedelta(minutes=15)), "capabilities": granted}


@router.post("/workshop/remote-sessions/{session_id}/end")
def owner_workshop_remote_end(session_id: uuid.UUID,
                              user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    _end_session(session_id, "OWNER", "OWNER_ENDED")
    return {"ended": True, "revokeConfirmed": True}


@router.post("/workshop/remote/mesh-bind")
def owner_workshop_mesh_bind(body: OwnerWorkshopMeshBind,
                             user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    node = body.meshNodeId.strip()
    if not node.startswith("node/"):
        raise HTTPException(400, "Wymagany pełny identyfikator MeshCentral node/…")
    with engine.begin() as con:
        _active_pro(con, body.installationId)
        existing = _open(con, body.installationId)
        if existing:
            raise HTTPException(409, "Najpierw zakończ bieżącą sesję.")
        con.execute(text("""
            INSERT INTO guard.workshop_remote_nodes(installation_id,mesh_node_id)
            VALUES (:iid,:node)
            ON CONFLICT (installation_id)
            DO UPDATE SET mesh_node_id=EXCLUDED.mesh_node_id,bound_at=now()
        """), {"iid": body.installationId, "node": node})
    return {"status": "ok", "meshNodeId": node}


@router.get("/workshop/remote/ready/{installation_id}")
def owner_workshop_remote_readiness(installation_id: uuid.UUID,
                                    user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    with engine.connect() as con:
        grant = _active_pro(con, installation_id)
    return {"serviceMode": "WORKSHOP", "edition": "PRO",
            "meshBound": bool(grant["mesh_node_id"]),
            "agentEnrollmentRequired": not bool(grant["mesh_node_id"])}
