from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal

from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner
from app.routers.multiguard_license import _panel_auth, _panel_html
from app.routers.multiguard_panel_settings import _csrf_token, _token_valid
from types import SimpleNamespace
import time
from app.routers.multiguard_runtime import (
    _ensure_schema as _ensure_runtime_schema,
    _require_agent,
)
from app.routers import multiguard_meshcentral as meshcentral


router = APIRouter(prefix="/multiguard", tags=["multi-guard-remote"])

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False


class AgentRemoteAuthBody(BaseModel):
    requestId: str
    nonce: str
    sentAt: datetime
    installationId: uuid.UUID
    deviceId: str = Field(min_length=16, max_length=128)
    serviceDeviceId: Optional[uuid.UUID] = None
    installationCredential: str = Field(min_length=32, max_length=512)


class AgentRemoteDecisionBody(AgentRemoteAuthBody):
    sessionId: uuid.UUID
    allowDesktop: bool
    allowFiles: bool = False


class AgentRemoteEndBody(AgentRemoteAuthBody):
    sessionId: uuid.UUID
    reason: str = Field(default="CLIENT_ENDED", max_length=80)


class AgentSessionMeshBody(AgentRemoteAuthBody):
    sessionId: uuid.UUID
    meshNodeId: str = Field(pattern=r"^[A-Za-z0-9@$]{64}$")


class OwnerRemoteCreateBody(BaseModel):
    supportRequestId: uuid.UUID
    requestFiles: bool = False


class OwnerStandingApprovalBody(BaseModel):
    deviceScope: Literal["OWNED_WORKSHOP", "CLIENT_DIAGNOSTIC"]
    priorConsentSha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    explicitConfirmation: Literal["CONFIRM_PRIOR_WRITTEN_CONSENT"]


class MeshBindBody(BaseModel):
    installationId: uuid.UUID
    meshNodeId: str = Field(min_length=8, max_length=300)


def _ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return

    _ensure_runtime_schema()

    statements = [
        """
        ALTER TABLE guard.installations
        ADD COLUMN IF NOT EXISTS mesh_node_id TEXT
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_guard_installations_mesh_node
        ON guard.installations(mesh_node_id)
        WHERE mesh_node_id IS NOT NULL
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.remote_sessions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            support_request_id UUID NOT NULL
                REFERENCES guard.support_requests(id) ON DELETE CASCADE,
            installation_id UUID NOT NULL
                REFERENCES guard.installations(id) ON DELETE CASCADE,
            service_device_id UUID NOT NULL
                REFERENCES core.devices(id) ON DELETE CASCADE,
            requested_by_user_id UUID,
            requested_by_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'REQUESTED'
                CHECK (
                    status IN (
                        'REQUESTED','CONSENTED','CONNECT_READY','ACTIVE',
                        'DENIED','ENDED','EXPIRED','ERROR'
                    )
                ),
            requested_capabilities JSONB NOT NULL DEFAULT '["desktop"]'::jsonb,
            granted_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
            requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            consented_at TIMESTAMPTZ,
            connected_at TIMESTAMPTZ,
            last_activity_at TIMESTAMPTZ,
            ended_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ NOT NULL,
            reconnect_until TIMESTAMPTZ,
            mesh_public_id TEXT,
            mesh_share_expires_at TIMESTAMPTZ,
            last_error TEXT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_remote_sessions_installation_open
        ON guard.remote_sessions(installation_id, requested_at DESC)
        WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_guard_remote_sessions_one_open_per_installation
        ON guard.remote_sessions(installation_id)
        WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_remote_sessions_support
        ON guard.remote_sessions(support_request_id, requested_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.remote_session_events (
            id BIGSERIAL PRIMARY KEY,
            remote_session_id UUID NOT NULL
                REFERENCES guard.remote_sessions(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            actor_type TEXT NOT NULL
                CHECK (actor_type IN ('CLIENT','TECHNICIAN','BACKEND','MESH')),
            actor_label TEXT,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            payload JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_remote_session_events
        ON guard.remote_session_events(remote_session_id, occurred_at DESC)
        """,
    ]

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))
        _SCHEMA_READY = True


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _iso(value):
    return value.isoformat() if value else None


def _plan_change_pending(connection, installation_internal_id) -> bool:
    return bool(connection.execute(text("""
        SELECT 1 FROM guard.license_plan_changes pc
        JOIN guard.license_links ll ON ll.id=pc.license_link_id
        JOIN guard.installations gi
          ON gi.installation_external_id=ll.installation_id
        WHERE gi.id=:id AND pc.status='PENDING'
        LIMIT 1
    """), {"id":installation_internal_id}).first())


def _has_active_remote_pro(installation, now: datetime) -> bool:
    """Only a current, unexpired PRO entitlement may use remote support."""
    return (
        str(installation["plan_code"]).upper() == "PRO"
        and installation["lifecycle"] == "ACTIVE"
        and (installation["valid_until"] is None
             or installation["valid_until"] > now)
        and (installation.get("is_current", True) is True)
    )


def _owner_label(user: CurrentUser) -> tuple[Optional[uuid.UUID], str]:
    raw_id = getattr(user, "id", None)
    try:
        user_id = uuid.UUID(str(raw_id)) if raw_id else None
    except (ValueError, TypeError):
        user_id = None

    name = (
        getattr(user, "display_name", None)
        or getattr(user, "username", None)
        or getattr(user, "name", None)
        or "OWNER"
    )
    return user_id, str(name)[:120]


def _remote_public(row):
    if not row:
        return None
    return {
        "sessionId": str(row["id"]),
        "supportRequestId": str(row["support_request_id"]),
        "status": row["status"],
        "technicianDisplayName": row["requested_by_name"],
        "subject": row.get("subject"),
        "requestedCapabilities": list(row["requested_capabilities"] or []),
        "grantedCapabilities": list(row["granted_capabilities"] or []),
        "requestedAt": _iso(row["requested_at"]),
        "expiresAt": _iso(row.get("mesh_share_expires_at")
                          if row["status"] in {"CONNECT_READY", "ACTIVE"}
                          else row["expires_at"]),
        "consentedAt": _iso(row["consented_at"]),
        "connectedAt": _iso(row["connected_at"]),
        "endedAt": _iso(row["ended_at"]),
        "reconnectUntil": _iso(row["reconnect_until"]),
        "meshReady": bool(row.get("mesh_public_id")),
        "lastError": row.get("last_error"),
    }


def _audit(
    connection,
    session_id,
    event_type: str,
    actor_type: str,
    actor_label: Optional[str] = None,
    payload=None,
):
    connection.execute(
        text(
            """
            INSERT INTO guard.remote_session_events(
                remote_session_id,event_type,actor_type,actor_label,payload
            )
            VALUES(:session_id,:event_type,:actor_type,:actor_label,CAST(:payload AS jsonb))
            """
        ),
        {
            "session_id": session_id,
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_label": actor_label,
            "payload": _json(payload or {}),
        },
    )


def _expire_and_find_open(connection, installation_id, *, entitlement_lost=False):
    now = datetime.now(timezone.utc)
    # Auto-expiry is processed on the next poll/request (no background
    # timer). Never mark a session EXPIRED while its remote URL still works.
    expired = connection.execute(
        text(
            """
            SELECT rs.id,rs.mesh_public_id,gi.mesh_node_id
            FROM guard.remote_sessions rs
            JOIN guard.installations gi ON gi.id=rs.installation_id
            WHERE rs.installation_id=:installation_id
              AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
              AND (
                :entitlement_lost
                OR (rs.status IN ('REQUESTED','CONSENTED') AND rs.expires_at<=:now)
                OR (rs.status IN ('CONNECT_READY','ACTIVE')
                    AND (rs.mesh_share_expires_at IS NULL
                         OR rs.mesh_share_expires_at<=:now))
              )
            ORDER BY rs.requested_at,rs.id
            FOR UPDATE OF rs
            """
        ),
        {"installation_id": installation_id, "now": now,
         "entitlement_lost": entitlement_lost},
    ).mappings().all()
    for item in expired:
        if item["mesh_public_id"]:
            if not item["mesh_node_id"]:
                raise HTTPException(
                    502, "Brak MeshCentral ID — nie potwierdzono wygaśnięcia sesji."
                )
            try:
                meshcentral.revoke_share(item["mesh_node_id"], item["mesh_public_id"])
            except meshcentral.MeshCentralError as exc:
                raise HTTPException(
                    502, "Nie potwierdzono zamknięcia wygasłego linku MeshCentral."
                ) from exc
        connection.execute(
            text(
                """
                UPDATE guard.remote_sessions
                SET status='EXPIRED',
                    ended_at=COALESCE(ended_at,:now),
                    last_activity_at=:now,
                    mesh_public_id=NULL,
                    mesh_share_expires_at=NULL
                WHERE id=:id
                """
            ),
            {"id": item["id"], "now": now},
        )
        event_type = "PRO_ENTITLEMENT_LOST" if entitlement_lost else "SESSION_EXPIRED"
        _audit(connection, item["id"], event_type, "BACKEND", "Multi-Servis")
    return connection.execute(
        text(
            """
            SELECT rs.*,sr.subject
            FROM guard.remote_sessions rs
            JOIN guard.support_requests sr ON sr.id=rs.support_request_id
            WHERE rs.installation_id=:installation_id
              AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
            ORDER BY rs.requested_at DESC
            LIMIT 1
            """
        ),
        {"installation_id": installation_id},
    ).mappings().first()


def _require_transport_consent(row, installation_id, now):
    if (not row or row["installation_id"] != installation_id
            or row["status"] != "CONSENTED" or row["expires_at"] <= now
            or row.get("ended_at") is not None or row.get("consented_at") is None
            or "desktop" not in (row.get("granted_capabilities") or [])
            or row.get("mesh_public_id")):
        raise HTTPException(409, "Brak aktualnej zgody na rejestrację agenta tej sesji.")


@router.post("/agent/remote/mesh-enroll")
def agent_session_mesh_enroll(body: AgentSessionMeshBody):
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    now = datetime.now(timezone.utc)
    if body.sentAt.tzinfo is None or abs((now - body.sentAt).total_seconds()) > 300:
        raise HTTPException(401, "Wygasłe żądanie rejestracji agenta.")
    def validate(db, lock=False):
        authenticated = _require_agent(db, body.installationId, body.deviceId, body.installationCredential)
        installation = db.execute(text("SELECT * FROM guard.installations WHERE id=:iid"
                                       + (" FOR UPDATE" if lock else "")),
                                  {"iid":authenticated["id"]}).mappings().first()
        if (not installation or not _has_active_remote_pro(installation, datetime.now(timezone.utc))
                or _plan_change_pending(db, installation["id"])):
            raise HTTPException(403, "Zdalna pomoc wymaga aktywnego Pro.")
        if body.serviceDeviceId and body.serviceDeviceId != installation["service_device_id"]:
            raise HTTPException(409, "Nieprawidłowe powiązanie instalacji.")
        row = db.execute(text("SELECT * FROM guard.remote_sessions WHERE id=:sid"
                              + (" FOR UPDATE" if lock else "")),
                         {"sid":body.sessionId}).mappings().first()
        _require_transport_consent(row, installation["id"], datetime.now(timezone.utc))
        return installation
    with engine.connect() as db:
        validate(db)
    try:
        node = meshcentral.verify_session_node(body.meshNodeId, str(body.sessionId), persistent_service=True)
    except meshcentral.MeshCentralError as exc:
        raise HTTPException(409, "Serwer nie potwierdził jeszcze agenta tej sesji.") from exc
    with engine.begin() as db:
        installation = validate(db, True)
        if installation.get("mesh_node_id") not in (None, "", node):
            raise HTTPException(409, "Instalacja ma już innego agenta; wymagana kontrola OWNER.")
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:node))"), {"node":node})
        # One bundled SCM MeshAgent retains its node across PRO license
        # modes. Never adopt a node bound to a DIFFERENT installation.
        if db.execute(text("""
            SELECT 1 FROM guard.workshop_mesh_nodes
            WHERE mesh_node_id=:node AND installation_id<>:iid LIMIT 1
        """), {"node":node, "iid":installation["id"]}).first():
            raise HTTPException(409, "Agent jest przypisany do innej instalacji.")
        # An old workshop viewer must be explicitly ended/revoked before
        # reusing this identity for commercial remote access.
        if db.execute(text("""
            SELECT 1 FROM guard.workshop_remote_sessions
            WHERE installation_id=:iid AND mesh_public_id IS NOT NULL
              AND status IN ('CONNECT_READY','ACTIVE') LIMIT 1
        """), {"iid":installation["id"]}).first():
            raise HTTPException(409, "Najpierw zakończ aktywne udostępnienie serwisowe.")
        db.execute(text("UPDATE guard.installations SET mesh_node_id=:node WHERE id=:iid"),
                   {"node":node,"iid":installation["id"]})
        _audit(db, body.sessionId, "SESSION_AGENT_VERIFIED", "CLIENT")
    return {"requestId":body.requestId,"sessionId":str(body.sessionId),"accepted":True}


@router.post("/agent/remote/poll")
def agent_remote_poll(body: AgentRemoteAuthBody):
    _ensure_schema()
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        installation = _require_agent(
            connection,
            body.installationId,
            body.deviceId,
            body.installationCredential,
        )
        if (
            body.serviceDeviceId
            and body.serviceDeviceId != installation["service_device_id"]
        ):
            raise HTTPException(
                409,
                "service_device_id nie pasuje do powiązania instalacji.",
            )

        entitlement_lost = (
            not _has_active_remote_pro(installation, now)
            or _plan_change_pending(connection, installation["id"])
        )
        # Previously the early return skipped cleanup of a MeshCentral URL
        # when the PRO licence expired. Revoke the URL at this poll first.
        row = _expire_and_find_open(
            connection, installation["id"], entitlement_lost=entitlement_lost
        )
        if entitlement_lost:
            return {
                "requestId": body.requestId,
                "serverTime": now.isoformat(),
                "session": None,
            }
        if row and row["status"] in {"CONNECT_READY", "ACTIVE"}:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET last_activity_at=:now
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": row["id"]},
            )

    return {
        "requestId": body.requestId,
        "serverTime": now.isoformat(),
        "session": _remote_public(row),
    }


@router.post("/agent/remote/decision")
def agent_remote_decision(body: AgentRemoteDecisionBody):
    _ensure_schema()
    now = datetime.now(timezone.utc)

    with engine.begin() as connection:
        installation = _require_agent(
            connection,
            body.installationId,
            body.deviceId,
            body.installationCredential,
        )
        if (not _has_active_remote_pro(installation, now)
                or _plan_change_pending(connection, installation["id"])) and body.allowDesktop:
            raise HTTPException(403, "Zdalna pomoc wymaga aktywnej licencji Pro.")
        row = connection.execute(
            text(
                """
                SELECT rs.*,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id AND rs.installation_id=:installation_id
                FOR UPDATE
                """
            ),
            {
                "session_id": body.sessionId,
                "installation_id": installation["id"],
            },
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono żądania sesji zdalnej.")
        if row["status"] != "REQUESTED":
            raise HTTPException(
                409,
                "To żądanie zdalnej pomocy nie oczekuje już na decyzję.",
            )
        if row["expires_at"] <= now:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='EXPIRED',ended_at=:now
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": body.sessionId},
            )
            # Return an HTTP response while leaving engine.begin() normally.
            # Raising here would roll back the EXPIRED write.
            _audit(
                connection, body.sessionId, "CLIENT_REQUEST_EXPIRED",
                "BACKEND", "Multi-Servis",
            )
            return JSONResponse(
                status_code=410, content={"detail": "Żądanie zdalnej pomocy wygasło."},
            )

        requested = set(row["requested_capabilities"] or [])
        if not body.allowDesktop:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='DENIED',ended_at=:now,granted_capabilities='[]'::jsonb
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": body.sessionId},
            )
            _audit(
                connection,
                body.sessionId,
                "CLIENT_DENIED",
                "CLIENT",
                "Multi-Guard",
            )
        else:
            granted = ["desktop"]
            if body.allowFiles and "files" in requested:
                granted.append("files")
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET
                        status='CONSENTED',
                        consented_at=:now,
                        granted_capabilities=CAST(:granted AS jsonb),
                        expires_at=:expires_at,
                        reconnect_until=:reconnect_until,
                        last_activity_at=:now
                    WHERE id=:session_id
                    """
                ),
                {
                    "now": now,
                    "expires_at": now + timedelta(minutes=5),
                    "granted": _json(granted),
                    "reconnect_until": now + timedelta(minutes=10),
                    "session_id": body.sessionId,
                },
            )
            _audit(
                connection,
                body.sessionId,
                "CLIENT_CONSENTED",
                "CLIENT",
                "Multi-Guard",
                {"granted": granted},
            )

        updated = connection.execute(
            text(
                """
                SELECT rs.*,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id
                """
            ),
            {"session_id": body.sessionId},
        ).mappings().first()

    return {
        "requestId": body.requestId,
        "serverTime": now.isoformat(),
        "session": _remote_public(updated),
    }


@router.post("/agent/remote/end")
def agent_remote_end(body: AgentRemoteEndBody):
    _ensure_schema()
    now = datetime.now(timezone.utc)
    public_id = None
    mesh_node_id = None

    with engine.begin() as connection:
        installation = _require_agent(
            connection,
            body.installationId,
            body.deviceId,
            body.installationCredential,
        )
        row = connection.execute(
            text(
                """
                SELECT rs.*,gi.mesh_node_id
                FROM guard.remote_sessions rs
                JOIN guard.installations gi ON gi.id=rs.installation_id
                WHERE rs.id=:session_id AND rs.installation_id=:installation_id
                FOR UPDATE
                """
            ),
            {
                "session_id": body.sessionId,
                "installation_id": installation["id"],
            },
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono sesji zdalnej.")

        # The client sees "ended" only after the remote share is
        # demonstrably gone. A Mesh failure keeps the session retryable.
        public_id = row["mesh_public_id"]
        mesh_node_id = row["mesh_node_id"]
        if public_id:
            if not mesh_node_id:
                raise HTTPException(502,
                    "Nie można potwierdzić zakończenia zdalnego pulpitu.")
            try:
                meshcentral.revoke_share(mesh_node_id, public_id)
            except meshcentral.MeshCentralError as exc:
                raise HTTPException(
                    502, "Nie unieważniono linku MeshCentral. Ponów zakończenie."
                ) from exc

        if row["status"] not in {"ENDED", "DENIED", "EXPIRED"} or public_id:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='ENDED',
                        ended_at=COALESCE(ended_at,:now),
                        last_activity_at=:now,
                        mesh_public_id=NULL,
                        mesh_share_expires_at=NULL
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": body.sessionId},
            )
            _audit(
                connection,
                body.sessionId,
                "CLIENT_ENDED",
                "CLIENT",
                "Multi-Guard",
                {"reason": body.reason[:80]},
            )

    return {
        "requestId": body.requestId,
        "serverTime": now.isoformat(),
        "ended": True,
        "revokeConfirmed": True,
    }


@router.post("/remote-sessions")
def create_remote_session(
    body: OwnerRemoteCreateBody,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    now = datetime.now(timezone.utc)
    user_id, user_label = _owner_label(user)

    with engine.begin() as connection:
        support = connection.execute(
            text(
                """
                SELECT
                    sr.id,sr.installation_id,sr.service_device_id,sr.subject,
                    gi.plan_code,gi.lifecycle,gi.valid_until,gi.is_current,
                    gi.mesh_node_id,sr.status AS support_status
                FROM guard.support_requests sr
                JOIN guard.installations gi ON gi.id=sr.installation_id
                WHERE sr.id=:support_request_id
                """
            ),
            {"support_request_id": body.supportRequestId},
        ).mappings().first()

        if not support:
            raise HTTPException(404, "Nie znaleziono zgłoszenia Multi-Guard.")
        if (not _has_active_remote_pro(support, now)
                or _plan_change_pending(connection,support["installation_id"])):
            raise HTTPException(403, "Zdalna pomoc wymaga aktywnej licencji Pro.")
        if support["support_status"] in {"RESOLVED", "CANCELLED"}:
            raise HTTPException(409, "Zgłoszenie pomocy jest już zamknięte.")
        # A Standard->Pro client may have a dormant bundled agent.
        # Ask for each-session consent first; require a verified MeshCentral
        # node later, in remote_session_connect, before any transport link.

        existing = _expire_and_find_open(
            connection,
            support["installation_id"],
        )
        if existing:
            raise HTTPException(
                409,
                "Dla tego urządzenia istnieje już otwarte żądanie "
                "lub sesja zdalna.",
            )

        capabilities = ["desktop"] + (["files"] if body.requestFiles else [])
        session_id = uuid.uuid4()
        connection.execute(
            text(
                """
                INSERT INTO guard.remote_sessions(
                    id,support_request_id,installation_id,service_device_id,
                    requested_by_user_id,requested_by_name,
                    requested_capabilities,expires_at,last_activity_at
                )
                VALUES(
                    :id,:support_request_id,:installation_id,:service_device_id,
                    :requested_by_user_id,:requested_by_name,
                    CAST(:capabilities AS jsonb),:expires_at,:now
                )
                """
            ),
            {
                "id": session_id,
                "support_request_id": support["id"],
                "installation_id": support["installation_id"],
                "service_device_id": support["service_device_id"],
                "requested_by_user_id": user_id,
                "requested_by_name": user_label,
                "capabilities": _json(capabilities),
                "expires_at": now + timedelta(minutes=5),
                "now": now,
            },
        )
        _audit(
            connection,
            session_id,
            "TECHNICIAN_REQUESTED",
            "TECHNICIAN",
            user_label,
            {"capabilities": capabilities},
        )
        connection.execute(
            text(
                """
                UPDATE guard.support_requests
                SET
                    status='IN_PROGRESS',
                    seen_at=COALESCE(seen_at,:now),
                    started_at=COALESCE(started_at,:now)
                WHERE id=:support_request_id
                """
            ),
            {"now": now, "support_request_id": support["id"]},
        )
        row = connection.execute(
            text(
                """
                SELECT rs.*,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id
                """
            ),
            {"session_id": session_id},
        ).mappings().first()

    return _remote_public(row)


@router.get("/remote-sessions/{session_id}")
def remote_session_detail(
    session_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID sesji.") from exc

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT rs.*,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id
                """
            ),
            {"session_id": session_uuid},
        ).mappings().first()

    if not row:
        raise HTTPException(404, "Nie znaleziono sesji.")
    return _remote_public(row)


@router.post("/remote-sessions/{session_id}/connect")
def remote_session_connect(
    session_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID sesji.") from exc

    now = datetime.now(timezone.utc)
    user_id, user_label = _owner_label(user)

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                SELECT rs.*,gi.mesh_node_id,gi.plan_code,gi.lifecycle,
                       gi.valid_until,gi.is_current,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.installations gi ON gi.id=rs.installation_id
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id
                FOR UPDATE OF rs,gi
                """
            ),
            {"session_id": session_uuid},
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono sesji.")
        if (not _has_active_remote_pro(row, now)
                or _plan_change_pending(connection,row["installation_id"])):
            raise HTTPException(403, "Zdalna pomoc wymaga aktywnej licencji Pro.")
        if row["status"] not in {"CONSENTED", "CONNECT_READY", "ACTIVE"}:
            raise HTTPException(
                409,
                "Klient nie wyraził zgody na tę sesję.",
            )
        expired_consent = row["status"] == "CONSENTED" and row["expires_at"] <= now
        if (row["status"] in {"CONNECT_READY", "ACTIVE"}
                and (row["mesh_share_expires_at"] is None
                     or row["mesh_share_expires_at"] <= now)):
            raise HTTPException(410, "Udostępnienie wygasło; rozpocznij nową sesję.")
        if expired_consent:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='EXPIRED',ended_at=COALESCE(ended_at,:now)
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": session_uuid},
            )
            _audit(
                connection, session_uuid, "CONSENT_EXPIRED",
                "BACKEND", "Multi-Servis",
            )
        else:
            if not row["mesh_node_id"]:
                raise HTTPException(409, "Brak powiązania MeshCentral dla urządzenia.")
            granted = list(row["granted_capabilities"] or [])
            if "desktop" not in granted:
                raise HTTPException(409, "Brak zgody na pulpit zdalny.")
            node_id = row["mesh_node_id"]
            existing_public_id = row["mesh_public_id"]

    # Raising only after engine.begin() commits the expired state and audit.
    if expired_consent:
        raise HTTPException(
            410, "Zgoda klienta na rozpoczęcie sesji wygasła.",
        )

    if existing_public_id:
        try:
            meshcentral.revoke_share(node_id, existing_public_id)
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(
                502,
                f"Nie udało się bezpiecznie obrócić poprzedniego linku: {exc}",
            ) from exc

    # Bound the advertised lease to the start of the external MeshCentral call.
    # A slow response must not extend our local expiry beyond MeshCentral's.
    share_expires = datetime.now(timezone.utc) + timedelta(minutes=60)
    try:
        share = meshcentral.create_share(
            node_id,
            f"Multi-Servis {str(session_uuid)[:8]}",
            granted,
            60,
        )
    except meshcentral.MeshCentralError as exc:
        with engine.begin() as connection:
            updated = connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET last_error=:error,last_activity_at=:now
                    WHERE id=:session_id
                      AND status IN ('CONSENTED','CONNECT_READY','ACTIVE')
                      AND mesh_public_id IS NOT DISTINCT FROM :expected_public_id
                    """
                ),
                {
                    "error": str(exc)[:1000],
                    "now": datetime.now(timezone.utc),
                    "session_id": session_uuid,
                    "expected_public_id": existing_public_id,
                },
            )
            if updated.rowcount:
                _audit(
                    connection,
                    session_uuid,
                    "MESH_SHARE_FAILED",
                    "MESH",
                    "MeshCentral",
                    {"error": str(exc)[:500]},
                )
        raise HTTPException(502, f"MeshCentral: {exc}") from exc

    try:
        with engine.begin() as connection:
            current = connection.execute(text("""
                SELECT rs.status,rs.expires_at,rs.ended_at,
                       rs.mesh_public_id,rs.mesh_share_expires_at,
                       rs.granted_capabilities,
                       gi.plan_code,gi.lifecycle,gi.valid_until,
                       gi.is_current,gi.mesh_node_id
                FROM guard.remote_sessions rs
                JOIN guard.installations gi ON gi.id=rs.installation_id
                WHERE rs.id=:sid FOR UPDATE OF rs,gi
            """), {"sid": session_uuid}).mappings().first()
            # If MeshCentral was slow enough for the new lease to expire,
            # revoke it through the existing rollback path rather than
            # publishing an already-expired remote-control URL.
            if share_expires <= datetime.now(timezone.utc):
                raise HTTPException(410, "Nowy link MeshCentral wygasł przed zapisem.")
            if (not current or not _has_active_remote_pro(current, datetime.now(timezone.utc))
                    or current["mesh_node_id"] != node_id
                    or current["mesh_public_id"] != existing_public_id
                    or current["ended_at"] is not None
                    or list(current["granted_capabilities"] or []) != granted
                    or (current["status"] == "CONSENTED"
                        and current["expires_at"] <= datetime.now(timezone.utc))
                    or (current["status"] in {"CONNECT_READY", "ACTIVE"}
                        and (current["mesh_share_expires_at"] is None
                             or current["mesh_share_expires_at"] <= datetime.now(timezone.utc)))
                    or _plan_change_pending(connection,row["installation_id"])
                    or current["status"] not in {"CONSENTED", "CONNECT_READY", "ACTIVE"}):
                raise HTTPException(
                    403, "Licencja, zgoda lub przypisanie MeshCentral zmieniły się w trakcie."
                )
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET
                        status='CONNECT_READY',
                        mesh_public_id=:public_id,
                        mesh_share_expires_at=:expires_at,
                        last_error=NULL,
                        last_activity_at=:now
                    WHERE id=:session_id
                    """
                ),
                {
                    "public_id": share.public_id,
                    "expires_at": share_expires,
                    "now": now,
                    "session_id": session_uuid,
                },
            )
            _audit(
                connection,
                session_uuid,
                (
                    "MESH_SHARE_ROTATED"
                    if existing_public_id
                    else "MESH_SHARE_CREATED"
                ),
                "MESH",
                "MeshCentral",
                {
                    "publicId": share.public_id,
                    "capabilities": granted,
                    "requestedBy": user_label,
                },
            )
    except Exception:
        try:
            meshcentral.revoke_share(node_id, share.public_id)
        except meshcentral.MeshCentralError:
            pass
        raise

    return {
        "sessionId": str(session_uuid),
        "url": share.url,
        "expiresAt": share_expires.isoformat(),
        "capabilities": granted,
    }


@router.post("/remote-sessions/{session_id}/end")
def remote_session_end(
    session_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID sesji.") from exc

    now = datetime.now(timezone.utc)
    _, user_label = _owner_label(user)

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                SELECT rs.*,gi.mesh_node_id
                FROM guard.remote_sessions rs
                JOIN guard.installations gi ON gi.id=rs.installation_id
                WHERE rs.id=:session_id
                FOR UPDATE
                """
            ),
            {"session_id": session_uuid},
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono sesji.")

        # Never mark a remote session ENDED while its MeshCentral link
        # might still be usable. On failure leave state retryable.
        public_id = row["mesh_public_id"]
        node_id = row["mesh_node_id"]
        if public_id:
            if not node_id:
                raise HTTPException(502,
                    "Brak MeshCentral ID. Nie można potwierdzić zakończenia sesji.")
            try:
                meshcentral.revoke_share(node_id, public_id)
            except meshcentral.MeshCentralError as exc:
                raise HTTPException(
                    502,
                    "Nie udało się unieważnić linku MeshCentral. "
                    "Sesja nadal wymaga zakończenia; ponów operację."
                ) from exc

        if row["status"] != "ENDED" or public_id:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET
                        status='ENDED',
                        ended_at=COALESCE(ended_at,:now),
                        last_activity_at=:now,
                        mesh_public_id=NULL,
                        mesh_share_expires_at=NULL
                    WHERE id=:session_id
                    """
                ),
                {"now": now, "session_id": session_uuid},
            )
            _audit(
                connection,
                session_uuid,
                "TECHNICIAN_ENDED",
                "TECHNICIAN",
                user_label,
            )

    return {"status": "ok"}


@router.post("/remote/mesh-bind")
def bind_mesh_node(
    body: MeshBindBody,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    node_id = body.meshNodeId.strip()
    if not node_id.startswith("node/"):
        raise HTTPException(
            400,
            "meshNodeId musi być pełnym identyfikatorem MeshCentral node/…",
        )

    with engine.begin() as connection:
        # A different Mesh node cannot replace the one belonging to an
        # existing public share. Otherwise later revoke_share() would target
        # the wrong node. Same-ID rebind remains an idempotent no-op.
        changed = connection.execute(
            text(
                """
                UPDATE guard.installations AS gi
                SET mesh_node_id=:node_id,updated_at=now()
                WHERE gi.installation_external_id=:installation_id
                  AND gi.is_current=TRUE
                  AND (
                    gi.mesh_node_id=:node_id OR NOT EXISTS (
                        SELECT 1 FROM guard.remote_sessions rs
                        WHERE rs.installation_id=gi.id
                          AND rs.mesh_public_id IS NOT NULL
                    )
                  )
                """
            ),
            {
                "node_id": node_id,
                "installation_id": body.installationId,
            },
        ).rowcount
        if not changed:
            exists = connection.execute(
                text(
                    """
                    SELECT id FROM guard.installations
                    WHERE installation_external_id=:id AND is_current=TRUE
                    """
                ),
                {"id": body.installationId},
            ).first()
            if exists:
                raise HTTPException(
                    409, "Najpierw zakończ aktywne udostępnienie MeshCentral."
                )
            raise HTTPException(
                404, "Nie znaleziono bieżącej instalacji Multi-Guard."
            )

    return {"status": "ok", "meshNodeId": node_id}




def _owner_panel_csrf(x_owner_csrf: str = Header(default="")) -> None:
    if not _token_valid(x_owner_csrf):
        raise HTTPException(403, "Wygasły lub nieprawidłowy token panelu.")


def _panel_owner_identity():
    # Panel-only identity, never accepted by the separate bearer API.
    return SimpleNamespace(id=None, display_name="OWNER")


@router.post("/panel/remote-api/sessions")
def panel_create_remote_session(
    body: OwnerRemoteCreateBody,
    _: None = Depends(_panel_auth),
    __: None = Depends(_owner_panel_csrf),
):
    return create_remote_session(body, user=_panel_owner_identity())


@router.get("/panel/remote-api/sessions/{session_id}")
def panel_remote_session_detail(session_id: str, _: None = Depends(_panel_auth)):
    return remote_session_detail(session_id, user=_panel_owner_identity())


@router.post("/panel/remote-api/sessions/{session_id}/connect")
def panel_remote_session_connect(
    session_id: str,
    _: None = Depends(_panel_auth),
    __: None = Depends(_owner_panel_csrf),
):
    return remote_session_connect(session_id, user=_panel_owner_identity())


@router.post("/panel/remote-api/sessions/{session_id}/end")
def panel_remote_session_end(
    session_id: str,
    _: None = Depends(_panel_auth),
    __: None = Depends(_owner_panel_csrf),
):
    return remote_session_end(session_id, user=_panel_owner_identity())


@router.get("/panel/remote")
def owner_remote_overview(_: None = Depends(_panel_auth)):
    """Compact full-width PRO fleet and support history; never render finances.

    This view does not grant remote access: session creation still requires
    OWNER API authorization and a fresh, verified customer consent.
    """
    from fastapi.responses import HTMLResponse
    from html import escape

    with engine.connect() as db:
        rows = db.execute(text("""
            SELECT gi.id, gi.installation_external_id,
                   gi.plan_code, gi.lifecycle, gi.valid_until, gi.is_current,
                   p.hostname, COALESCE(d.manufacturer,p.manufacturer) AS manufacturer,
                   COALESCE(d.model,p.model) AS model,
                   sr.id AS request_id, sr.subject AS request_subject,
                   sr.status AS request_status, sr.created_at AS request_created
            FROM guard.installations gi
            LEFT JOIN core.devices d ON d.id=gi.service_device_id
            LEFT JOIN guard.pending_installations p ON p.installation_id=gi.installation_external_id
            LEFT JOIN guard.support_requests sr ON sr.installation_id=gi.id
            WHERE gi.is_current=TRUE AND UPPER(gi.plan_code)='PRO'
            ORDER BY (CASE WHEN sr.status NOT IN ('RESOLVED','CANCELLED') THEN 0 ELSE 1 END), sr.created_at DESC NULLS LAST, gi.id
            LIMIT 1500
        """)).mappings().all()

    # Device identity comes only from the internal core.devices foreign key,
    # never from hostname, client name, or model similarity.
    with engine.connect() as db:
        linked_orders = db.execute(text("""
            SELECT gi.id AS installation_internal_id, so.id AS order_id,
                   so.reception_number, so.received_at,
                   (SELECT count(*) FROM service.service_order_media m
                    JOIN core.storage_objects o ON o.id=m.storage_object_id
                    WHERE m.service_order_id=so.id
                      AND m.deleted_at IS NULL AND o.deleted_at IS NULL) AS photo_count
            FROM guard.installations gi
            JOIN service.service_orders so ON so.device_id=gi.service_device_id
            WHERE gi.is_current=TRUE AND gi.service_device_id IS NOT NULL
            ORDER BY so.received_at DESC
            LIMIT 3000
        """)).mappings().all()
    orders_by_installation = {}
    for service_row in linked_orders:
        orders_by_installation.setdefault(
            str(service_row["installation_internal_id"]), []
        ).append(service_row)

    devices = {}
    for row in rows:
        key = str(row["id"])
        if key not in devices:
            devices[key] = {"info": row, "requests": []}
        if row["request_id"] is not None:
            devices[key]["requests"].append(row)

    def safe(value):
        return escape(str(value if value is not None else ""), quote=True)

    # Show every active PRO installation; requested help sorts before idle devices.
    output = []
    for device in sorted(devices.values(), key=lambda dev: (
        0 if any(str(req['request_status']) not in ('RESOLVED', 'CANCELLED') for req in dev['requests']) else 1,
        -max((req['request_created'].timestamp() if req['request_created'] else 0)
             for req in dev['requests']) if dev['requests'] else 0
    )):
        item = device["info"]
        external = str(item["installation_external_id"])
        machine = " ".join(str(item[k] or "").strip() for k in ("manufacturer", "model")).strip()
        machine = machine or str(item["hostname"] or "Komputer bez nazwy")
        valid = item["valid_until"]
        expiry = valid.strftime("%d.%m.%Y") if valid else "Bez daty"
        requests = device["requests"]
        history = "".join(
            '<li><span>' + safe((r["request_created"].strftime("%d.%m.%Y") if r["request_created"] else "")) +
            '</span> ' + safe(r["request_subject"]) + ' · ' + safe(r["request_status"]) + '</li>'
            for r in requests
        )
        disclosure = (
            '<details><summary>' + str(len(requests)) + ' zgłoszeń</summary><ul>' +
            history + '</ul></details>'
            if requests else '<span class="muted">Brak zgłoszeń</span>'
        )
        details_url = '/multiguard/panel/device/' + safe(item["id"])
        associated = orders_by_installation.get(str(item["id"]), [])
        repairs = (
            '<details><summary>' + str(len(associated)) + ' napraw</summary><ul>' +
            ''.join(
                '<li><a href="/multiguard/panel/service/' + safe(o["order_id"]) + '">' +
                safe(o["reception_number"]) + '</a></li>' for o in associated
            ) + '</ul></details>'
            if associated else '<span class="muted">Brak powiązanych napraw</span>'
        )
        total_photos = sum(int(o["photo_count"] or 0) for o in associated)
        photos = (
            '<details><summary>' + str(total_photos) + ' zdjęć/plików</summary><ul>' +
            ''.join(
                '<li><a href="/multiguard/panel/service/' + safe(o["order_id"]) + '">' +
                safe(o["reception_number"]) + ': ' + str(int(o["photo_count"] or 0)) + '</a></li>'
                for o in associated if int(o["photo_count"] or 0) > 0
            ) + '</ul></details>'
            if total_photos else '<span class="muted">Brak zdjęć</span>'
        )
        ready_request = next(
            (req for req in requests if str(req["request_status"]) not in ("RESOLVED", "CANCELLED")),
            None,
        )
        connect_target = (
            '/multiguard/panel/remote/session/' + safe(ready_request["request_id"])
            if ready_request else '/multiguard/panel/remote/device/' + safe(item["id"])
        )
        connect_action = (
            '<a class="button-link compact" target="_blank" rel="noopener" '
            'onclick="return confirm(\'Czy na pewno rozpocząć procedurę połączenia z tym komputerem?\')" '
            'href="' + connect_target + '">POŁĄCZ</a> '
            if str(item["lifecycle"]) == "ACTIVE"
            else '<span class="muted">Licencja nieaktywna</span> '
        )
        output.append(
            '<tr><td><code>' + safe(external[:12]) + '</code></td>'
            '<td><a href="' + details_url + '">' + safe(machine) + '</a>'
            '<small style="display:block">' + safe(item["hostname"]) + '</small></td>'
            '<td>PRO · ' + safe(item["lifecycle"]) + '</td>'
            '<td>' + safe(expiry) + '</td>'
            '<td>' + disclosure + '</td>'
            '<td>' + repairs + '</td><td>' + photos + '</td>'
            '<td>' + connect_action + '<a class="button-link compact" href="' + details_url + '">SZCZEGÓŁY</a></td></tr>'
        )
    # Workshop Pro and customer support are separate authorization modes.
    # Never treat a workshop grant as an ordinary paid licence.
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    with engine.connect() as db:
        workshop_rows = db.execute(text('''
            SELECT p.installation_id, p.status, g.edition,
                   p.hostname,p.manufacturer,p.model,
                   p.first_seen_at AS registered_at,
                   COUNT(wsr.id) AS request_count
            FROM guard.pending_installations p
            JOIN guard.workshop_grants g ON g.installation_id=p.installation_id
            LEFT JOIN guard.workshop_support_requests wsr
                ON wsr.installation_id=p.installation_id
            WHERE g.enabled=TRUE AND g.edition='PRO'
              AND p.status NOT IN ('ASSIGNED','PROVISIONED','ARCHIVED','UNINSTALLED','IGNORED')
            GROUP BY p.installation_id,p.status,g.edition,p.hostname,p.manufacturer,p.model,p.first_seen_at
            ORDER BY p.first_seen_at DESC
            LIMIT 500
        ''')).mappings().all()
    workshop_output = []
    for item in workshop_rows:
        iid = safe(item['installation_id'])
        workshop_output.append(
            '<tr><td><code>' + iid[:12] + '</code></td>'
            '<td>' + safe(item['hostname'] or (str(item['manufacturer'] or '') + ' ' + str(item['model'] or '')).strip() or 'Komputer serwisowy') + '</td><td>PRO · TRYB SERWISOWY</td>'
            '<td>Bezterminowo</td><td>' + str(int(item['request_count'])) + ' zgłoszeń</td>'
            '<td>—</td><td>—</td>'
            '<td><a class="button-link compact" target="_blank" rel="noopener" '
            'href="/multiguard/panel/remote/workshop/' + iid + '">POŁĄCZ</a></td></tr>'
        )
    body = (
        '<section class="card"><div class="eyebrow">MULTI-SERVIS / ZDALNA POMOC</div>'
        '<h1>Komputery PRO</h1><p>Lista urządzeń i zgłoszeń. Kwoty napraw '
        'nie są pokazywane na tym ekranie. PRO klienta wymaga zgody '
        'na każdą sesję; serwisowy PRO wymaga wcześniejszego '
        'upoważnienia zapisanego dla danego komputera.</p>'
        '<h2>1. PRO · tryb serwisowy</h2>'
        '<div class="table-wrap"><table><thead><tr>'
        '<th>ID komputera</th><th>Komputer</th><th>Licencja</th>'
        '<th>Ważna do</th><th>Zgłoszenia</th><th>Naprawy</th><th>Zdjęcia</th><th>Akcje</th>'
        '</tr></thead><tbody>' +
        ("".join(workshop_output) if workshop_output else '<tr><td colspan="8">Brak komputerów PRO w trybie serwisowym.</td></tr>') +
        '</tbody></table></div><h2>2. Zgłoszenia klientów PRO</h2>'
        '<div class="table-wrap"><table><thead><tr>'
        '<th>ID komputera</th><th>Komputer</th><th>Licencja</th>'
        '<th>Ważna do</th><th>Zgłoszenia</th><th>Naprawy</th><th>Zdjęcia</th><th>Akcje</th>'
        '</tr></thead><tbody>' +
        ("".join(output) if output else '<tr><td colspan="8">Brak aktywnych instalacji klientów PRO.</td></tr>') +
        '</tbody></table></div></section>'
    )
    return HTMLResponse(_panel_html(body), headers={"Cache-Control": "private, no-store"})



@router.get("/panel/remote-api/entitlement/{installation_id}")
def panel_remote_entitlement_diagnostic(
    installation_id: uuid.UUID, _: None = Depends(_panel_auth),
):
    """Owner-only mode diagnosis; read backend licence truth, never issue access."""
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    with engine.connect() as db:
        grant = workshop._grant(db, installation_id)
        mode = workshop.remote_entitlement_mode(grant)
        standing = (
            workshop.standing_authorization_record(db, installation_id)
            if mode == "SERVICE_PRO" else None
        )
    # A durable record by itself is NOT an online authorization. The actual
    # share path must independently verify exact MeshCentral live node/group
    # and current, unrevoked scope. Until then never report ready.
    owner_prepared = bool(
        mode == "SERVICE_PRO" and standing
        and standing["owner_approved_at"] is not None
        and standing["revoked_at"] is None
        and standing["approved_mesh_node_id"] == grant.get("mesh_node_id")
    )
    standing_recorded = workshop.standing_authorization_record_valid(grant, standing)
    group_online = False
    if standing_recorded:
        try:
            group_online = (
                meshcentral.verify_standing_service_node(
                    grant["mesh_node_id"], standing["device_scope"]
                ) == grant["mesh_node_id"]
            )
        except meshcentral.MeshCentralError:
            # No configured group, offline or foreign node => deny.
            group_online = False
    return JSONResponse({
        "mode": mode,
        "serviceRemoteEligible": mode == "SERVICE_PRO",
        "customerLicenceRoute": mode == "CUSTOMER_LICENSE",
        # No standing-access share is enabled until independent signed
        # device authorization, owner attestation and dedicated MeshCentral
        # group are wired and checked at connection time.
        "ownerPriorConsentPrepared": owner_prepared,
        "localOptInAttested": bool(
            owner_prepared and standing["local_opt_in_attested_at"] is not None
        ),
        "standingAuthorizationRecorded": standing_recorded,
        "unattendedReady": bool(standing_recorded and group_online),
        "reasonCode": (
            "SERVICE_PRO_STANDING_SESSION_READY"
            if standing_recorded and group_online
            else "CHECK_CUSTOMER_PRO_AND_USE_PER_SESSION_CONSENT"
            if mode == "CUSTOMER_LICENSE"
            else "SERVICE_PRO_AWAITS_LIVE_MESH_GROUP_VERIFICATION"
            if mode == "SERVICE_PRO" and standing_recorded
            else "SERVICE_PRO_AWAITS_LOCAL_CONFIRMATION"
            if mode == "SERVICE_PRO" and owner_prepared
            else "SERVICE_PRO_NEEDS_DEVICE_BOUND_STANDING_AUTHORIZATION"
            if mode == "SERVICE_PRO"
            else "REMOTE_NOT_ELIGIBLE"
        ),
    }, headers={"Cache-Control": "private, no-store"})


@router.post("/panel/remote-api/standing/{installation_id}/prepare")
def panel_owner_prepare_standing_remote_authorization(
    installation_id: uuid.UUID,
    body: OwnerStandingApprovalBody,
    _: None = Depends(_panel_auth),
    __: None = Depends(_owner_panel_csrf),
):
    """Record independent OWNER prior-consent document, never grant access."""
    from app.routers import multiguard_workshop_remote as workshop
    return JSONResponse(
        workshop.prepare_standing_authorization_for_owner(
            installation_id, body.deviceScope, body.priorConsentSha256
        ),
        headers={"Cache-Control": "private, no-store"},
    )


@router.post("/panel/remote-api/standing/{installation_id}/revoke")
def panel_owner_revoke_standing_remote_authorization(
    installation_id: uuid.UUID,
    _: None = Depends(_panel_auth),
    __: None = Depends(_owner_panel_csrf),
):
    """Explicit OWNER revocation; never inferred from a browser checkbox."""
    from app.routers import multiguard_workshop_remote as workshop
    return JSONResponse(
        workshop.revoke_standing_authorization_for_owner(installation_id),
        headers={"Cache-Control": "private, no-store"},
    )


@router.get("/panel/remote-api/workshop/active/{installation_id}")
def panel_workshop_active(installation_id: uuid.UUID, _: None = Depends(_panel_auth)):
    """Resume a workshop session from server state, never from browser storage."""
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    with engine.connect() as db:
        grant = workshop._grant(db, installation_id)
        if not workshop._eligible(grant):
            raise HTTPException(403, "Nieaktywny tryb serwisowy PRO.")
        row = db.execute(text("""
            SELECT * FROM guard.workshop_remote_sessions
            WHERE installation_id=:iid
              AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
            ORDER BY requested_at DESC LIMIT 1
        """), {"iid": installation_id}).mappings().first()
    if not row:
        return {"session": None}
    result = workshop._public(row)
    result["meshLinked"] = workshop.session_node_ready(grant, row)
    return {"session": result}


@router.get("/panel/remote/workshop/{installation_id}")
def owner_workshop_workspace(installation_id: uuid.UUID, _: None = Depends(_panel_auth)):
    """Workshop PRO control room: audited unattended OWNER access, new browser tab."""
    from fastapi.responses import HTMLResponse
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    with engine.connect() as db:
        grant = workshop._grant(db, installation_id)
    if not workshop._eligible(grant):
        raise HTTPException(403, "Wymagany aktywny tryb serwisowy PRO.")
    csrf = _csrf_token(int(time.time() // 3600))
    body = """
    <section class="card" style="max-width:none;min-height:65vh">
      <h1>Zdalny pulpit · PRO / tryb serwisowy</h1>
      <p>Serwisowy PRO może działać bez pytania przy każdej sesji dopiero po zapisanym upoważnieniu do tego konkretnego komputera i potwierdzeniu MeshCentral. Do czasu aktywacji tej procedury dostęp bez zgody pozostaje zablokowany.</p>
      <style>
        .ws-controls{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
        .ws-controls button{border:0;border-radius:9px;padding:13px 18px;color:#fff;font-size:15px;font-weight:500;cursor:pointer;min-height:46px}
        #ws-start{background:#1764b0}
        #ws-connect{background:#16834a}
        #ws-end{background:#be3030}
        #ws-revoke{background:#823a3a}
        #ws-prepare{background:#1764b0}
        .ws-prior-consent{border:1px solid #8592a0;border-radius:10px;padding:15px;margin:16px 0;display:grid;gap:10px}
        .ws-prior-consent label{display:grid;gap:5px}
        .ws-prior-consent input[type=file],.ws-prior-consent select{max-width:100%;padding:9px}
        .ws-prior-consent small{display:block}
        .ws-controls button:disabled{background:#737b87!important;color:#fff;cursor:not-allowed;opacity:.65}
        .ws-controls button:focus-visible{outline:3px solid #72baff;outline-offset:3px}
      </style>
      <div class="ws-prior-consent">
        <h2>Upoważnienie do stałej diagnostyki</h2>
        <p>Najpierw zapisz dokument wcześniejszej zgody osoby uprawnionej do tego komputera. Plik pozostanie na Twoim komputerze: do serwera trafi jedynie SHA-256 dokumentu. Po tej operacji MultiGuard na komputerze klienta musi osobno potwierdzić upoważnienie.</p>
        <label>Rodzaj komputera
          <select id="ws-scope">
            <option value="CLIENT_DIAGNOSTIC">Komputer klienta — wcześniej uzgodniona diagnostyka</option>
            <option value="OWNED_WORKSHOP">Komputer serwisowy Multi-Servis</option>
          </select>
        </label>
        <label>Plik dokumentujący wcześniejsze upoważnienie
          <input type="file" id="ws-proof" accept=".pdf,.txt,.png,.jpg,.jpeg" />
        </label>
        <label><input type="checkbox" id="ws-confirm-proof" /> Potwierdzam, że właściciel lub osoba upoważniona wyraziła świadomą zgodę na dostęp zdalny do wskazanego urządzenia również podczas nieobecności.</label>
        <button type="button" id="ws-prepare">ZAPISZ WCZEŚNIEJSZE UPOWAŻNIENIE</button>
        <small role="status" aria-live="polite" id="ws-approval-status">Upoważnienie wymaga niezależnego potwierdzenia w aplikacji MultiGuard na tym urządzeniu.</small>
      </div>
      <div class="ws-controls">
        <button type="button" id="ws-start">POŁĄCZ BEZ KOLEJNEJ ZGODY</button>
        <button type="button" id="ws-consent" disabled>POŁĄCZ ZA ZGODĄ KLIENTA</button>
        <button type="button" id="ws-connect" disabled>OTWÓRZ PULPIT</button>
        <button type="button" id="ws-end" disabled>ROZŁĄCZ</button>
        <button type="button" id="ws-revoke">COFNIJ STAŁE UPOWAŻNIENIE</button>
      </div>
      <p role="status" aria-live="polite" id="ws-status">Gotowy do połączenia.</p>
    </section>
    <script>
    (() => {
      const installation = """ + json.dumps(str(installation_id)) + """;
      const csrf = """ + json.dumps(csrf) + """;
      const start = document.getElementById('ws-start');
      const consent = document.getElementById('ws-consent');
      const connect = document.getElementById('ws-connect');
      const end = document.getElementById('ws-end');
      const revoke = document.getElementById('ws-revoke');
      const prepare = document.getElementById('ws-prepare');
      const proof = document.getElementById('ws-proof');
      const scope = document.getElementById('ws-scope');
      const proofConfirmed = document.getElementById('ws-confirm-proof');
      const approvalStatus = document.getElementById('ws-approval-status');
      const status = document.getElementById('ws-status');
      let sid = null, timer = null, standingEligible = false;
      let autoOpen = false, opening = false, viewerTab = null;
      start.disabled = true;
      consent.disabled = true;
      async function refreshApproval() {
        const r = await fetch('/multiguard/panel/remote-api/entitlement/' + installation,{
          credentials:'same-origin',cache:'no-store'
        });
        if(!r.ok) throw Error('HTTP '+r.status+': '+(await r.text()).slice(0,150));
        const state = await r.json();
        standingEligible = state.unattendedReady === true
          && state.mode === 'SERVICE_PRO'
          && state.standingAuthorizationRecorded === true;
        if(!sid) { start.disabled = !standingEligible; consent.disabled = false; }
        approvalStatus.textContent = standingEligible
          ? 'Zweryfikowano ważną zgodę i dedykowaną grupę online. Możesz rozpocząć połączenie serwisowe bez kolejnego pytania.'
          : state.localOptInAttested
          ? 'Zgoda potwierdzona lokalnie, ale komputer nie jest jeszcze gotowy w dedykowanej grupie MeshCentral.'
          : state.ownerPriorConsentPrepared
          ? 'Dokument zgody zapisany. Oczekuje na jednorazowe potwierdzenie w aplikacji MultiGuard na wskazanym komputerze.'
          : 'Nie zapisano bieżącego wcześniejszego upoważnienia dla tego komputera.';
      }
      prepare.onclick = async () => {
        if(!proof.files || proof.files.length!==1 || !proofConfirmed.checked) {
          approvalStatus.textContent='Wybierz dokument zgody i osobno potwierdź wcześniejsze upoważnienie.';
          return;
        }
        const file=proof.files[0];
        if(!file.size || file.size>8000000) {
          approvalStatus.textContent='Dokument musi mieć wielkość od 1 bajtu do 8 MB.';
          return;
        }
        prepare.disabled=true;
        try {
          const digest=await crypto.subtle.digest('SHA-256',await file.arrayBuffer());
          const hash=Array.from(new Uint8Array(digest)).map(v=>v.toString(16).padStart(2,'0')).join('');
          const r=await fetch('/multiguard/panel/remote-api/standing/'+installation+'/prepare',{
            method:'POST',credentials:'same-origin',cache:'no-store',
            headers:{'Content-Type':'application/json','X-Owner-CSRF':csrf},
            body:JSON.stringify({deviceScope:scope.value,priorConsentSha256:hash,
              explicitConfirmation:'CONFIRM_PRIOR_WRITTEN_CONSENT'})
          });
          if(!r.ok) throw Error('HTTP '+r.status+': '+(await r.text()).slice(0,220));
          const result=await r.json();
          if(!result.recorded||result.unattendedReady!==false)throw Error('Brak potwierdzenia zapisu dokumentu.');
          proof.value='';proofConfirmed.checked=false;
          await refreshApproval();
        }catch(e){approvalStatus.textContent='Nie udało się zapisać wcześniejszej zgody: '+e.message;}
        finally{prepare.disabled=false;}
      };
      async function recover() {
        consent.disabled = true;
        start.disabled = true;
        connect.disabled = true;
        end.disabled = true;
        status.textContent = 'Sprawdzam, czy istnieje otwarta sesja…';
        try {
          const data = await api('active/' + installation);
          if (data.session) {
            consent.disabled = true;
            sid = data.session.sessionId;
            end.disabled = false;
            timer = setInterval(refresh, 3000);
            await refresh();
          } else {
            sid = null;
            start.disabled = true;
            try {
              await refreshApproval();
              status.textContent = standingEligible
                ? 'Gotowy do połączenia serwisowego.'
                : 'Połączenie oczekuje na weryfikację upoważnienia i grupy MeshCentral.';
            } catch(e) {
              status.textContent = 'Nie udało się sprawdzić upoważnienia: ' + e.message;
              start.disabled = true;
            }
          }
        } catch(e) {
          status.textContent = 'Nie można sprawdzić otwartych sesji: ' + e.message;
          // Never offer a duplicate connection until server confirms no open session.
          start.disabled = true;
        }
      }
      async function api(path, method='GET') {
        const r = await fetch('/multiguard/panel/remote-api/workshop/' + path, {
          method, credentials:'same-origin', cache:'no-store',
          headers: method === 'POST' ? {'X-Owner-CSRF': csrf} : {}
        });
        if (!r.ok) throw Error('HTTP ' + r.status + ': ' + (await r.text()).slice(0,180));
        return r.json();
      }
      async function refresh() {
        if (!sid) return;
        try {
          const info = await api('sessions/' + sid);
          if (['CONSENTED','CONNECT_READY','ACTIVE'].includes(info.status)) {
            consent.disabled = true;
            start.disabled = true;
            const ready = info.meshLinked === true;
            connect.disabled = !ready;
            if (ready && autoOpen && !opening) {
              autoOpen = false;
              await openDesktop();
            }
            status.textContent = ready
              ? 'MeshCentral powiązany — możesz otworzyć pulpit.'
              : 'Oczekiwanie na powiązanie MeshAgenta z tym komputerem. Pulpit jeszcze niedostępny.';
          } else if (['DENIED','ENDED','EXPIRED','ERROR'].includes(info.status)) {
            autoOpen = false;
            if (viewerTab && !viewerTab.closed) viewerTab.close();
            viewerTab = null;
            status.textContent = 'Sesja: ' + info.status;
            connect.disabled = true;
            end.disabled = true;
            start.disabled = !standingEligible;
            consent.disabled = false;
            sid = null;
            clearInterval(timer);
            timer = null;
          } else {
            consent.disabled = true;
            start.disabled = true;
            connect.disabled = true;
            status.textContent = 'Oczekiwanie na decyzję klienta lub przygotowanie sesji…';
          }
        } catch (e) {
          connect.disabled = true;
          status.textContent = 'Utracono potwierdzenie stanu MeshCentral: ' + e.message;
        }
      }
      function prepareViewer() {
        viewerTab = window.open('about:blank','_blank');
        autoOpen = true;
      }
      async function openDesktop() {
        if (!sid || opening) return;
        opening = true;
        const tab = viewerTab && !viewerTab.closed ? viewerTab : null;
        viewerTab = null;
        try {
          connect.disabled = true;
          const reply = await api('sessions/' + sid + '/connect','POST');
          const url = new URL(reply.url);
          if (url.protocol !== 'https:' || url.hostname !== 'mesh.multi-servis.pl') throw Error('Niezaufany adres MeshCentral.');
          if (tab) tab.location.replace(url.href);
          else { status.textContent = 'Przeglądarka zablokowała nową kartę. Kliknij OTWÓRZ PULPIT.'; connect.disabled = false; }
        } catch(e) {
          if (tab) tab.close();
          status.textContent = 'Nie udało się otworzyć pulpitu: ' + e.message;
          connect.disabled = false;
        } finally { opening = false; }
      }
      start.onclick = async () => {
        if (!standingEligible) {
          start.disabled = true;
          status.textContent = 'Wymagane wcześniejsze upoważnienie i potwierdzenie online MeshCentral.';
          return;
        }
        if (!window.confirm('Połączyć się z komputerem na podstawie wcześniej udzielonego upoważnienia serwisowego Pro?')) return;
        prepareViewer();
        start.disabled = true;
        try {
          const reply = await api('request/' + installation, 'POST');
          sid = reply.sessionId;
          end.disabled = false;
          status.textContent = 'Utworzono sesję serwisową. Sprawdzam powiązanie MeshCentral…';
          if (timer) clearInterval(timer);
          timer = setInterval(refresh, 3000);
          await refresh();
        } catch (e) {
          autoOpen=false;
          if(viewerTab && !viewerTab.closed) viewerTab.close(); viewerTab=null;
          start.disabled=true; connect.disabled=true; end.disabled=true;
          status.textContent='Nie udało się rozpocząć sesji: '+e.message;
          try{await refreshApproval();}catch(_){standingEligible=false;start.disabled=true;}
        }
      };
      consent.onclick = async () => {
        if (sid || !window.confirm('Wysłać prośbę o zgodę na jedną sesję?')) return;
        prepareViewer();
        consent.disabled = true;
        start.disabled = true;
        try {
          const reply = await api('request-consent/' + installation, 'POST');
          sid = reply.sessionId;
          end.disabled = false;
          status.textContent = 'Oczekiwanie na zgodę klienta w MultiGuard…';
          if (timer) clearInterval(timer);
          timer = setInterval(refresh, 3000);
          await refresh();
        } catch(e) {
          autoOpen=false;
          if(viewerTab && !viewerTab.closed) viewerTab.close(); viewerTab=null;
          status.textContent = 'Prośba o zgodę nie powiodła się: ' + e.message;
          await recover();
        }
      };
      connect.onclick = async () => { if(!viewerTab) viewerTab=window.open('about:blank','_blank'); await openDesktop(); };
      end.onclick = async () => {
        if (!sid) return;
        end.disabled = true;
        try {
          await api('sessions/' + sid + '/end','POST');
          clearInterval(timer); timer=null; sid=null;
          connect.disabled=true; end.disabled=true; start.disabled=true; consent.disabled=true;
          await refreshApproval();
          status.textContent=standingEligible
            ?'Sesja zakończona. Możesz rozpocząć kolejne połączenie.'
            :'Sesja zakończona. Upoważnienie lub grupa nie są potwierdzone.';
        } catch(e) {end.disabled=false;status.textContent=e.message;}
      };
      revoke.onclick = async () => {
        if (!window.confirm('Cofnąć wcześniejsze upoważnienie do zdalnej diagnostyki tego komputera? Aktywne udostępnienie również zostanie zakończone.')) return;
        revoke.disabled = true;
        try {
          const result = await fetch('/multiguard/panel/remote-api/standing/' + installation + '/revoke', {
            method:'POST', credentials:'same-origin', cache:'no-store',
            headers:{'X-Owner-CSRF':csrf}
          });
          if (!result.ok) throw Error('HTTP ' + result.status + ': ' + (await result.text()).slice(0,220));
          const record = await result.json();
          status.textContent = record.previouslyActive
            ? 'Stałe upoważnienie cofnięte. Poprzednia sesja została zamknięta.'
            : 'Brak aktywnego stałego upoważnienia do cofnięcia.';
          if (timer) clearInterval(timer);
          timer=null; sid=null; connect.disabled=true; end.disabled=true;
          await recover();
          await refreshApproval();
        } catch(e) {
          status.textContent = 'Nie można potwierdzić zamknięcia zdalnego dostępu: ' + e.message;
          connect.disabled = true;
        } finally {
          revoke.disabled = false;
        }
      };
      void refreshApproval().catch(e=>{
        standingEligible=false; start.disabled=true;
        approvalStatus.textContent='Brak potwierdzenia upoważnienia: '+e.message;
      });
      recover();
    })();
    </script>
    """
    return HTMLResponse(_panel_html(body),headers={"Cache-Control":"private, no-store"})


@router.post("/panel/remote-api/workshop/request-consent/{installation_id}")
def panel_workshop_request_consent(installation_id: uuid.UUID,
                                   _: None = Depends(_panel_auth),
                                   __: None = Depends(_owner_panel_csrf)):
    """Explicit per-session customer consent; never unattended or auto-fallback.

    This path remains available when a standing service authorization is
    absent, pending or revoked. Only the authenticated OWNER can invoke it.
    """
    from app.routers import multiguard_workshop_remote as workshop
    return {"sessionId": str(workshop.request_consent_for_owner(installation_id))}


@router.post("/panel/remote-api/workshop/request/{installation_id}")
def panel_workshop_request(installation_id: uuid.UUID,
                           _: None = Depends(_panel_auth),
                           __: None = Depends(_owner_panel_csrf)):
    from app.routers import multiguard_workshop_remote as workshop
    return {"sessionId":str(workshop.request_for_owner(installation_id))}


@router.get("/panel/remote-api/workshop/sessions/{session_id}")
def panel_workshop_status(session_id: uuid.UUID, _: None = Depends(_panel_auth)):
    from app.routers import multiguard_workshop_remote as workshop
    workshop._schema()
    with engine.connect() as db:
        row = db.execute(text("SELECT * FROM guard.workshop_remote_sessions WHERE id=:sid"),
                         {"sid":session_id}).mappings().first()
        if row is None:
            raise HTTPException(404, "Sesja nie istnieje.")
        grant = workshop._grant(db, row["installation_id"])
        if not workshop._eligible(grant):
            raise HTTPException(403, "Nieaktywny tryb serwisowy PRO.")
    result = workshop._public(row)
    result["meshLinked"] = workshop.session_node_ready(grant, row)
    return result


@router.post("/panel/remote-api/workshop/sessions/{session_id}/connect")
def panel_workshop_connect(session_id: uuid.UUID,
                           _: None = Depends(_panel_auth),
                           __: None = Depends(_owner_panel_csrf)):
    from app.routers import multiguard_workshop_remote as workshop
    return workshop.connect_for_owner(session_id)


@router.post("/panel/remote-api/workshop/sessions/{session_id}/end")
def panel_workshop_end(session_id: uuid.UUID,
                       _: None = Depends(_panel_auth),
                       __: None = Depends(_owner_panel_csrf)):
    from app.routers import multiguard_workshop_remote as workshop
    workshop.end_for_owner(session_id)
    return {"ended":True}


@router.get("/panel/remote/session/{request_id}")
def owner_remote_session_workspace(
    request_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    """New-tab owner control room; every session requires fresh client consent."""
    from fastapi.responses import HTMLResponse
    from html import escape

    with engine.connect() as connection:
        row = connection.execute(text("""
            SELECT sr.subject, sr.status, gi.plan_code, gi.lifecycle, gi.valid_until
            FROM guard.support_requests sr
            JOIN guard.installations gi ON gi.id=sr.installation_id
            WHERE sr.id=:request_id AND gi.is_current=TRUE
        """), {"request_id": request_id}).mappings().first()
    if not row:
        raise HTTPException(404, "Nie znaleziono zgłoszenia.")
    if row["plan_code"] != "PRO" or row["lifecycle"] != "ACTIVE" or (
        row["valid_until"] is not None and row["valid_until"] <= datetime.now(timezone.utc)
    ):
        raise HTTPException(403, "Zdalna pomoc wymaga aktywnej licencji PRO.")
    if row["status"] in {"RESOLVED", "CANCELLED"}:
        raise HTTPException(409, "Zgłoszenie zostało zamknięte.")

    subject = escape(str(row["subject"] or "Pomoc zdalna"), quote=True)
    csrf = _csrf_token(int(time.time() // 3600))
    html_body = """
    <section class="card">
      <div class="eyebrow">MULTI-GUARD PRO / ZDALNA POMOC</div>
      <h1>""" + subject + """</h1>
      <p>Klient musi wyrazić zgodę na każdą nową sesję. Samo otwarcie strony
      nie łączy się z komputerem ani nie uruchamia MeshAgenta.</p>
      <button type="button" id="request-connect">WYŚLIJ PROŚBĘ O POŁĄCZENIE</button>
      <button type="button" id="connect-desktop" disabled>OTWÓRZ PULPIT</button>
      <button type="button" id="end-remote" disabled>ROZŁĄCZ</button>
      <p id="remote-status" role="status" aria-live="polite">Oczekiwanie na rozpoczęcie.</p>
    </section>
    <script>
    (() => {
      const supportRequestId = """ + json.dumps(str(request_id)) + """;
      const csrf = """ + json.dumps(csrf) + """;
      const status = document.getElementById('remote-status');
      const start = document.getElementById('request-connect');
      const connect = document.getElementById('connect-desktop');
      const end = document.getElementById('end-remote');
      let sessionId = null;
      let poll = null;
      async function api(url, method='GET', body=null) {
        const response = await fetch(url, {
          method,
          credentials: 'same-origin',
          headers: method === 'POST' ? {'Content-Type':'application/json', 'X-Owner-CSRF':csrf} : {},
          body: body ? JSON.stringify(body) : undefined,
          cache: 'no-store'
        });
        if (!response.ok) {
          const message = await response.text();
          throw Error('HTTP ' + response.status + ': ' + message.slice(0,250));
        }
        return response.json();
      }
      async function refresh() {
        if (!sessionId) return;
        try {
          const session = await api('/multiguard/panel/remote-api/sessions/' + sessionId);
          if (session.status === 'CONSENTED' || session.status === 'CONNECT_READY') {
            status.textContent = 'Klient wyraził zgodę. Możesz otworzyć pulpit.';
            connect.disabled = false;
          } else if (['DENIED','ENDED','EXPIRED','ERROR'].includes(session.status)) {
            status.textContent = 'Sesja zakończona: ' + session.status;
            connect.disabled = true;
            end.disabled = true;
            clearInterval(poll);
          } else if (session.status === 'ACTIVE') {
            status.textContent = 'Sesja aktywna.';
            connect.disabled = false;
          } else {
            status.textContent = 'Oczekiwanie na zgodę klienta...';
          }
        } catch (error) { status.textContent = 'Błąd sprawdzenia: ' + error.message; }
      }
      start.onclick = async () => {
        if (!window.confirm('Wysłać klientowi prośbę o zatwierdzenie połączenia?')) return;
        start.disabled = true;
        try {
          const session = await api('/multiguard/panel/remote-api/sessions', 'POST',
                                    {supportRequestId, requestFiles:false});
          sessionId = session.sessionId;
          end.disabled = false;
          status.textContent = 'Prośba wysłana. Oczekiwanie na zgodę klienta.';
          await refresh();
          poll = setInterval(refresh, 3000);
        } catch (error) {
          status.textContent = 'Nie udało się wysłać prośby: ' + error.message;
          start.disabled = false;
        }
      };
      connect.onclick = async () => {
        if (!sessionId) return;
        // Reserve tab synchronously so browser popup blockers do not discard
        // the session after the asynchronous OWNER authorization step.
        const desktopTab = window.open('about:blank', '_blank');
        if (desktopTab) desktopTab.opener = null;
        connect.disabled = true;
        try {
          const session = await api('/multiguard/panel/remote-api/sessions/' + sessionId + '/connect', 'POST');
          const url = new URL(session.url);
          if (url.protocol !== 'https:') throw Error('Niebezpieczny adres sesji.');
          if (desktopTab) desktopTab.location.replace(url.href);
          else status.textContent = 'Przeglądarka zablokowała nową kartę. Zezwól na wyskakujące okna.';
          if (desktopTab) status.textContent = 'Otworzono zabezpieczony pulpit MeshCentral.';
        } catch (error) {
          if (desktopTab) desktopTab.close();
          status.textContent = 'Połączenie nieudane: ' + error.message;
        } finally { connect.disabled = false; }
      };
      end.onclick = async () => {
        if (!sessionId) return;
        try {
          await api('/multiguard/panel/remote-api/sessions/' + sessionId + '/end', 'POST');
          status.textContent = 'Sesja zakończona.';
          connect.disabled = true; end.disabled = true;
          clearInterval(poll);
        } catch (error) { status.textContent = 'Nie udało się rozłączyć: ' + error.message; }
      };
      window.addEventListener('pagehide', () => clearInterval(poll));
    })();
    </script>
    """
    return HTMLResponse(_panel_html(html_body), headers={
        "Cache-Control": "private, no-store",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "frame-ancestors 'none'",
    })
