from __future__ import annotations

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


class OwnerRemoteCreateBody(BaseModel):
    supportRequestId: uuid.UUID
    requestFiles: bool = False


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
        "expiresAt": _iso(row["expires_at"]),
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


def _expire_and_find_open(connection, installation_id):
    now = datetime.now(timezone.utc)
    connection.execute(
        text(
            """
            UPDATE guard.remote_sessions
            SET status='EXPIRED', ended_at=COALESCE(ended_at,:now)
            WHERE installation_id=:installation_id
              AND (
                (status IN ('REQUESTED','CONSENTED') AND expires_at<:now)
                OR (
                    status IN ('CONNECT_READY','ACTIVE')
                    AND mesh_share_expires_at IS NOT NULL
                    AND mesh_share_expires_at<:now
                )
              )
            """
        ),
        {"installation_id": installation_id, "now": now},
    )
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

        if str(installation["plan_code"]).upper() != "PRO":
            return {
                "requestId": body.requestId,
                "serverTime": now.isoformat(),
                "session": None,
            }

        row = _expire_and_find_open(connection, installation["id"])
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
        if row["expires_at"] < now:
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
            raise HTTPException(410, "Żądanie zdalnej pomocy wygasło.")

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

        if row["status"] not in {"ENDED", "DENIED", "EXPIRED"}:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='ENDED',ended_at=:now,last_activity_at=:now
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

        public_id = row["mesh_public_id"]
        mesh_node_id = row["mesh_node_id"]

    if public_id and mesh_node_id:
        try:
            meshcentral.revoke_share(mesh_node_id, public_id)
        except meshcentral.MeshCentralError as exc:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        UPDATE guard.remote_sessions
                        SET last_error=:error
                        WHERE id=:session_id
                        """
                    ),
                    {"error": str(exc)[:1000], "session_id": body.sessionId},
                )
                _audit(
                    connection,
                    body.sessionId,
                    "MESH_REVOKE_FAILED",
                    "MESH",
                    "MeshCentral",
                    {"error": str(exc)[:500]},
                )
            raise HTTPException(
                502,
                "Sesja została zakończona, ale nie potwierdzono "
                f"unieważnienia linku MeshCentral: {exc}",
            ) from exc

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
                    gi.plan_code,gi.lifecycle,gi.mesh_node_id
                FROM guard.support_requests sr
                JOIN guard.installations gi ON gi.id=sr.installation_id
                WHERE sr.id=:support_request_id
                """
            ),
            {"support_request_id": body.supportRequestId},
        ).mappings().first()

        if not support:
            raise HTTPException(404, "Nie znaleziono zgłoszenia Multi-Guard.")
        if str(support["plan_code"]).upper() != "PRO":
            raise HTTPException(403, "Zdalna pomoc wymaga Multi-Guard Pro.")
        if not support["mesh_node_id"]:
            raise HTTPException(
                409,
                "Urządzenie nie ma jeszcze powiązanego węzła zdalnej pomocy.",
            )

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
                SELECT rs.*,gi.mesh_node_id,sr.subject
                FROM guard.remote_sessions rs
                JOIN guard.installations gi ON gi.id=rs.installation_id
                JOIN guard.support_requests sr ON sr.id=rs.support_request_id
                WHERE rs.id=:session_id
                FOR UPDATE
                """
            ),
            {"session_id": session_uuid},
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono sesji.")
        if row["status"] not in {"CONSENTED", "CONNECT_READY", "ACTIVE"}:
            raise HTTPException(
                409,
                "Klient nie wyraził zgody na tę sesję.",
            )
        if row["status"] == "CONSENTED" and row["expires_at"] < now:
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
                connection,
                session_uuid,
                "CONSENT_EXPIRED",
                "BACKEND",
                "Multi-Servis",
            )
            raise HTTPException(
                410,
                "Zgoda klienta na rozpoczęcie sesji wygasła.",
            )

        if not row["mesh_node_id"]:
            raise HTTPException(409, "Brak powiązania MeshCentral dla urządzenia.")

        granted = list(row["granted_capabilities"] or [])
        if "desktop" not in granted:
            raise HTTPException(409, "Brak zgody na pulpit zdalny.")

        node_id = row["mesh_node_id"]
        existing_public_id = row["mesh_public_id"]

    if existing_public_id:
        try:
            meshcentral.revoke_share(node_id, existing_public_id)
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(
                502,
                f"Nie udało się bezpiecznie obrócić poprzedniego linku: {exc}",
            ) from exc

    try:
        share = meshcentral.create_share(
            node_id,
            f"Multi-Servis {str(session_uuid)[:8]}",
            granted,
            60,
        )
    except meshcentral.MeshCentralError as exc:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE guard.remote_sessions
                    SET status='ERROR',last_error=:error,last_activity_at=:now
                    WHERE id=:session_id
                    """
                ),
                {
                    "error": str(exc)[:1000],
                    "now": now,
                    "session_id": session_uuid,
                },
            )
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
                    "expires_at": now + timedelta(minutes=60),
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
        "expiresAt": (now + timedelta(minutes=60)).isoformat(),
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

        connection.execute(
            text(
                """
                UPDATE guard.remote_sessions
                SET
                    status='ENDED',
                    ended_at=COALESCE(ended_at,:now),
                    last_activity_at=:now
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

        public_id = row["mesh_public_id"]
        node_id = row["mesh_node_id"]

    if public_id and node_id:
        try:
            meshcentral.revoke_share(node_id, public_id)
        except meshcentral.MeshCentralError as exc:
            raise HTTPException(
                502,
                "Sesja została zakończona, ale nie potwierdzono "
                f"unieważnienia linku MeshCentral: {exc}",
            ) from exc

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
        changed = connection.execute(
            text(
                """
                UPDATE guard.installations
                SET mesh_node_id=:node_id,updated_at=now()
                WHERE installation_external_id=:installation_id
                  AND is_current=TRUE
                """
            ),
            {
                "node_id": node_id,
                "installation_id": body.installationId,
            },
        ).rowcount

    if not changed:
        raise HTTPException(
            404,
            "Nie znaleziono bieżącej instalacji Multi-Guard.",
        )
    return {"status": "ok", "meshNodeId": node_id}
