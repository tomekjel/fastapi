from __future__ import annotations

import hashlib
import hmac
import html as html_lib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner
from app.routers.multiguard_license import (
    _ensure_schema as _ensure_license_schema,
    _panel_auth,
    _panel_html,
)


router = APIRouter(prefix="/multiguard", tags=["multi-guard-runtime"])

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False


class DefenderCompact(BaseModel):
    available: bool
    realtimeProtection: Optional[bool] = None
    activeThreatCount: Optional[int] = None
    firewallProtected: Optional[bool] = None
    signatureAgeDays: Optional[int] = None


class BrowserCompact(BaseModel):
    installedCount: int = 0
    activeCount: int = 0
    needsAttentionCount: int = 0


class HardwareCompact(BaseModel):
    whea24h: Optional[int] = None
    kernelPower7d: Optional[int] = None
    diskProblemCount: int = 0
    batteryHealthPercent: Optional[float] = None


class HeartbeatBody(BaseModel):
    requestId: str
    nonce: str
    sentAt: datetime
    installationId: uuid.UUID
    deviceId: str = Field(min_length=16, max_length=128)
    serviceDeviceId: Optional[uuid.UUID] = None
    installationCredential: str = Field(min_length=32, max_length=512)
    appVersion: str
    planCode: str
    licenseId: Optional[str] = None
    lifecycle: str
    acceptedAt: Optional[datetime] = None
    validUntil: Optional[datetime] = None
    healthLevel: str
    defender: DefenderCompact
    browserShield: BrowserCompact
    hardware: HardwareCompact


class EventBody(BaseModel):
    requestId: str
    nonce: str
    sentAt: datetime
    eventId: uuid.UUID
    eventType: str = Field(min_length=1, max_length=120)
    severity: str = "INFO"
    installationId: uuid.UUID
    deviceId: str
    serviceDeviceId: Optional[uuid.UUID] = None
    installationCredential: str = Field(min_length=32, max_length=512)
    payload: dict[str, Any] = Field(default_factory=dict)


def _credential_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _severity(value: str) -> str:
    normalized = value.upper().strip()
    return normalized if normalized in {"INFO", "WARNING", "IMPORTANT", "CRITICAL"} else "INFO"


def _ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return

    _ensure_license_schema()

    statements = [
        """
        CREATE SCHEMA IF NOT EXISTS guard
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.device_state (
            installation_id UUID PRIMARY KEY REFERENCES guard.installations(id) ON DELETE CASCADE,
            captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            defender_available BOOLEAN,
            defender_realtime BOOLEAN,
            active_threat_count INTEGER,
            firewall_protected BOOLEAN,
            signature_age_days INTEGER,
            browser_installed_count INTEGER,
            browser_active_count INTEGER,
            browser_needs_attention_count INTEGER,
            whea_24h INTEGER,
            kernel_power_7d INTEGER,
            disk_problem_count INTEGER,
            battery_health_percent NUMERIC(6,2),
            raw_compact JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            event_id UUID NOT NULL UNIQUE,
            installation_id UUID NOT NULL REFERENCES guard.installations(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'INFO',
            occurred_at TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            payload JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_events_installation_time
        ON guard.events(installation_id, occurred_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            service_device_id UUID NOT NULL REFERENCES core.devices(id) ON DELETE CASCADE,
            installation_id UUID REFERENCES guard.installations(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'INFO',
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            dedup_key TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            seen_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_guard_notification_dedup_open
        ON guard.notifications(dedup_key)
        WHERE dedup_key IS NOT NULL AND resolved_at IS NULL
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_notifications_open
        ON guard.notifications(seen_at, resolved_at, created_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.support_requests (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            local_request_id UUID NOT NULL UNIQUE,
            source_event_id UUID UNIQUE,
            installation_id UUID NOT NULL REFERENCES guard.installations(id) ON DELETE CASCADE,
            service_device_id UUID NOT NULL REFERENCES core.devices(id) ON DELETE CASCADE,
            priority TEXT NOT NULL DEFAULT 'NORMAL',
            subject TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NEW',
            diagnostics_included BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            seen_at TIMESTAMPTZ,
            started_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,
            resolution_note TEXT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_support_requests_device
        ON guard.support_requests(service_device_id, created_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_support_requests_open
        ON guard.support_requests(status, created_at DESC)
        WHERE status NOT IN ('RESOLVED','CANCELLED')
        """,
        """
        CREATE TABLE IF NOT EXISTS guard.diagnostic_packages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            support_request_id UUID NOT NULL REFERENCES guard.support_requests(id) ON DELETE CASCADE,
            schema_version INTEGER NOT NULL DEFAULT 1,
            captured_at TIMESTAMPTZ NOT NULL,
            payload JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_guard_diag_support
        ON guard.diagnostic_packages(support_request_id, created_at DESC)
        """,
    ]

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.support_requests
                    DROP CONSTRAINT IF EXISTS support_requests_priority_check
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE guard.support_requests
                    SET priority='NORMAL'
                    WHERE priority IN ('STANDARD','')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    UPDATE guard.support_requests
                    SET priority='PRIORITY'
                    WHERE priority='PRO'
                    """
                )
            )
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.support_requests
                    ALTER COLUMN priority SET DEFAULT 'NORMAL'
                    """
                )
            )
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.support_requests
                    ADD CONSTRAINT support_requests_priority_check
                    CHECK (priority IN ('NORMAL','PRIORITY'))
                    """
                )
            )
        _SCHEMA_READY = True


def _load_installation(connection, installation_external_id: uuid.UUID):
    _ensure_schema()
    return connection.execute(
        text(
            """
            SELECT
                id,
                service_device_id,
                device_id_hash,
                credential_sha256,
                plan_code,
                lifecycle,
                release_channel
            FROM guard.installations
            WHERE installation_external_id=:installation_id
              AND is_current=TRUE
            LIMIT 1
            """
        ),
        {"installation_id": installation_external_id},
    ).mappings().first()


def _require_agent(
    connection,
    installation_external_id: uuid.UUID,
    device_id: str,
    credential: str,
):
    row = _load_installation(connection, installation_external_id)
    if not row:
        raise HTTPException(401, "Instalacja Multi-Guard nie jest zarejestrowana w Multi-Servis.")
    if not hmac.compare_digest(str(row["device_id_hash"]), device_id):
        raise HTTPException(401, "Identyfikator urządzenia nie pasuje do instalacji.")
    if not hmac.compare_digest(str(row["credential_sha256"]), _credential_hash(credential)):
        raise HTTPException(401, "Nieprawidłowe poświadczenie instalacji.")
    return row


@router.post("/agent/heartbeat")
def heartbeat(body: HeartbeatBody):
    _ensure_schema()
    now = datetime.now(timezone.utc)
    plan = "PRO" if body.planCode.upper() == "PRO" else "STANDARD"
    health = body.healthLevel.upper()
    if health not in {"GREEN", "YELLOW", "ORANGE", "RED"}:
        health = "GREEN"

    with engine.begin() as connection:
        row = _require_agent(
            connection,
            body.installationId,
            body.deviceId,
            body.installationCredential,
        )
        if body.serviceDeviceId and body.serviceDeviceId != row["service_device_id"]:
            raise HTTPException(409, "service_device_id nie pasuje do powiązania instalacji.")

        previous_lifecycle = row["lifecycle"]

        connection.execute(
            text(
                """
                UPDATE guard.installations
                SET
                    app_version=:app_version,
                    plan_code=:plan_code,
                    license_id=COALESCE(:license_id, license_id),
                    lifecycle=:lifecycle,
                    accepted_at=COALESCE(:accepted_at, accepted_at),
                    valid_until=:valid_until,
                    health_level=:health_level,
                    last_seen_at=:now,
                    updated_at=:now
                WHERE id=:id
                """
            ),
            {
                "app_version": body.appVersion,
                "plan_code": plan,
                "license_id": body.licenseId,
                "lifecycle": body.lifecycle,
                "accepted_at": body.acceptedAt,
                "valid_until": body.validUntil,
                "health_level": health,
                "now": now,
                "id": row["id"],
            },
        )

        connection.execute(
            text(
                """
                UPDATE core.devices
                SET last_seen=:now, is_online=TRUE, updated_at=:now
                WHERE id=:device_id
                """
            ),
            {"now": now, "device_id": row["service_device_id"]},
        )

        raw_compact = body.model_dump(
            exclude={"installationCredential"}
        )
        connection.execute(
            text(
                """
                INSERT INTO guard.device_state (
                    installation_id,captured_at,defender_available,defender_realtime,
                    active_threat_count,firewall_protected,signature_age_days,
                    browser_installed_count,browser_active_count,browser_needs_attention_count,
                    whea_24h,kernel_power_7d,disk_problem_count,battery_health_percent,raw_compact
                )
                VALUES (
                    :id,:now,:defender_available,:defender_realtime,
                    :active_threat_count,:firewall_protected,:signature_age_days,
                    :browser_installed_count,:browser_active_count,:browser_needs_attention_count,
                    :whea_24h,:kernel_power_7d,:disk_problem_count,:battery_health_percent,
                    CAST(:raw_compact AS jsonb)
                )
                ON CONFLICT(installation_id) DO UPDATE SET
                    captured_at=EXCLUDED.captured_at,
                    defender_available=EXCLUDED.defender_available,
                    defender_realtime=EXCLUDED.defender_realtime,
                    active_threat_count=EXCLUDED.active_threat_count,
                    firewall_protected=EXCLUDED.firewall_protected,
                    signature_age_days=EXCLUDED.signature_age_days,
                    browser_installed_count=EXCLUDED.browser_installed_count,
                    browser_active_count=EXCLUDED.browser_active_count,
                    browser_needs_attention_count=EXCLUDED.browser_needs_attention_count,
                    whea_24h=EXCLUDED.whea_24h,
                    kernel_power_7d=EXCLUDED.kernel_power_7d,
                    disk_problem_count=EXCLUDED.disk_problem_count,
                    battery_health_percent=EXCLUDED.battery_health_percent,
                    raw_compact=EXCLUDED.raw_compact
                """
            ),
            {
                "id": row["id"],
                "now": now,
                "defender_available": body.defender.available,
                "defender_realtime": body.defender.realtimeProtection,
                "active_threat_count": body.defender.activeThreatCount,
                "firewall_protected": body.defender.firewallProtected,
                "signature_age_days": body.defender.signatureAgeDays,
                "browser_installed_count": body.browserShield.installedCount,
                "browser_active_count": body.browserShield.activeCount,
                "browser_needs_attention_count": body.browserShield.needsAttentionCount,
                "whea_24h": body.hardware.whea24h,
                "kernel_power_7d": body.hardware.kernelPower7d,
                "disk_problem_count": body.hardware.diskProblemCount,
                "battery_health_percent": body.hardware.batteryHealthPercent,
                "raw_compact": _json(raw_compact),
            },
        )

        if previous_lifecycle != "ACTIVE" and body.lifecycle == "ACTIVE":
            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,'LICENSE_ACTIVATED','INFO',
                        'Multi-Guard aktywowany',
                        'Licencja Multi-Guard została aktywowana na urządzeniu.',
                        :dedup_key,
                        CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "dedup_key": f"activation:{row['id']}:{body.validUntil}",
                    "payload": _json({"source": "heartbeat"}),
                },
            )

    return {
        "requestId": body.requestId,
        "accepted": True,
        "serverTime": now.isoformat(),
        "serviceDeviceId": str(row["service_device_id"]),
    }


@router.post("/agent/event")
def agent_event(body: EventBody):
    _ensure_schema()
    now = datetime.now(timezone.utc)
    severity = _severity(body.severity)

    with engine.begin() as connection:
        row = _require_agent(
            connection,
            body.installationId,
            body.deviceId,
            body.installationCredential,
        )

        if body.serviceDeviceId and body.serviceDeviceId != row["service_device_id"]:
            raise HTTPException(409, "service_device_id nie pasuje do powiązania instalacji.")

        existing = connection.execute(
            text("SELECT 1 FROM guard.events WHERE event_id=:event_id"),
            {"event_id": body.eventId},
        ).first()
        if existing:
            return {
                "requestId": body.requestId,
                "accepted": True,
                "duplicate": True,
                "serverTime": now.isoformat(),
            }

        connection.execute(
            text(
                """
                INSERT INTO guard.events(
                    event_id,installation_id,event_type,severity,occurred_at,payload
                )
                VALUES(
                    :event_id,:installation_id,:event_type,:severity,:occurred_at,
                    CAST(:payload AS jsonb)
                )
                """
            ),
            {
                "event_id": body.eventId,
                "installation_id": row["id"],
                "event_type": body.eventType,
                "severity": severity,
                "occurred_at": body.sentAt,
                "payload": _json(body.payload),
            },
        )

        payload = body.payload or {}

        if body.eventType == "CLIENT_ALERT_REPORT":
            alert_title = str(payload.get("title") or "Zgłoszenie alertu Multi-Guard").strip()[:180]
            alert_detail = str(payload.get("detail") or "").strip()[:600]
            message = alert_title if not alert_detail else f"{alert_title} — {alert_detail}"
            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,'CLIENT_ALERT_REPORT',:severity,
                        'Klient przesłał alert Multi-Guard',:message,:dedup_key,
                        CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "severity": severity,
                    "message": message,
                    "dedup_key": f"client-alert:{body.eventId}",
                    "payload": _json(
                        {
                            "eventId": str(body.eventId),
                            "title": alert_title,
                            "detail": alert_detail,
                        }
                    ),
                },
            )

        if body.eventType == "CLIENT_SCREENSHOT":
            screenshot_id = str(payload.get("screenshotId") or "").strip()[:120]
            comment = str(payload.get("comment") or "").strip()[:500]
            related_issue_id = str(payload.get("relatedIssueId") or "").strip()[:120]
            message = comment or "Klient przesłał zrzut ekranu."
            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,'CLIENT_SCREENSHOT','INFO',
                        'Klient przesłał zrzut ekranu',:message,:dedup_key,
                        CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "message": message,
                    "dedup_key": f"client-screenshot:{body.eventId}",
                    "payload": _json(
                        {
                            "eventId": str(body.eventId),
                            "screenshotId": screenshot_id,
                            "relatedIssueId": related_issue_id or None,
                            "width": payload.get("width"),
                            "height": payload.get("height"),
                            "byteSize": payload.get("byteSize"),
                        }
                    ),
                },
            )

        if body.eventType in {"CLIENT_LOG_BUNDLE", "CLIENT_DIAGNOSTIC_REPORT"}:
            report_title = str(
                payload.get("title")
                or (
                    "Pakiet logów Multi-Guard"
                    if body.eventType == "CLIENT_LOG_BUNDLE"
                    else "Raport diagnostyczny Multi-Guard"
                )
            ).strip()[:180]
            report_note = str(payload.get("note") or payload.get("summary") or "").strip()[:600]
            message = report_title if not report_note else f"{report_title} — {report_note}"
            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,:kind,:severity,
                        :title,:message,:dedup_key,CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "kind": body.eventType,
                    "severity": severity,
                    "title": (
                        "Klient przesłał pakiet logów Multi-Guard"
                        if body.eventType == "CLIENT_LOG_BUNDLE"
                        else "Klient przesłał raport diagnostyczny Multi-Guard"
                    ),
                    "message": message,
                    "dedup_key": f"client-report:{body.eventId}",
                    "payload": _json({"eventId": str(body.eventId)}),
                },
            )

        if body.eventType in {"SUPPORT_REQUEST", "PRO_SUPPORT_REQUEST"}:
            priority = "PRIORITY" if str(row["plan_code"]).upper() == "PRO" else "NORMAL"
            try:
                local_request_id = uuid.UUID(str(payload.get("localRequestId")))
            except (ValueError, TypeError) as exc:
                raise HTTPException(400, "Nieprawidłowe localRequestId zgłoszenia.") from exc

            subject = str(payload.get("subject") or "").strip()[:120]
            description = str(payload.get("description") or "").strip()[:4000]
            if len(subject) < 3 or len(description) < 10:
                raise HTTPException(400, "Zgłoszenie ma nieprawidłową treść.")

            created_at = body.sentAt
            try:
                if payload.get("createdAt"):
                    created_at = datetime.fromisoformat(
                        str(payload["createdAt"]).replace("Z", "+00:00")
                    )
            except ValueError:
                created_at = body.sentAt

            diagnostics = (
                payload.get("diagnostics")
                if payload.get("diagnosticsIncluded")
                else None
            )

            support_row = connection.execute(
                text(
                    """
                    INSERT INTO guard.support_requests(
                        local_request_id,source_event_id,installation_id,
                        service_device_id,priority,subject,description,
                        diagnostics_included,created_at
                    )
                    VALUES(
                        :local_request_id,:source_event_id,:installation_id,
                        :service_device_id,:priority,:subject,:description,
                        :diagnostics_included,:created_at
                    )
                    ON CONFLICT(local_request_id) DO UPDATE SET
                        source_event_id=COALESCE(
                            guard.support_requests.source_event_id,
                            EXCLUDED.source_event_id
                        )
                    RETURNING id
                    """
                ),
                {
                    "local_request_id": local_request_id,
                    "source_event_id": body.eventId,
                    "installation_id": row["id"],
                    "service_device_id": row["service_device_id"],
                    "priority": priority,
                    "subject": subject,
                    "description": description,
                    "diagnostics_included": bool(diagnostics),
                    "created_at": created_at,
                },
            ).mappings().first()

            if diagnostics and support_row:
                connection.execute(
                    text(
                        """
                        INSERT INTO guard.diagnostic_packages(
                            support_request_id,schema_version,captured_at,payload,expires_at
                        )
                        SELECT
                            :support_request_id,:schema_version,:captured_at,
                            CAST(:payload AS jsonb),now()+interval '30 days'
                        WHERE NOT EXISTS (
                            SELECT 1 FROM guard.diagnostic_packages
                            WHERE support_request_id=:support_request_id
                        )
                        """
                    ),
                    {
                        "support_request_id": support_row["id"],
                        "schema_version": (
                            int(diagnostics.get("schemaVersion", 1))
                            if isinstance(diagnostics, dict)
                            else 1
                        ),
                        "captured_at": created_at,
                        "payload": _json(diagnostics),
                    },
                )

            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,'SUPPORT_REQUEST','INFO',
                        :title,:message,:dedup_key,CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "title": (
                        "Nowe zgłoszenie Multi-Guard Pro"
                        if priority == "PRIORITY"
                        else "Nowe zgłoszenie Multi-Guard Standard"
                    ),
                    "message": subject,
                    "dedup_key": f"support:{local_request_id}",
                    "payload": _json(
                        {
                            "supportRequestId": (
                                str(support_row["id"]) if support_row else None
                            ),
                            "priority": priority,
                        }
                    ),
                },
            )

        if severity == "CRITICAL" and str(row["plan_code"]).upper() == "PRO":
            connection.execute(
                text(
                    """
                    INSERT INTO guard.notifications(
                        service_device_id,installation_id,kind,severity,
                        title,message,dedup_key,payload
                    )
                    VALUES(
                        :device_id,:installation_id,'PRO_CRITICAL','CRITICAL',
                        'Krytyczne zdarzenie Multi-Guard Pro',:message,:dedup_key,
                        CAST(:payload AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "device_id": row["service_device_id"],
                    "installation_id": row["id"],
                    "message": body.eventType,
                    "dedup_key": f"pro-critical:{body.eventId}",
                    "payload": _json({"eventId": str(body.eventId)}),
                },
            )

    return {
        "requestId": body.requestId,
        "accepted": True,
        "duplicate": False,
        "serverTime": now.isoformat(),
    }


@router.get("/overview")
def overview(user: CurrentUser = Depends(require_owner)):
    _ensure_schema()
    with engine.connect() as connection:
        counts = connection.execute(
            text(
                """
                SELECT
                    count(*) FILTER (WHERE lifecycle='ACTIVE') active,
                    count(*) FILTER (WHERE lifecycle='ACTIVE' AND plan_code='STANDARD') standard,
                    count(*) FILTER (WHERE lifecycle='ACTIVE' AND plan_code='PRO') pro,
                    count(*) FILTER (WHERE health_level IN ('ORANGE','RED')) needs_attention,
                    count(*) FILTER (WHERE health_level='RED') critical,
                    count(*) FILTER (WHERE last_seen_at < now()-interval '30 days') no_contact_30d,
                    count(*) FILTER (
                        WHERE lifecycle='ACTIVE'
                          AND valid_until BETWEEN now() AND now()+interval '30 days'
                    ) expiring_30d
                FROM guard.installations
                WHERE is_current=TRUE
                """
            )
        ).mappings().one()

        unread = connection.execute(
            text(
                """
                SELECT count(*)
                FROM guard.notifications
                WHERE resolved_at IS NULL AND seen_at IS NULL
                """
            )
        ).scalar_one()

        open_support = connection.execute(
            text(
                """
                SELECT count(*)
                FROM guard.support_requests
                WHERE status NOT IN ('RESOLVED','CANCELLED')
                """
            )
        ).scalar_one()

    return {
        "counts": dict(counts),
        "unreadNotifications": int(unread or 0),
        "openSupportRequests": int(open_support or 0),
    }



def _short_installation_id(value: Any) -> str:
    raw = str(value or "").replace("-", "").upper()
    return "MG-" + (raw[:8] if raw else "--------")


def _panel_h(value: Any) -> str:
    if value is None:
        return ""
    return html_lib.escape(str(value))


def _panel_dt(value: Any) -> str:
    if not value:
        return "—"
    try:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return _panel_h(value)


def _device_label(row: Any) -> str:
    parts = [
        str(row.get("manufacturer") or "").strip(),
        str(row.get("model") or "").strip(),
    ]
    label = " ".join(part for part in parts if part).strip()
    if not label:
        label = str(row.get("hostname") or row.get("device_type") or "Komputer")
    return label


def _fetch_device_rows(limit: int = 250):
    _ensure_schema()
    limit = min(max(int(limit), 1), 500)
    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                SELECT
                    gi.id AS installation_id,
                    gi.installation_external_id,
                    gi.service_device_id,
                    gi.plan_code,
                    gi.lifecycle,
                    gi.valid_until,
                    gi.last_seen_at,
                    gi.health_level,
                    gi.app_version,
                    gi.release_channel,
                    d.device_type,
                    d.manufacturer,
                    d.model,
                    d.serial_number,
                    d.hostname,
                    ll.reception_id,
                    ll.reception_number,
                    COALESCE(ev.warning_30d,0) AS warning_30d,
                    COALESCE(ev.important_30d,0) AS important_30d,
                    COALESCE(ev.critical_30d,0) AS critical_30d,
                    COALESCE(ev.error_30d,0) AS error_30d,
                    COALESCE(sr.open_support,0) AS open_support,
                    COALESCE(nn.unread_notifications,0) AS unread_notifications
                FROM guard.installations gi
                LEFT JOIN core.devices d
                    ON d.id=gi.service_device_id
                LEFT JOIN guard.license_links ll
                    ON ll.installation_id=gi.installation_external_id
                LEFT JOIN LATERAL (
                    SELECT
                        count(*) FILTER (
                            WHERE e.occurred_at >= now()-interval '30 days'
                              AND e.severity='WARNING'
                        ) AS warning_30d,
                        count(*) FILTER (
                            WHERE e.occurred_at >= now()-interval '30 days'
                              AND e.severity='IMPORTANT'
                        ) AS important_30d,
                        count(*) FILTER (
                            WHERE e.occurred_at >= now()-interval '30 days'
                              AND e.severity='CRITICAL'
                        ) AS critical_30d,
                        count(*) FILTER (
                            WHERE e.occurred_at >= now()-interval '30 days'
                              AND (
                                  e.event_type LIKE 'TELEMETRY_%'
                                  OR e.event_type IN (
                                      'APP_ERROR',
                                      'MODULE_ERROR',
                                      'SENSOR_ERROR',
                                      'UNKNOWN_ANOMALY',
                                      'PROVIDER_FAILURE',
                                      'READ_FAILURE'
                                  )
                              )
                        ) AS error_30d
                    FROM guard.events e
                    WHERE e.installation_id=gi.id
                ) ev ON TRUE
                LEFT JOIN LATERAL (
                    SELECT count(*) AS open_support
                    FROM guard.support_requests s
                    WHERE s.installation_id=gi.id
                      AND s.status NOT IN ('RESOLVED','CANCELLED')
                ) sr ON TRUE
                LEFT JOIN LATERAL (
                    SELECT count(*) AS unread_notifications
                    FROM guard.notifications n
                    WHERE n.installation_id=gi.id
                      AND n.resolved_at IS NULL
                      AND n.seen_at IS NULL
                ) nn ON TRUE
                WHERE gi.is_current=TRUE
                ORDER BY
                    CASE gi.health_level
                        WHEN 'RED' THEN 0
                        WHEN 'ORANGE' THEN 1
                        WHEN 'YELLOW' THEN 2
                        ELSE 3
                    END,
                    COALESCE(ev.critical_30d,0) DESC,
                    COALESCE(ev.important_30d,0) DESC,
                    COALESCE(ev.warning_30d,0) DESC,
                    gi.last_seen_at DESC NULLS LAST
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()


def _fetch_telemetry_rows(days: int = 90, limit: int = 200):
    _ensure_schema()
    days = min(max(int(days), 1), 3650)
    limit = min(max(int(limit), 1), 500)
    with engine.connect() as connection:
        return connection.execute(
            text(
                """
                WITH telemetry AS (
                    SELECT
                        e.installation_id,
                        e.event_type,
                        e.severity,
                        e.occurred_at,
                        e.payload,
                        COALESCE(
                            NULLIF(e.payload->>'fingerprint',''),
                            e.event_type || ':' ||
                            COALESCE(NULLIF(e.payload->>'component',''),'unknown') || ':' ||
                            COALESCE(NULLIF(e.payload->>'code',''),'unknown')
                        ) AS fingerprint,
                        COALESCE(
                            NULLIF(e.payload->>'appVersion',''),
                            NULLIF(gi.app_version,''),
                            'unknown'
                        ) AS app_version
                    FROM guard.events e
                    JOIN guard.installations gi
                      ON gi.id=e.installation_id
                    WHERE e.occurred_at >= now() - (:days * interval '1 day')
                      AND (
                          e.event_type LIKE 'TELEMETRY_%'
                          OR e.event_type IN (
                              'APP_ERROR',
                              'MODULE_ERROR',
                              'SENSOR_ERROR',
                              'UNKNOWN_ANOMALY',
                              'PROVIDER_FAILURE',
                              'READ_FAILURE'
                          )
                      )
                )
                SELECT
                    fingerprint,
                    max(event_type) AS event_type,
                    max(COALESCE(payload->>'component','')) AS component,
                    max(COALESCE(payload->>'code','')) AS code,
                    count(*) AS occurrences,
                    count(DISTINCT installation_id) AS affected_devices,
                    min(occurred_at) AS first_seen,
                    max(occurred_at) AS last_seen,
                    array_agg(DISTINCT app_version ORDER BY app_version) AS app_versions,
                    count(*) FILTER (WHERE severity='CRITICAL') AS critical_count,
                    count(*) FILTER (WHERE severity='IMPORTANT') AS important_count,
                    count(*) FILTER (WHERE severity='WARNING') AS warning_count
                FROM telemetry
                GROUP BY fingerprint
                ORDER BY
                    critical_count DESC,
                    affected_devices DESC,
                    occurrences DESC,
                    last_seen DESC
                LIMIT :limit
                """
            ),
            {"days": days, "limit": limit},
        ).mappings().all()


@router.get("/devices")
def multi_guard_devices(
    limit: int = 250,
    user: CurrentUser = Depends(require_owner),
):
    rows = _fetch_device_rows(limit)
    return [
        {
            **dict(row),
            "installation_id": str(row["installation_id"]),
            "installation_external_id": str(row["installation_external_id"]),
            "service_device_id": str(row["service_device_id"]),
            "short_id": _short_installation_id(row["installation_external_id"]),
            "reception_id": (
                str(row["reception_id"]) if row["reception_id"] else None
            ),
        }
        for row in rows
    ]


@router.get("/devices/{installation_id}/events")
def multi_guard_device_events(
    installation_id: str,
    limit: int = 200,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID instalacji.") from exc

    limit = min(max(int(limit), 1), 500)
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    event_id,event_type,severity,occurred_at,received_at,payload
                FROM guard.events
                WHERE installation_id=:installation_id
                ORDER BY occurred_at DESC
                LIMIT :limit
                """
            ),
            {"installation_id": iid, "limit": limit},
        ).mappings().all()

    return [
        {
            **dict(row),
            "event_id": str(row["event_id"]),
        }
        for row in rows
    ]


@router.get("/telemetry")
def multi_guard_telemetry(
    days: int = 90,
    limit: int = 200,
    user: CurrentUser = Depends(require_owner),
):
    rows = _fetch_telemetry_rows(days, limit)
    return [dict(row) for row in rows]


@router.get("/panel/dashboard", response_class=HTMLResponse)
def multi_guard_panel_dashboard(
    _: None = Depends(_panel_auth),
):
    _ensure_schema()
    with engine.connect() as connection:
        counts = connection.execute(
            text(
                """
                SELECT
                    count(*) FILTER (WHERE lifecycle='ACTIVE') active,
                    count(*) FILTER (
                        WHERE lifecycle='ACTIVE' AND plan_code='STANDARD'
                    ) standard,
                    count(*) FILTER (
                        WHERE lifecycle='ACTIVE' AND plan_code='PRO'
                    ) pro,
                    count(*) FILTER (
                        WHERE health_level IN ('ORANGE','RED')
                    ) needs_attention,
                    count(*) FILTER (WHERE health_level='RED') critical,
                    count(*) FILTER (
                        WHERE lifecycle='ACTIVE'
                          AND valid_until BETWEEN now() AND now()+interval '30 days'
                    ) expiring_30d,
                    count(*) FILTER (
                        WHERE last_seen_at < now()-interval '30 days'
                    ) no_contact_30d
                FROM guard.installations
                WHERE is_current=TRUE
                """
            )
        ).mappings().one()

        unread = connection.execute(
            text(
                """
                SELECT count(*)
                FROM guard.notifications
                WHERE resolved_at IS NULL AND seen_at IS NULL
                """
            )
        ).scalar_one()

        open_support = connection.execute(
            text(
                """
                SELECT count(*)
                FROM guard.support_requests
                WHERE status NOT IN ('RESOLVED','CANCELLED')
                """
            )
        ).scalar_one()

        pending_count = connection.execute(
            text(
                """
                SELECT count(*)
                FROM guard.pending_installations
                WHERE status='WAITING'
                """
            )
        ).scalar_one()

        pending_rows = connection.execute(
            text(
                """
                SELECT *
                FROM guard.pending_installations
                WHERE status IN ('WAITING','ASSIGNED')
                ORDER BY
                    CASE status WHEN 'WAITING' THEN 0 ELSE 1 END,
                    last_seen_at DESC
                LIMIT 100
                """
            )
        ).mappings().all()

    devices = _fetch_device_rows(250)

    metrics = [
        ("Aktywne", counts["active"]),
        ("Standard", counts["standard"]),
        ("Pro", counts["pro"]),
        ("Wymagają uwagi", counts["needs_attention"]),
        ("Krytyczne", counts["critical"]),
        ("Wygasają ≤30 dni", counts["expiring_30d"]),
        ("Brak kontaktu 30 dni", counts["no_contact_30d"]),
        ("Nieodczytane", int(unread or 0)),
        ("Otwarte zgłoszenia", int(open_support or 0)),
        ("Nowe instalacje", int(pending_count or 0)),
    ]
    metrics_html = "".join(
        f'<div class="metric"><b>{_panel_h(label)}</b><strong>{int(value or 0)}</strong></div>'
        for label, value in metrics
    )

    rows_html = []
    for row in devices:
        health = str(row["health_level"] or "GREEN").upper()
        health_class = {
            "RED": "critical",
            "ORANGE": "bad",
            "YELLOW": "warn",
            "GREEN": "good",
        }.get(health, "muted")
        plan = "PRO" if str(row["plan_code"]).upper() == "PRO" else "STANDARD"
        rows_html.append(
            f"""
            <tr>
              <td class="mono">
                <a href="/multiguard/panel/device/{row['installation_id']}">
                  {_panel_h(_short_installation_id(row['installation_external_id']))}
                </a>
              </td>
              <td>
                <b>{_panel_h(_device_label(row))}</b><br>
                <span class="muted">{_panel_h(row['serial_number'] or row['hostname'] or '')}</span>
              </td>
              <td><span class="badge">{_panel_h(plan)}</span><br><span class="muted">{_panel_h(row['lifecycle'])}</span></td>
              <td><span class="badge {health_class}">{_panel_h(health)}</span></td>
              <td>{_panel_h(row['app_version'] or '—')}</td>
              <td>{_panel_dt(row['last_seen_at'])}</td>
              <td class="numbers">
                ⚠ {_panel_h(row['warning_30d'])}
                &nbsp; ! {_panel_h(row['important_30d'])}
                &nbsp; ⛔ {_panel_h(row['critical_30d'])}
                &nbsp; ERR {_panel_h(row['error_30d'])}
              </td>
              <td>{_panel_h(row['open_support'])}</td>
            </tr>
            """
        )

    if not rows_html:
        rows_html.append(
            '<tr><td colspan="8" class="muted">Brak zarejestrowanych instalacji Multi-Guard.</td></tr>'
        )

    pending_html = []
    for pending in pending_rows:
        installation_external = pending["installation_id"]
        short_id = _short_installation_id(installation_external)
        last_seen = pending["last_seen_at"]
        online = False
        if last_seen:
            try:
                online = (
                    datetime.now(timezone.utc) - last_seen
                ).total_seconds() <= 300
            except Exception:
                online = False
        device_label = " ".join(
            part for part in [
                str(pending["manufacturer"] or "").strip(),
                str(pending["model"] or "").strip(),
            ] if part
        ) or str(pending["hostname"] or "Nieznany komputer")
        state_label = (
            "OCZEKUJE NA PRZYPISANIE"
            if pending["status"] == "WAITING"
            else "LICENCJA PRZYPISANA — CZEKA NA ODBIÓR"
        )
        action = (
            f'<a class="button-link" href="/multiguard/panel/pending/{installation_external}">PRZYPISZ</a>'
            if pending["status"] == "WAITING"
            else '<span class="badge good">AUTO-PROVISION</span>'
        )
        pending_html.append(
            f"""
            <tr>
              <td class="mono">{_panel_h(short_id)}</td>
              <td><b>{_panel_h(device_label)}</b><br><span class="muted">{_panel_h(pending["serial_number"] or pending["hostname"] or "")}</span></td>
              <td>{_panel_h(pending["app_version"] or "—")}</td>
              <td><span class="badge {"good" if online else "muted"}">{"ONLINE" if online else "offline"}</span></td>
              <td>{_panel_h(state_label)}</td>
              <td>{_panel_dt(last_seen)}</td>
              <td>{action}</td>
            </tr>
            """
        )

    if not pending_html:
        pending_html.append(
            '<tr><td colspan="7" class="muted">Brak nowych, nieprzypisanych instalacji Multi-Guard.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card">
          <h1>Multi-Guard — Centrum właściciela</h1>
          <p>Widok komputerowy do zarządzania flotą, zgłoszeniami, telemetrią i licencjami.</p>
          <div class="metrics">{metrics_html}</div>
        </section>

        <section class="card">
          <div class="section-head">
            <div>
              <h2>Nowe / nieprzypisane instalacje</h2>
              <p>Multi-Guard wykryty po instalacji, ale jeszcze bez przypisanej licencji.</p>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Komputer</th><th>Wersja</th><th>Połączenie</th>
                  <th>Status</th><th>Ostatnio widziany</th><th>Akcja</th>
                </tr>
              </thead>
              <tbody>{''.join(pending_html)}</tbody>
            </table>
          </div>
        </section>

        <section class="card" id="devices">
          <div class="section-head">
            <div>
              <h2>Urządzenia</h2>
              <p>Liczniki zdarzeń dotyczą ostatnich 30 dni.</p>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Komputer</th><th>Licencja</th><th>Stan</th>
                  <th>Wersja</th><th>Ostatni kontakt</th><th>Zdarzenia 30 dni</th><th>Zgłoszenia</th>
                </tr>
              </thead>
              <tbody>{''.join(rows_html)}</tbody>
            </table>
          </div>
        </section>
        """
    )


@router.get("/panel/device/{installation_id}", response_class=HTMLResponse)
def multi_guard_panel_device(
    installation_id: str,
    _: None = Depends(_panel_auth),
):
    _ensure_schema()
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID instalacji.") from exc

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT
                    gi.id AS installation_id,
                    gi.installation_external_id,
                    gi.service_device_id,
                    gi.plan_code,gi.lifecycle,gi.valid_until,gi.last_seen_at,
                    gi.health_level,gi.app_version,gi.release_channel,
                    d.device_type,d.manufacturer,d.model,d.serial_number,d.hostname,
                    ll.reception_number
                FROM guard.installations gi
                LEFT JOIN core.devices d ON d.id=gi.service_device_id
                LEFT JOIN guard.license_links ll
                  ON ll.installation_id=gi.installation_external_id
                WHERE gi.id=:installation_id
                LIMIT 1
                """
            ),
            {"installation_id": iid},
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono instalacji Multi-Guard.")

        events = connection.execute(
            text(
                """
                SELECT event_id,event_type,severity,occurred_at,payload
                FROM guard.events
                WHERE installation_id=:installation_id
                ORDER BY occurred_at DESC
                LIMIT 200
                """
            ),
            {"installation_id": iid},
        ).mappings().all()

        support = connection.execute(
            text(
                """
                SELECT id,priority,subject,status,created_at
                FROM guard.support_requests
                WHERE installation_id=:installation_id
                ORDER BY created_at DESC
                LIMIT 50
                """
            ),
            {"installation_id": iid},
        ).mappings().all()

    event_rows = []
    for event in events:
        payload = event["payload"] or {}
        summary = (
            payload.get("message")
            or payload.get("detail")
            or payload.get("title")
            or payload.get("code")
            or ""
        )
        event_rows.append(
            f"""
            <tr>
              <td>{_panel_dt(event['occurred_at'])}</td>
              <td><span class="badge">{_panel_h(event['severity'])}</span></td>
              <td class="mono">{_panel_h(event['event_type'])}</td>
              <td>{_panel_h(summary)}</td>
            </tr>
            """
        )
    if not event_rows:
        event_rows.append(
            '<tr><td colspan="4" class="muted">Brak zapisanych zdarzeń.</td></tr>'
        )

    support_rows = []
    for item in support:
        priority = "PRO" if item["priority"] == "PRIORITY" else "STANDARD"
        support_rows.append(
            f"""
            <tr>
              <td>{_panel_dt(item['created_at'])}</td>
              <td><span class="badge">{priority}</span></td>
              <td>{_panel_h(item['subject'])}</td>
              <td>{_panel_h(item['status'])}</td>
            </tr>
            """
        )
    if not support_rows:
        support_rows.append(
            '<tr><td colspan="4" class="muted">Brak zgłoszeń dla tego komputera.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card">
          <a href="/multiguard/panel/dashboard">← Wróć do urządzeń</a>
          <h1>{_panel_h(_short_installation_id(row['installation_external_id']))} — {_panel_h(_device_label(row))}</h1>
          <div class="detail-grid">
            <div><b>Licencja</b><span>{_panel_h(row['plan_code'])} / {_panel_h(row['lifecycle'])}</span></div>
            <div><b>Wersja Multi-Guard</b><span>{_panel_h(row['app_version'] or '—')}</span></div>
            <div><b>Kanał</b><span>{_panel_h(row['release_channel'] or 'STABLE')}</span></div>
            <div><b>Stan</b><span>{_panel_h(row['health_level'] or '—')}</span></div>
            <div><b>Ostatni kontakt</b><span>{_panel_dt(row['last_seen_at'])}</span></div>
            <div><b>Zlecenie</b><span>{_panel_h(row['reception_number'] or '—')}</span></div>
            <div><b>Numer seryjny</b><span>{_panel_h(row['serial_number'] or '—')}</span></div>
            <div><b>Ważność</b><span>{_panel_dt(row['valid_until'])}</span></div>
          </div>
        </section>

        <section class="card">
          <h2>Zdarzenia — ostatnie 200</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Data</th><th>Poziom</th><th>Typ</th><th>Opis</th></tr></thead>
              <tbody>{''.join(event_rows)}</tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <h2>Zgłoszenia klienta</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Data</th><th>Plan</th><th>Temat</th><th>Status</th></tr></thead>
              <tbody>{''.join(support_rows)}</tbody>
            </table>
          </div>
        </section>
        """
    )


@router.get("/panel/telemetry", response_class=HTMLResponse)
def multi_guard_panel_telemetry(
    _: None = Depends(_panel_auth),
):
    rows = _fetch_telemetry_rows(90, 300)
    table_rows = []
    for row in rows:
        versions = ", ".join(row["app_versions"] or [])
        table_rows.append(
            f"""
            <tr>
              <td class="mono">{_panel_h(row['fingerprint'])}</td>
              <td>{_panel_h(row['component'] or '—')}</td>
              <td>{_panel_h(row['code'] or row['event_type'])}</td>
              <td>{_panel_h(row['affected_devices'])}</td>
              <td>{_panel_h(row['occurrences'])}</td>
              <td>{_panel_h(versions or '—')}</td>
              <td>{_panel_dt(row['last_seen'])}</td>
              <td>⚠ {_panel_h(row['warning_count'])} &nbsp; ! {_panel_h(row['important_count'])} &nbsp; ⛔ {_panel_h(row['critical_count'])}</td>
            </tr>
            """
        )
    if not table_rows:
        table_rows.append(
            '<tr><td colspan="8" class="muted">Telemetria jest gotowa. Zacznie się zapełniać po wdrożeniu wysyłki TELEMETRY_* w Multi-Guard dla Windows.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card">
          <h1>Telemetria / Rozwój Multi-Guard</h1>
          <p>Grupowanie podobnych problemów z ostatnich 90 dni. To jest baza do poprawiania kolejnych wersji Multi-Guard, a nie lista zgłoszeń klienta.</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Fingerprint</th><th>Moduł</th><th>Kod / typ</th>
                  <th>Urządzenia</th><th>Wystąpienia</th><th>Wersje</th>
                  <th>Ostatnio</th><th>Poziomy</th>
                </tr>
              </thead>
              <tbody>{''.join(table_rows)}</tbody>
            </table>
          </div>
        </section>
        """
    )


@router.get("/panel/licenses", response_class=HTMLResponse)
def multi_guard_panel_licenses(
    _: None = Depends(_panel_auth),
):
    _ensure_license_schema()
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    ll.reception_number,
                    ll.keygate_license_id,
                    ll.plan_code,
                    ll.duration_months,
                    ll.release_channel,
                    ll.lifecycle,
                    ll.app_version,
                    ll.valid_until,
                    ll.installation_id,
                    d.manufacturer,
                    d.model,
                    d.serial_number
                FROM guard.license_links ll
                LEFT JOIN core.devices d
                  ON d.id=ll.service_device_id
                ORDER BY ll.updated_at DESC
                LIMIT 500
                """
            )
        ).mappings().all()

    table_rows = []
    for row in rows:
        edition = "PRO" if row["plan_code"] == "multi_guard_pro" else "STANDARD"
        device = " ".join(
            part for part in [
                str(row["manufacturer"] or "").strip(),
                str(row["model"] or "").strip(),
            ] if part
        ) or "—"
        table_rows.append(
            f"""
            <tr>
              <td>{_panel_h(row['reception_number'])}</td>
              <td><span class="badge">{edition}</span></td>
              <td>{_panel_h(row['duration_months'])} mies.</td>
              <td>{_panel_h(row['release_channel'] or 'STABLE')}</td>
              <td>{_panel_h(row['lifecycle'])}</td>
              <td>{_panel_h(device)}</td>
              <td class="mono">{_panel_h(_short_installation_id(row['installation_id']) if row['installation_id'] else '—')}</td>
              <td>{_panel_h(row['app_version'] or '—')}</td>
              <td>{_panel_dt(row['valid_until'])}</td>
            </tr>
            """
        )
    if not table_rows:
        table_rows.append(
            '<tr><td colspan="9" class="muted">Brak licencji Multi-Guard.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card">
          <div class="section-head">
            <div>
              <h1>Licencje Multi-Guard</h1>
              <p>Przegląd wystawionych licencji, kanałów aktualizacji i terminów ważności.</p>
            </div>
            <a class="button-link" href="/multiguard/panel">NOWA LICENCJA</a>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Zlecenie</th><th>Plan</th><th>Okres</th><th>Kanał</th>
                  <th>Status</th><th>Komputer</th><th>ID</th><th>Wersja</th><th>Ważna do</th>
                </tr>
              </thead>
              <tbody>{''.join(table_rows)}</tbody>
            </table>
          </div>
        </section>
        """
    )


@router.get("/notifications")
def notifications(
    open_only: bool = True,
    limit: int = 100,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    limit = min(max(int(limit), 1), 250)
    where = "WHERE n.resolved_at IS NULL" if open_only else ""

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                f"""
                SELECT
                    n.id,n.service_device_id,n.installation_id,n.kind,n.severity,
                    n.title,n.message,n.created_at,n.seen_at,n.resolved_at,n.payload,
                    d.device_type,d.manufacturer,d.model,d.serial_number,
                    ll.reception_id,ll.reception_number
                FROM guard.notifications n
                LEFT JOIN core.devices d ON d.id=n.service_device_id
                LEFT JOIN guard.installations gi ON gi.id=n.installation_id
                LEFT JOIN guard.license_links ll
                    ON ll.installation_id=gi.installation_external_id
                {where}
                ORDER BY n.created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()

    return [
        {
            **dict(row),
            "id": str(row["id"]),
            "service_device_id": str(row["service_device_id"]),
            "installation_id": (
                str(row["installation_id"]) if row["installation_id"] else None
            ),
        }
        for row in rows
    ]


@router.post("/notifications/{notification_id}/seen")
def mark_notification_seen(
    notification_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        notification_uuid = uuid.UUID(notification_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID powiadomienia.") from exc

    with engine.begin() as connection:
        changed = connection.execute(
            text(
                """
                UPDATE guard.notifications
                SET seen_at=COALESCE(seen_at,now())
                WHERE id=:id
                """
            ),
            {"id": notification_uuid},
        ).rowcount

    if not changed:
        raise HTTPException(404, "Nie znaleziono powiadomienia.")
    return {"status": "ok"}


@router.post("/notifications/{notification_id}/resolve")
def resolve_notification(
    notification_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        notification_uuid = uuid.UUID(notification_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID powiadomienia.") from exc

    with engine.begin() as connection:
        changed = connection.execute(
            text(
                """
                UPDATE guard.notifications
                SET
                    seen_at=COALESCE(seen_at,now()),
                    resolved_at=COALESCE(resolved_at,now())
                WHERE id=:id
                """
            ),
            {"id": notification_uuid},
        ).rowcount

    if not changed:
        raise HTTPException(404, "Nie znaleziono powiadomienia.")
    return {"status": "ok"}


@router.get("/support-requests")
def support_requests(
    status: Optional[str] = None,
    limit: int = 100,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    limit = min(max(int(limit), 1), 250)
    params: dict[str, Any] = {"limit": limit}
    where = ""

    if status:
        params["status"] = status.upper()
        where = "WHERE sr.status=:status"

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                f"""
                SELECT
                    sr.id,sr.local_request_id,sr.service_device_id,sr.installation_id,
                    sr.priority,sr.subject,sr.description,sr.status,
                    sr.diagnostics_included,sr.created_at,sr.received_at,
                    sr.seen_at,sr.started_at,sr.resolved_at,sr.resolution_note,
                    d.device_type,d.manufacturer,d.model,d.serial_number,
                    ll.reception_id,ll.reception_number
                FROM guard.support_requests sr
                LEFT JOIN core.devices d ON d.id=sr.service_device_id
                LEFT JOIN guard.installations gi ON gi.id=sr.installation_id
                LEFT JOIN guard.license_links ll
                    ON ll.installation_id=gi.installation_external_id
                {where}
                ORDER BY
                    CASE sr.priority WHEN 'PRIORITY' THEN 0 ELSE 1 END,
                    CASE sr.status
                        WHEN 'NEW' THEN 0
                        WHEN 'SEEN' THEN 1
                        WHEN 'IN_PROGRESS' THEN 2
                        ELSE 3
                    END,
                    sr.created_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).mappings().all()

    return [
        {
            **dict(row),
            "id": str(row["id"]),
            "local_request_id": str(row["local_request_id"]),
            "service_device_id": str(row["service_device_id"]),
            "installation_id": str(row["installation_id"]),
        }
        for row in rows
    ]


@router.get("/support-requests/{request_id}")
def support_request_detail(
    request_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        request_uuid = uuid.UUID(request_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zgłoszenia.") from exc

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT
                    sr.id,sr.local_request_id,sr.service_device_id,sr.installation_id,
                    sr.priority,sr.subject,sr.description,sr.status,
                    sr.diagnostics_included,sr.created_at,sr.received_at,
                    sr.seen_at,sr.started_at,sr.resolved_at,sr.resolution_note,
                    d.device_type,d.manufacturer,d.model,d.serial_number,
                    ll.reception_id,ll.reception_number
                FROM guard.support_requests sr
                LEFT JOIN core.devices d ON d.id=sr.service_device_id
                LEFT JOIN guard.installations gi ON gi.id=sr.installation_id
                LEFT JOIN guard.license_links ll
                    ON ll.installation_id=gi.installation_external_id
                WHERE sr.id=:id
                LIMIT 1
                """
            ),
            {"id": request_uuid},
        ).mappings().first()

        if not row:
            raise HTTPException(404, "Nie znaleziono zgłoszenia.")

        diagnostic = connection.execute(
            text(
                """
                SELECT
                    schema_version,captured_at,payload,created_at,expires_at
                FROM guard.diagnostic_packages
                WHERE support_request_id=:id
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"id": request_uuid},
        ).mappings().first()

    response = {
        **dict(row),
        "id": str(row["id"]),
        "local_request_id": str(row["local_request_id"]),
        "service_device_id": str(row["service_device_id"]),
        "installation_id": str(row["installation_id"]),
        "diagnostic": None,
    }

    if diagnostic:
        response["diagnostic"] = {
            "schemaVersion": diagnostic["schema_version"],
            "capturedAt": diagnostic["captured_at"],
            "payload": diagnostic["payload"],
            "createdAt": diagnostic["created_at"],
            "expiresAt": diagnostic["expires_at"],
        }

    return response


@router.post("/support-requests/{request_id}/status")
def support_request_status(
    request_id: str,
    status: str,
    note: Optional[str] = None,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        request_uuid = uuid.UUID(request_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zgłoszenia.") from exc

    target = status.upper()
    if target not in {"SEEN", "IN_PROGRESS", "RESOLVED", "CANCELLED"}:
        raise HTTPException(400, "Nieprawidłowy status zgłoszenia.")

    with engine.begin() as connection:
        changed = connection.execute(
            text(
                """
                UPDATE guard.support_requests
                SET
                    status=:status,
                    seen_at=CASE
                        WHEN :status IN ('SEEN','IN_PROGRESS','RESOLVED')
                        THEN COALESCE(seen_at,now())
                        ELSE seen_at
                    END,
                    started_at=CASE
                        WHEN :status IN ('IN_PROGRESS','RESOLVED')
                        THEN COALESCE(started_at,now())
                        ELSE started_at
                    END,
                    resolved_at=CASE
                        WHEN :status IN ('RESOLVED','CANCELLED')
                        THEN COALESCE(resolved_at,now())
                        ELSE resolved_at
                    END,
                    resolution_note=CASE
                        WHEN :status IN ('RESOLVED','CANCELLED')
                        THEN :note
                        ELSE resolution_note
                    END
                WHERE id=:id
                """
            ),
            {
                "status": target,
                "note": note[:1000] if note else None,
                "id": request_uuid,
            },
        ).rowcount

    if not changed:
        raise HTTPException(404, "Nie znaleziono zgłoszenia.")
    return {"status": "ok"}


@router.get("/events/{event_id}")
def event_detail(
    event_id: str,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        event_uuid = uuid.UUID(event_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zdarzenia.") from exc

    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT
                    e.event_id,e.event_type,e.severity,e.occurred_at,e.received_at,
                    e.payload,i.service_device_id
                FROM guard.events e
                JOIN guard.installations i ON i.id=e.installation_id
                WHERE e.event_id=:event_id
                LIMIT 1
                """
            ),
            {"event_id": event_uuid},
        ).mappings().first()

    if not row:
        raise HTTPException(404, "Nie znaleziono zdarzenia.")

    return {
        **dict(row),
        "event_id": str(row["event_id"]),
        "service_device_id": str(row["service_device_id"]),
    }
