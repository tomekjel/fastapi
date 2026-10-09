from __future__ import annotations

import hashlib
import hmac
import html as html_lib
import json
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner
from app.routers.multiguard_panel_settings import owner_panel_config
from app.routers.multiguard_panel_diagnostics import owner_diagnostic_plan_panel
from app.routers.multiguard_panel_devices import (
    _schema as _ensure_owner_device_schema,
    owner_device_note,
    owner_device_note_form,
)
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
        -- Separate installation/lifecycle tracking from commercial licences.
        -- A confirmed installer event is not the same as a missing heartbeat.
        CREATE TABLE IF NOT EXISTS guard.agent_uninstalls (
            installation_id UUID PRIMARY KEY REFERENCES guard.installations(id) ON DELETE CASCADE,
            event_id UUID NOT NULL UNIQUE,
            reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            client_occurred_at TIMESTAMPTZ
        )
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

        # A new authenticated heartbeat is explicit evidence the agent works
        # again, e.g. after reinstallation on the same device. Clear only
        # the installation's removal indicator, not the audit event.
        connection.execute(
            text("DELETE FROM guard.agent_uninstalls WHERE installation_id=:id"),
            {"id": row["id"]},
        )

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

        if body.eventType == "CLIENT_UNINSTALLED":
            # This records a positive *client report* from the signed-in
            # installer path. Lack of heartbeat is NEVER considered removal.
            # In-place updater uninstall does not send this event.
            if payload.get("reason") == "user_uninstall" and payload.get("source") == "windows_uninstaller":
                connection.execute(
                    text("""
                        INSERT INTO guard.agent_uninstalls(
                            installation_id,event_id,client_occurred_at
                        )
                        VALUES(:installation_id,:event_id,:occurred_at)
                        ON CONFLICT(installation_id) DO UPDATE SET
                            event_id=EXCLUDED.event_id,
                            reported_at=now(),
                            client_occurred_at=EXCLUDED.client_occurred_at
                    """),
                    {
                        "installation_id": row["id"],
                        "event_id": body.eventId,
                        "occurred_at": body.sentAt,
                    },
                )
                connection.execute(
                    text("""
                        INSERT INTO guard.notifications(
                            service_device_id,installation_id,kind,severity,
                            title,message,dedup_key,payload
                        )
                        VALUES(
                            :device_id,:installation_id,'CLIENT_UNINSTALLED','INFO',
                            'Multi-Guard — odinstalowanie zgłoszone',
                            'Instalator Windows zgłosił świadome odinstalowanie Multi-Guard.',
                            :dedup_key,CAST(:payload AS jsonb)
                        )
                        ON CONFLICT DO NOTHING
                    """),
                    {
                        "device_id": row["service_device_id"],
                        "installation_id": row["id"],
                        "dedup_key": f"uninstall:{body.eventId}",
                        "payload": _json({"eventId": str(body.eventId), "source": "windows_uninstaller"}),
                    },
                )

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
    config = owner_panel_config()
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


def _fetch_device_rows(
    limit: int = 250, presence_filter: str = "all", search: str = "",
    offset: int = 0, silence_days: int = 7,
):

    _ensure_schema()
    _ensure_owner_device_schema()
    limit = min(max(int(limit), 1), 500)
    offset = min(max(int(offset), 0), 500000)
    silence_days = min(max(int(silence_days), 1), 90)
    search_like = "%" + search.strip()[:120].replace("%", "\\%").replace("_", "\\_") + "%"
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
                    au.reported_at AS uninstall_reported_at,
                    COALESCE(owner_notes.priority,'NORMAL') AS owner_priority,
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
                    COALESCE(nn.unread_notifications,0) AS unread_notifications,
                    COALESCE(visits.service_order_count,0) AS service_order_count
                FROM guard.installations gi
                LEFT JOIN core.devices d
                    ON d.id=gi.service_device_id
                LEFT JOIN guard.agent_uninstalls au
                    ON au.installation_id=gi.id
                LEFT JOIN guard.owner_device_notes owner_notes
                    ON owner_notes.installation_id=gi.id
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
                LEFT JOIN LATERAL (
                    SELECT count(*) AS service_order_count
                    FROM service.service_orders so
                    WHERE so.device_id=gi.service_device_id
                ) visits ON TRUE
                WHERE gi.is_current=TRUE
                  AND (
                    :presence_filter='all'
                    OR (:presence_filter='removed' AND au.installation_id IS NOT NULL)
                    OR (:presence_filter='silent' AND au.installation_id IS NULL
                        AND gi.lifecycle='ACTIVE'
                        AND (gi.last_seen_at IS NULL OR
                          gi.last_seen_at < now() - :silence_days * interval '1 day'))
                  )
                  AND (
                      :search_is_empty OR
                      COALESCE(d.model,'') ILIKE :search_like OR
                      COALESCE(d.manufacturer,'') ILIKE :search_like OR
                      COALESCE(d.hostname,'') ILIKE :search_like OR
                      COALESCE(d.serial_number,'') ILIKE :search_like OR
                      COALESCE(ll.reception_number,'') ILIKE :search_like
                  )
                ORDER BY
                    -- Client-initiated uninstalls stay accessible, at the
                    -- bottom of the inventory instead of disappearing.
                    CASE WHEN au.installation_id IS NOT NULL THEN 1 ELSE 0 END,
                    CASE COALESCE(owner_notes.priority,'NORMAL')
                        WHEN 'URGENT' THEN 0 WHEN 'WATCH' THEN 1 ELSE 2 END,
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
                LIMIT :limit OFFSET :offset
                """
            ),
            {
                "limit": limit, "offset": offset,
                "presence_filter": presence_filter,
                "silence_days": silence_days,
                "search_is_empty": not search.strip(),
                "search_like": search_like,
            },
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


def _presence_indicator(
    last_seen_at: Optional[datetime],
    uninstall_reported_at: Optional[datetime],
    recent_hours: int = 24,
    delayed_days: int = 7,
):
    """Last *server-confirmed* contact, not Windows login, physical uptime or licence."""
    if uninstall_reported_at is not None:
        return "removed", "Odinstalowanie zgłoszone"
    if last_seen_at is None:
        return "unknown", "Brak potwierdzonego kontaktu"
    try:
        age_s = max(0, (datetime.now(timezone.utc) - last_seen_at).total_seconds())
    except (TypeError, ValueError):
        return "unknown", "Brak potwierdzonego kontaktu"
    if age_s <= recent_hours * 3600:
        return "recent", f"Kontakt w ciągu {recent_hours} h"
    if age_s <= delayed_days * 24 * 3600:
        return "delayed", f"Brak kontaktu do {delayed_days} dni"
    if age_s <= 30 * 24 * 3600:
        return "stale", f"Brak kontaktu {delayed_days}–30 dni"
    return "stale", "Brak kontaktu ponad 30 dni"


@router.get("/panel/dashboard", response_class=HTMLResponse)
def multi_guard_panel_dashboard(
    _: None = Depends(_panel_auth),
):
    """Owner start screen: operational summary, not a second inventory page."""
    _ensure_schema()
    with engine.connect() as connection:
        counts = connection.execute(text("""
            SELECT
              count(*) FILTER (WHERE lifecycle='ACTIVE') AS active,
              count(*) FILTER (WHERE lifecycle='ACTIVE' AND plan_code='STANDARD') AS standard,
              count(*) FILTER (WHERE lifecycle='ACTIVE' AND plan_code='PRO') AS pro,
              count(*) FILTER (WHERE health_level IN ('ORANGE','RED')) AS attention,
              count(*) FILTER (WHERE health_level='RED') AS critical,
              count(*) FILTER (WHERE lifecycle='ACTIVE' AND last_seen_at < now()-interval '7 days') AS silent
            FROM guard.installations
            WHERE is_current=TRUE
        """)).mappings().one()
        pending_count = connection.execute(text("""
            SELECT count(*) FROM guard.pending_installations WHERE status='WAITING'
        """)).scalar_one()
        alerts_count = connection.execute(text("""
            SELECT count(*) FROM guard.notifications
            WHERE resolved_at IS NULL AND seen_at IS NULL
        """)).scalar_one()
        support_count = connection.execute(text("""
            SELECT count(*) FROM guard.support_requests
            WHERE status NOT IN ('RESOLVED','CANCELLED')
        """)).scalar_one()
    kpis = [
        ("Aktywne komputery", counts["active"], "blue"),
        ("Wymagają uwagi", counts["attention"], "red"),
        ("Krytyczne", counts["critical"], "red"),
        ("Oczekujące instalacje", pending_count, "gold"),
        ("Nieodczytane powiadomienia", alerts_count, "blue"),
        ("Otwarte zgłoszenia", support_count, "green"),
    ]
    metrics_html = "".join(
        (
            f'<a class="metric metric-link accent-{tone}" href="/multiguard/panel/computers#pending">'
            f'<b>{_panel_h(label)}</b><strong>{int(value or 0)}</strong></a>'
            if label == "Oczekujące instalacje" else
            f'<div class="metric accent-{tone}"><b>{_panel_h(label)}</b>'
            f'<strong>{int(value or 0)}</strong></div>'
        )
        for label, value, tone in kpis
    )
    return _panel_html(f"""
      <section class="card panel-hero dashboard-hero">
        <div class="eyebrow">MULTI-SERVIS / CENTRUM WŁAŚCICIELA</div>
        <h1>Pulpit</h1>
        <p>Aktualny stan serwisu i Multi-Guard. Kliknij oczekujące instalacje, aby od razu przypisać licencję.</p>
        <div class="metrics">{metrics_html}</div>
      </section>
      <section class="card">
        <div class="section-head">
          <div><div class="eyebrow">SKRÓTY</div>
          <h2>Szybki dostęp</h2></div>
        </div>
        <div class="hub-grid">
          <a class="hub-tile" href="/multiguard/panel/computers">
            <span class="hub-symbol" aria-hidden="true">▤</span>
            <strong>Komputery</strong><span>Lista instalacji, zdarzenia i historia napraw</span>
            <small>{int(counts["standard"] or 0)} Standard · {int(counts["pro"] or 0)} Pro →</small>
          </a>
          <a class="hub-tile" href="/multiguard/panel/service">
            <span class="hub-symbol" aria-hidden="true">◇</span>
            <strong>Zlecenia serwisowe</strong><span>Statusy napraw, zdjęcia, dokumentacja, kwoty</span>
            <small>Otwórz rejestr zleceń →</small>
          </a>
          <a class="hub-tile" href="/multiguard/panel/statistics">
            <span class="hub-symbol" aria-hidden="true">▥</span>
            <strong>Statystyki</strong><span>Finanse, materiały z dawcy i rozliczenia</span>
            <small>Dostęp właściciela →</small>
          </a>
          <a class="hub-tile" href="/multiguard/panel/licenses">
            <span class="hub-symbol" aria-hidden="true">▣</span>
            <strong>Licencje</strong><span>Standard, Pro i przypisanie instalacji</span>
            <small>Otwórz licencje →</small>
          </a>
        </div>
      </section>

    """)


@router.get("/panel/computers", response_class=HTMLResponse)
def multi_guard_panel_computers(
    presence: str = "all",
    q: str = "",
    page_number: int = 1,
    _: None = Depends(_panel_auth),
):
    if len(q) > 120 or not 1 <= page_number <= 5000:
        raise HTTPException(400, "Nieprawidłowe parametry wyszukiwania.")
    if presence not in {"all", "silent", "removed"}:
        raise HTTPException(400, "Nieprawidłowy filtr kontaktu Multi-Guard.")
    _ensure_schema()
    config = owner_panel_config()
    page_size = config["inventory_page_size"]
    device_results = _fetch_device_rows(
        page_size + 1,
        presence_filter=presence,
        search=q,
        offset=(page_number - 1) * page_size,
        silence_days=config["no_contact_filter_days"],
    )
    has_more_devices = len(device_results) > page_size
    devices = device_results[:page_size]

    def device_page_url(page: int) -> str:
        return "/multiguard/panel/computers?" + urllib.parse.urlencode({
            "presence": presence, "q": q, "page_number": page,
        }) + "#devices"

    device_search_form = f"""
        <form class="service-search" method="get" action="/multiguard/panel/computers">
          <input type="hidden" name="presence" value="{_panel_h(presence)}">
          <label>Wyszukaj model, producenta, numer seryjny, hostname lub zlecenie
            <input name="q" maxlength="120" value="{_panel_h(q)}"
              placeholder="np. Lenovo, MG-2026, S/N">
          </label>
          <button type="submit">SZUKAJ</button>
        </form>
    """
    device_paging = (
        f'<a class="button-link compact" href="{device_page_url(page_number - 1)}">← POPRZEDNIA</a>'
        if page_number > 1 else ""
    ) + f'<span>Strona {page_number}</span>' + (
        f'<a class="button-link compact" href="{device_page_url(page_number + 1)}">NASTĘPNA →</a>'
        if has_more_devices else ""
    )


    # WAITING machines have no signed paid licence yet, so they cannot
    # appear in the ACTIVE fleet table. Show them separately, with a direct
    # link to the existing authenticated assignment form.
    with engine.connect() as connection:
        pending_rows = connection.execute(text("""
            SELECT installation_id,hostname,manufacturer,model,
                   serial_number,app_version,status,last_seen_at
            FROM guard.pending_installations
            WHERE status IN ('WAITING','ASSIGNED')
            ORDER BY CASE WHEN status='WAITING' THEN 0 ELSE 1 END,
                     last_seen_at DESC
            LIMIT 40
        """)).mappings().all()
    pending_trs = []
    for pending in pending_rows:
        iid = pending["installation_id"]
        name = " ".join(str(x).strip() for x in (pending["manufacturer"],pending["model"]) if x
                        ) or pending["hostname"] or "Komputer bez nazwy"
        status_label = "OCZEKUJE NA LICENCJĘ" if pending["status"]=="WAITING" else "PRZYPISANA — POBIERANIE"
        pending_trs.append(f"""
            <tr><td><strong>{_panel_h('MG-'+str(iid).replace('-','')[:8].upper())}</strong></td>
                <td>{_panel_h(name)}<small class="row-sub">{_panel_h(pending["serial_number"] or pending["hostname"] or "")}</small></td>
                <td>{_panel_h(pending["app_version"] or "—")}</td>
                <td><span class="badge {'mg-gold' if pending["status"]=='WAITING' else 'mg-blue'}">{status_label}</span></td>
                <td>{_panel_dt(pending["last_seen_at"])}</td>
                <td><a class="button-link compact" href="/multiguard/panel/pending/{iid}">
                  {'PRZYPISZ LICENCJĘ' if pending["status"]=='WAITING' else 'SZCZEGÓŁY'}</a></td>
            </tr>
        """)
    pending_section = f"""
        <section class="card" id="pending">
          <div class="section-head"><div><div class="eyebrow">NOWE INSTALACJE</div>
            <h2>Oczekujące komputery ({len(pending_rows)})</h2>
            <p>Tutaj pojawia się nowy Multi-Guard przed przypisaniem licencji.
            Takie komputery nie są jeszcze w rejestrze aktywnej floty.</p></div></div>
          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Komputer</th><th>Wersja</th>
            <th>Stan</th><th>Ostatni kontakt</th><th>Akcja</th></tr></thead>
            <tbody>{''.join(pending_trs) or '<tr><td colspan="6" class="muted">Brak oczekujących instalacji.</td></tr>'}</tbody>
          </table></div>
        </section>
    """

    rows_html = []
    for row in devices:
        presence_style, presence_label = _presence_indicator(
            row["last_seen_at"], row["uninstall_reported_at"],
            config["contact_recent_hours"], config["contact_delayed_days"],
        )
        health = str(row["health_level"] or "GREEN").upper()
        health_class = {
            "RED": "critical",
            "ORANGE": "bad",
            "YELLOW": "warn",
            "GREEN": "good",
        }.get(health, "muted")
        plan = "PRO" if str(row["plan_code"]).upper() == "PRO" else "STANDARD"
        owner_priority = str(row["owner_priority"] or "NORMAL")
        owner_attention = (
            '<br><span class="badge mg-red">PILNE — OBSERWUJ</span>'
            if owner_priority=="URGENT" else
            ('<br><span class="badge mg-gold">DO OBSERWACJI</span>'
             if owner_priority=="WATCH" else "")
        )
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
                <span class="muted">{_panel_h(row['serial_number'] or row['hostname'] or '')}</span>{owner_attention}
              </td>
              <td><span class="badge {'mg-gold' if plan=='PRO' else 'mg-red'}">{_panel_h(plan)}</span><br><span class="muted">{_panel_h(row['lifecycle'])}</span></td>
              <td><span class="badge {health_class}">{_panel_h(health)}</span></td>
              <td>{_panel_h(row['app_version'] or '—')}</td>
              <td><span class="presence-label"><span class="presence-dot presence-{presence_style}" aria-hidden="true"></span>{_panel_h(presence_label)}</span></td>
              <td><a class="strong-link" href="/multiguard/panel/device/{row['installation_id']}#service-history">{_panel_h(row['service_order_count'])} wpisów</a></td>
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
            '<tr><td colspan="10" class="muted">Brak zarejestrowanych instalacji Multi-Guard.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card panel-hero computers-hero">
          <div class="eyebrow">MULTI-SERVIS / KOMPUTERY KLIENTÓW</div>
          <h1>Komputery</h1>
          <p>Samodzielny rejestr instalacji Multi-Guard, ich ostatniego kontaktu, stanu technicznego i historii serwisu.</p>
          <div class="inventory-headline">
            <span class="badge mg-blue">Lista i historia urządzeń</span>
            <span class="muted">Stan łączności pochodzi z ostatniego raportu agenta.</span>
          </div>
        </section>
        {pending_section}
        <section class="card" id="devices">
          <div class="section-head">
            <div>
              <h2>Urządzenia</h2>
              <p>Ostatni kontakt jest potwierdzony przez serwer, nie oznacza pracy użytkownika w tej chwili. Odinstalowanie pokazujemy tylko po otrzymaniu zgłoszenia instalatora. Zdarzenia dotyczą ostatnich 30 dni.</p>
            </div>
          </div>
          <div class="filter-tabs">
            <a class="filter-tab {'selected' if presence=='all' else ''}" href="/multiguard/panel/computers?presence=all#devices">WSZYSTKIE</a>
            <a class="filter-tab {'selected' if presence=='silent' else ''}" href="/multiguard/panel/computers?presence=silent#devices">BRAK KONTAKTU PONAD {config['no_contact_filter_days']} DNI</a>
            <a class="filter-tab {'selected' if presence=='removed' else ''}" href="/multiguard/panel/computers?presence=removed#devices">ZGŁOSZONE ODINSTALOWANIE</a>
          </div>
          {device_search_form}
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Komputer</th><th>Licencja</th><th>Stan</th>
                  <th>Wersja</th><th>Łączność</th><th>Historia serwisu</th><th>Ostatni kontakt</th><th>Zdarzenia 30 dni</th><th>Zgłoszenia</th>
                </tr>
              </thead>
              <tbody>{''.join(rows_html)}</tbody>
            </table>
          </div>
          <div class="pagination">{device_paging}</div>
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
                    au.reported_at AS uninstall_reported_at,
                    d.device_type,d.manufacturer,d.model,d.serial_number,d.hostname,
                    ll.reception_number
                FROM guard.installations gi
                LEFT JOIN core.devices d ON d.id=gi.service_device_id
                LEFT JOIN guard.agent_uninstalls au ON au.installation_id=gi.id
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

        # Repair/service visits belong to the physical core.devices record, not
        # to the licence or its reception number. Never guess identity from a
        # hostname or serial number: those can be duplicated or mistyped.
        repair_visits = connection.execute(
            text(
                """
                SELECT so.id,so.reception_number,so.status,
                       so.received_at,so.completed_at,
                       so.fault_description,so.intake_description,
                       (SELECT count(*) FROM service.service_order_media media
                        WHERE media.service_order_id=so.id
                          AND media.deleted_at IS NULL) AS media_count
                FROM service.service_orders so
                WHERE so.device_id=:service_device_id
                ORDER BY so.received_at DESC
                LIMIT 100
                """
            ),
            {"service_device_id": row["service_device_id"]},
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

    settings = owner_panel_config()
    device_presence_style, device_presence_label = _presence_indicator(
        row["last_seen_at"], row["uninstall_reported_at"],
        settings["contact_recent_hours"], settings["contact_delayed_days"],
    )
    own_note_data = owner_device_note(iid)
    note_edit_html = owner_device_note_form(iid, own_note_data)
    diagnostic_plan_html = owner_diagnostic_plan_panel(iid)
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
              <td><a class="button-link compact" href="/multiguard/panel/incident/{event['event_id']}">OCENA / NOTATKA</a></td>
            </tr>
            """
        )
    if not event_rows:
        event_rows.append(
            '<tr><td colspan="5" class="muted">Brak zapisanych zdarzeń.</td></tr>'
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

    service_rows = []
    service_state_labels = {
        "IN_SERVICE": "W naprawie",
        "READY_FOR_PICKUP": "Do odbioru",
        "COMPLETED": "Wydane",
        "CANCELLED": "Anulowane",
    }
    for order in repair_visits:
        # A licence-related visit is not proof that we physically repaired
        # the PC: use neutral "wpis w serwisie", not "wykonana naprawa".
        status = str(order["status"] or "")
        description = str(
            order["fault_description"] or order["intake_description"] or ""
        ).strip()
        if len(description) > 240:
            description = description[:237] + "..."
        service_rows.append(
            f"""
            <tr>
              <td><a class="strong-link" href="/multiguard/panel/service/{order['id']}">{_panel_h(order['reception_number'])}</a></td>
              <td>{_panel_dt(order['received_at'])}</td>
              <td>{_panel_h(service_state_labels.get(status,status))}</td>
              <td>{_panel_h(description or 'Wpis w serwisie — brak opisu naprawy')}</td>
              <td>{_panel_h(order['media_count'])}</td>
              <td><a class="button-link compact" href="/multiguard/panel/service/{order['id']}">ZLECENIE / PLIKI</a></td>
            </tr>
            """
        )
    if not service_rows:
        service_rows.append(
            '<tr><td colspan="6" class="muted">Brak powiązanych wizyt lub napraw w Multi-Servis. Samo zainstalowanie Multi-Guard nie oznacza wykonania naprawy.</td></tr>'
        )

    return _panel_html(
        f"""
        <section class="card panel-hero device-hero">
          <a class="button-link compact" href="/multiguard/panel/dashboard#devices">← Wróć do komputerów</a>
          <h1>{_panel_h(_short_installation_id(row['installation_external_id']))} — {_panel_h(_device_label(row))}</h1>
          <div class="detail-grid">
            <div><b>Licencja</b><span>{_panel_h(row['plan_code'])} / {_panel_h(row['lifecycle'])}</span></div>
            <div><b>Wersja Multi-Guard</b><span>{_panel_h(row['app_version'] or '—')}</span></div>
            <div><b>Kanał</b><span>{_panel_h(row['release_channel'] or 'STABLE')}</span></div>
            <div><b>Stan</b><span>{_panel_h(row['health_level'] or '—')}</span></div>
            <div><b>Łączność</b><span class="presence-label"><span class="presence-dot presence-{device_presence_style}" aria-hidden="true"></span>{_panel_h(device_presence_label)}</span></div>
            <div><b>Ostatni kontakt</b><span>{_panel_dt(row['last_seen_at'])}</span></div>
            <div><b>Zlecenie</b><span>{_panel_h(row['reception_number'] or '—')}</span></div>
            <div><b>Numer seryjny</b><span>{_panel_h(row['serial_number'] or '—')}</span></div>
            <div><b>Ważność</b><span>{_panel_dt(row['valid_until'])}</span></div>
          </div>
        </section>

        {diagnostic_plan_html}
        {note_edit_html}

        <section class="card" id="service-history">
          <div class="section-head">
            <div>
              <div class="eyebrow">MULTI-SERVIS / HISTORIA FIZYCZNEGO URZĄDZENIA</div>
              <h2>Wizyty, zlecenia i dokumentacja serwisowa</h2>
              <p>Wyłącznie zlecenia powiązane z tą kartą sprzętu. Kliknij zlecenie, aby zobaczyć opis, historię statusów, finanse oraz wykaz zdjęć i dokumentów. Podgląd samych zdjęć WWW wymaga osobnej zabezpieczonej integracji.</p>
            </div>
            <a class="button-link compact" href="/multiguard/panel/service">WSZYSTKIE ZLECENIA</a>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Zlecenie</th><th>Przyjęto</th><th>Status</th><th>Opis</th><th>Plików</th><th></th></tr></thead>
              <tbody>{''.join(service_rows)}</tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <h2>Zdarzenia — ostatnie 200</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Data</th><th>Poziom</th><th>Typ</th><th>Opis</th><th>Ocena właściciela</th></tr></thead>
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
    days: int = 90,
    severity: str = "ALL",
    q: str = "",
    _: None = Depends(_panel_auth),
):
    days = min(max(int(days), 1), 3650)
    severity = severity.strip().upper()
    if severity not in {"ALL", "WARNING", "IMPORTANT", "CRITICAL"}:
        severity = "ALL"
    query = q.strip().lower()

    rows = [dict(row) for row in _fetch_telemetry_rows(days, 500)]

    def matches(row: dict[str, Any]) -> bool:
        if severity == "WARNING" and int(row["warning_count"] or 0) <= 0:
            return False
        if severity == "IMPORTANT" and int(row["important_count"] or 0) <= 0:
            return False
        if severity == "CRITICAL" and int(row["critical_count"] or 0) <= 0:
            return False
        if query:
            haystack = " ".join(
                [
                    str(row.get("fingerprint") or ""),
                    str(row.get("component") or ""),
                    str(row.get("code") or ""),
                    str(row.get("event_type") or ""),
                    " ".join(row.get("app_versions") or []),
                ]
            ).lower()
            if query not in haystack:
                return False
        return True

    filtered = [row for row in rows if matches(row)]
    total_occurrences = sum(int(row["occurrences"] or 0) for row in filtered)
    critical_occurrences = sum(int(row["critical_count"] or 0) for row in filtered)
    important_occurrences = sum(int(row["important_count"] or 0) for row in filtered)
    warning_occurrences = sum(int(row["warning_count"] or 0) for row in filtered)

    metrics_html = "".join(
        [
            f'<div class="metric"><b>Grupy problemów</b><strong>{len(filtered)}</strong></div>',
            f'<div class="metric"><b>Wystąpienia</b><strong>{total_occurrences}</strong></div>',
            f'<div class="metric"><b>Krytyczne</b><strong>{critical_occurrences}</strong></div>',
            f'<div class="metric"><b>Ważne</b><strong>{important_occurrences}</strong></div>',
            f'<div class="metric"><b>Ostrzeżenia</b><strong>{warning_occurrences}</strong></div>',
        ]
    )

    table_rows = []
    for row in filtered:
        versions = ", ".join(row["app_versions"] or [])
        if int(row["critical_count"] or 0) > 0:
            priority, priority_class = "KRYTYCZNE", "critical"
        elif int(row["important_count"] or 0) > 0:
            priority, priority_class = "WAŻNE", "bad"
        elif int(row["warning_count"] or 0) > 0:
            priority, priority_class = "OSTRZEŻENIE", "warn"
        else:
            priority, priority_class = "INFO", "good"

        fingerprint = str(row["fingerprint"] or "")
        detail_url = (
            "/multiguard/panel/telemetry/detail?fingerprint="
            + urllib.parse.quote(fingerprint, safe="")
            + f"&days={days}"
        )
        problem_name = str(row["code"] or row["event_type"] or "Nieznany problem")
        component = str(row["component"] or "Nieznany moduł")

        table_rows.append(
            f"""
            <tr>
              <td><span class="badge {priority_class}">{_panel_h(priority)}</span></td>
              <td>
                <b class="problem-title">{_panel_h(problem_name)}</b><br>
                <span class="muted">{_panel_h(component)}</span><br>
                <span class="mono muted">{_panel_h(fingerprint)}</span>
              </td>
              <td class="numbers"><b>{_panel_h(row['affected_devices'])}</b></td>
              <td class="numbers"><b>{_panel_h(row['occurrences'])}</b></td>
              <td>{_panel_h(versions or '—')}</td>
              <td>{_panel_dt(row['first_seen'])}</td>
              <td>{_panel_dt(row['last_seen'])}</td>
              <td class="numbers">
                ⚠ {_panel_h(row['warning_count'])}
                &nbsp; ! {_panel_h(row['important_count'])}
                &nbsp; ⛔ {_panel_h(row['critical_count'])}
              </td>
              <td><a class="button-link compact" href="{detail_url}">SZCZEGÓŁY</a></td>
            </tr>
            """
        )

    if not table_rows:
        table_rows.append(
            '<tr><td colspan="9" class="muted">Brak telemetrii pasującej do wybranych filtrów. Gdy Multi-Guard Windows zacznie wysyłać zdarzenia, pojawią się tutaj automatycznie.</td></tr>'
        )

    day_options = "".join(
        f'<option value="{value}" {"selected" if days == value else ""}>{label}</option>'
        for value, label in [
            (7, "7 dni"),
            (30, "30 dni"),
            (90, "90 dni"),
            (180, "180 dni"),
            (365, "1 rok"),
        ]
    )
    severity_options = "".join(
        f'<option value="{value}" {"selected" if severity == value else ""}>{label}</option>'
        for value, label in [
            ("ALL", "Wszystkie"),
            ("WARNING", "Ostrzeżenia"),
            ("IMPORTANT", "Ważne"),
            ("CRITICAL", "Krytyczne"),
        ]
    )

    return _panel_html(
        f"""
        <section class="card panel-hero telemetry-hero">
          <div class="section-head">
            <div>
              <div class="eyebrow">MULTI-GUARD • ROZWÓJ</div>
              <h1>Telemetria</h1>
              <p>
                Problemy techniczne grupowane według wzorca. Kliknij „Szczegóły”,
                aby zobaczyć konkretne urządzenia, zlecenia i wystąpienia.
              </p>
            </div>
            <div class="telemetry-status">
              <span class="badge good">● ANALIZA AKTYWNA</span>
              <span class="muted">Zakres: ostatnie {days} dni</span>
            </div>
          </div>
          <div class="metrics">{metrics_html}</div>
        </section>

        <section class="card">
          <form method="get" action="/multiguard/panel/telemetry" class="filter-bar">
            <label>Zakres czasu
              <select name="days">{day_options}</select>
            </label>
            <label>Poziom
              <select name="severity">{severity_options}</select>
            </label>
            <label class="filter-grow">Szukaj
              <input name="q" value="{_panel_h(q)}" placeholder="moduł, kod, fingerprint, wersja...">
            </label>
            <label>&nbsp;<button type="submit">FILTRUJ</button></label>
          </form>
        </section>

        <section class="card">
          <div class="section-head">
            <div>
              <h2>Grupy problemów</h2>
              <p>Jeden wiersz oznacza jeden wzorzec problemu, nawet jeśli wystąpił wielokrotnie na wielu komputerach.</p>
            </div>
          </div>
          <div class="table-wrap">
            <table class="telemetry-table">
              <thead>
                <tr>
                  <th>Priorytet</th><th>Problem</th><th>Urządzenia</th>
                  <th>Wystąpienia</th><th>Wersje</th><th>Pierwszy raz</th>
                  <th>Ostatnio</th><th>Poziomy</th><th></th>
                </tr>
              </thead>
              <tbody>{''.join(table_rows)}</tbody>
            </table>
          </div>
        </section>
        """
    )


@router.get("/panel/telemetry/detail", response_class=HTMLResponse)
def multi_guard_panel_telemetry_detail(
    fingerprint: str,
    days: int = 90,
    _: None = Depends(_panel_auth),
):
    _ensure_schema()
    days = min(max(int(days), 1), 3650)
    fingerprint = fingerprint.strip()
    if not fingerprint:
        raise HTTPException(400, "Brak fingerprintu telemetrii.")

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                WITH telemetry AS (
                    SELECT
                        e.event_id,e.installation_id,e.event_type,e.severity,
                        e.occurred_at,e.payload,
                        gi.installation_external_id,gi.app_version,
                        gi.health_level,gi.lifecycle,gi.plan_code,gi.last_seen_at,
                        d.device_type,d.manufacturer,d.model,d.serial_number,d.hostname,
                        ll.reception_id,ll.reception_number,
                        COALESCE(
                            NULLIF(e.payload->>'fingerprint',''),
                            e.event_type || ':' ||
                            COALESCE(NULLIF(e.payload->>'component',''),'unknown') || ':' ||
                            COALESCE(NULLIF(e.payload->>'code',''),'unknown')
                        ) AS fingerprint
                    FROM guard.events e
                    JOIN guard.installations gi ON gi.id=e.installation_id
                    LEFT JOIN core.devices d ON d.id=gi.service_device_id
                    LEFT JOIN guard.license_links ll
                      ON ll.installation_id=gi.installation_external_id
                    WHERE e.occurred_at >= now() - (:days * interval '1 day')
                      AND (
                          e.event_type LIKE 'TELEMETRY_%'
                          OR e.event_type IN (
                              'APP_ERROR','MODULE_ERROR','SENSOR_ERROR',
                              'UNKNOWN_ANOMALY','PROVIDER_FAILURE','READ_FAILURE'
                          )
                      )
                )
                SELECT * FROM telemetry
                WHERE fingerprint=:fingerprint
                ORDER BY occurred_at DESC
                LIMIT 500
                """
            ),
            {"days": days, "fingerprint": fingerprint},
        ).mappings().all()

    if not rows:
        raise HTTPException(404, "Nie znaleziono zdarzeń dla tego wzorca w wybranym okresie.")

    first = dict(rows[0])
    devices: dict[str, dict[str, Any]] = {}
    event_rows = []

    for raw in rows:
        row = dict(raw)
        installation_key = str(row["installation_id"])
        item = devices.setdefault(
            installation_key,
            {
                "installation_id": row["installation_id"],
                "installation_external_id": row["installation_external_id"],
                "reception_number": row["reception_number"],
                "device_type": row["device_type"],
                "manufacturer": row["manufacturer"],
                "model": row["model"],
                "serial_number": row["serial_number"],
                "hostname": row["hostname"],
                "app_version": row["app_version"],
                "health_level": row["health_level"],
                "occurrences": 0,
                "last_seen": row["occurred_at"],
            },
        )
        item["occurrences"] += 1
        if row["occurred_at"] and (
            not item["last_seen"] or row["occurred_at"] > item["last_seen"]
        ):
            item["last_seen"] = row["occurred_at"]

        payload = row["payload"] or {}
        summary = (
            payload.get("message")
            or payload.get("detail")
            or payload.get("title")
            or payload.get("code")
            or row["event_type"]
        )
        sev = str(row["severity"] or "INFO").upper()
        sev_class = {"CRITICAL":"critical","IMPORTANT":"bad","WARNING":"warn"}.get(sev,"good")
        event_rows.append(
            f"""
            <tr>
              <td>{_panel_dt(row['occurred_at'])}</td>
              <td><span class="badge {sev_class}">{_panel_h(sev)}</span></td>
              <td><a href="/multiguard/panel/device/{row['installation_id']}">{_panel_h(_short_installation_id(row['installation_external_id']))}</a></td>
              <td>{_panel_h(row['reception_number'] or '—')}</td>
              <td>{_panel_h(row['app_version'] or '—')}</td>
              <td>{_panel_h(summary)}</td>
            </tr>
            """
        )

    device_rows = []
    for item in sorted(devices.values(), key=lambda value: (-int(value["occurrences"]), str(value["reception_number"] or ""))):
        device_label = " ".join(
            part for part in [
                str(item["manufacturer"] or "").strip(),
                str(item["model"] or "").strip(),
            ] if part
        ) or str(item["hostname"] or "Nieznany komputer")
        device_rows.append(
            f"""
            <tr>
              <td><a href="/multiguard/panel/device/{item['installation_id']}">{_panel_h(_short_installation_id(item['installation_external_id']))}</a></td>
              <td><b>{_panel_h(device_label)}</b><br><span class="muted">{_panel_h(item['device_type'] or '')}</span></td>
              <td class="mono">{_panel_h(item['serial_number'] or '—')}</td>
              <td><b>{_panel_h(item['reception_number'] or '—')}</b></td>
              <td>{_panel_h(item['app_version'] or '—')}</td>
              <td><span class="badge">{_panel_h(item['health_level'] or '—')}</span></td>
              <td class="numbers"><b>{_panel_h(item['occurrences'])}</b></td>
              <td>{_panel_dt(item['last_seen'])}</td>
            </tr>
            """
        )

    payload = first["payload"] or {}
    component = payload.get("component") or "Nieznany moduł"
    code = payload.get("code") or first["event_type"]

    return _panel_html(
        f"""
        <section class="card panel-hero telemetry-hero">
          <a href="/multiguard/panel/telemetry?days={days}">← Wróć do telemetrii</a>
          <div class="eyebrow">SZCZEGÓŁY WZORCA</div>
          <h1>{_panel_h(code)}</h1>
          <p>Moduł: <b>{_panel_h(component)}</b><br><span class="mono">{_panel_h(fingerprint)}</span></p>
          <div class="metrics">
            <div class="metric"><b>Urządzenia</b><strong>{len(devices)}</strong></div>
            <div class="metric"><b>Wystąpienia</b><strong>{len(rows)}</strong></div>
            <div class="metric"><b>Zakres</b><strong>{days} d</strong></div>
          </div>
        </section>

        <section class="card">
          <h2>Urządzenia i zlecenia</h2>
          <p>Sprzęt, na którym wystąpił problem, oraz powiązane zlecenie Multi-Servis.</p>
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Sprzęt</th><th>Serial</th><th>Zlecenie</th><th>Wersja</th><th>Stan</th><th>Wystąpienia</th><th>Ostatnio</th></tr></thead>
              <tbody>{''.join(device_rows)}</tbody>
            </table>
          </div>
        </section>

        <section class="card">
          <h2>Historia wystąpień</h2>
          <p>Ostatnie maksymalnie 500 zdarzeń tego samego wzorca.</p>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Data</th><th>Poziom</th><th>Urządzenie</th><th>Zlecenie</th><th>Wersja</th><th>Opis</th></tr></thead>
              <tbody>{''.join(event_rows)}</tbody>
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
                    gi.id AS internal_installation_id,
                    d.manufacturer,
                    d.model,
                    d.serial_number
                FROM guard.license_links ll
                LEFT JOIN core.devices d
                  ON d.id=ll.service_device_id
                LEFT JOIN guard.installations gi
                  ON gi.installation_external_id=ll.installation_id
                 AND gi.is_current=TRUE
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
        device_history_link = (
            f'<a class="strong-link" href="/multiguard/panel/device/{row["internal_installation_id"]}#service-history">HISTORIA I ALERTY →</a>'
            if row["internal_installation_id"] else ""
        )
        table_rows.append(
            f"""
            <tr>
              <td>{_panel_h(row['reception_number'])}</td>
              <td><span class="badge {'mg-gold' if edition=='PRO' else 'mg-red'}">{edition}</span></td>
              <td>{_panel_h(row['duration_months'])} mies.</td>
              <td>{_panel_h(row['release_channel'] or 'STABLE')}</td>
              <td>{_panel_h(row['lifecycle'])}</td>
              <td>{_panel_h(device)}<br>{device_history_link}</td>
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
        <section class="card panel-hero license-hero">
          <div class="section-head">
            <div>
              <div class="eyebrow">MULTI-SERVIS / UPRAWNIENIA KOMPUTERÓW</div>
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
