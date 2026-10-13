from __future__ import annotations

import base64
import calendar
import hashlib
import html
import json
import logging
import os
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, Form, HTTPException
from app.routers.multiguard_panel_theme import PANEL_CSS
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner, require_staff


logger = logging.getLogger(__name__)
router = APIRouter(tags=["multi-guard-license"])
_panel_security = HTTPBasic(auto_error=False)

_KEY_PATTERN = __import__("re").compile(
    r"^KG-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}-[A-Z2-9]{8}$"
)
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_CONFIG_FILE = os.getenv(
    "MULTIGUARD_CONFIG_FILE",
    "/opt/multiservis/config/multiguard-license.json",
)
_CONFIG_LOCK = threading.Lock()
_CONFIG_CACHE: dict[str, Any] | None = None


def _config() -> dict[str, Any]:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    with _CONFIG_LOCK:
        if _CONFIG_CACHE is not None:
            return _CONFIG_CACHE
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except FileNotFoundError:
            loaded = {}
        except Exception as exc:
            raise HTTPException(
                503, f"Błędny plik konfiguracji Multi-Guard: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise HTTPException(
                503, "Konfiguracja Multi-Guard musi być obiektem JSON."
            )
        _CONFIG_CACHE = loaded
        return loaded


def _setting(name: str, default: Any = "") -> Any:
    environment = os.getenv(name)
    if environment is not None and environment != "":
        return environment
    return _config().get(name, default)


class ProvisionRequest(BaseModel):
    request_id: str = Field(alias="requestId")
    nonce: str
    sent_at: str = Field(alias="sentAt")
    provisioning_token: str = Field(alias="provisioningToken")
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId", min_length=16, max_length=128)
    app_version: str = Field(alias="appVersion")

    model_config = {"populate_by_name": True}


class RefreshRequest(BaseModel):
    request_id: str = Field(alias="requestId")
    nonce: str
    sent_at: str = Field(alias="sentAt")
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId", min_length=16, max_length=128)
    installation_credential: str = Field(
        alias="installationCredential", min_length=32, max_length=512
    )
    app_version: str = Field(alias="appVersion")

    model_config = {"populate_by_name": True}


class AcceptedDocument(BaseModel):
    kind: str
    version: str
    sha256: str


class AcceptanceRequest(RefreshRequest):
    documents: list[AcceptedDocument]


class GenerateLicenseRequest(BaseModel):
    edition: str
    months: int
    release_channel: str = Field(default="STABLE", alias="releaseChannel")

    model_config = {"populate_by_name": True}


class DirectLicenseRequest(BaseModel):
    edition: str
    months: int
    release_channel: str = Field(default="STABLE", alias="releaseChannel")
    model_config = {"populate_by_name": True}


class ExtendLicenseRequest(BaseModel):
    operation_id: uuid.UUID = Field(alias="operationId")
    months: int
    payment_confirmed: bool = Field(default=False, alias="paymentConfirmed")

    model_config = {"populate_by_name": True}


class ReleaseChannelRequest(BaseModel):
    release_channel: str = Field(alias="releaseChannel")

    model_config = {"populate_by_name": True}


class DiscoveryRegisterRequest(BaseModel):
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId", min_length=16, max_length=128)
    discovery_credential: str = Field(
        alias="discoveryCredential", min_length=32, max_length=512
    )
    app_version: str = Field(default="", alias="appVersion", max_length=80)
    hostname: str = Field(default="", max_length=160)
    manufacturer: str = Field(default="", max_length=160)
    model: str = Field(default="", max_length=240)
    serial_number: str = Field(default="", alias="serialNumber", max_length=240)
    os_version: str = Field(default="", alias="osVersion", max_length=160)

    model_config = {"populate_by_name": True}


class DiscoveryAssignmentRequest(BaseModel):
    installation_id: str = Field(alias="installationId")
    device_id: str = Field(alias="deviceId", min_length=16, max_length=128)
    discovery_credential: str = Field(
        alias="discoveryCredential", min_length=32, max_length=512
    )

    model_config = {"populate_by_name": True}


class DiscoveryUninstallRequest(DiscoveryAssignmentRequest):
    """An unlicensed device can report removal using its discovery credential."""
    uninstall_event_id: uuid.UUID = Field(alias="uninstallEventId")
    app_version: str = Field(default="", alias="appVersion", max_length=80)


class WorkshopReportRequest(DiscoveryAssignmentRequest):
    """Explicit minimal workshop diagnostics, authenticated with discovery credential."""
    summary: dict[str, Any] = Field(default_factory=dict)


class AssignPendingInstallationRequest(BaseModel):
    reception_id: str = Field(alias="receptionId")
    edition: str
    months: int
    release_channel: str = Field(default="STABLE", alias="releaseChannel")

    model_config = {"populate_by_name": True}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _panel_escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _required_env(name: str) -> str:
    value = str(_setting(name, "")).strip()
    if not value:
        raise HTTPException(503, f"Brak konfiguracji {name}.")
    return value


def _keygate_base_url() -> str:
    return str(
        _setting(
            "MULTIGUARD_KEYGATE_BASE_URL",
            "https://license.multi-servis.pl",
        )
    ).strip().rstrip("/")


def _plan_slug(edition: str, months: int) -> str:
    key = (edition.upper(), months)
    defaults = {
        ("STANDARD", 3): "multi-guard-assist-3m",
        ("STANDARD", 6): "multi-guard-assist-6m",
        ("STANDARD", 12): "multi-guard-assist-12m",
        ("PRO", 3): "multi-guard-assist-pro-3m",
        ("PRO", 6): "multi-guard-assist-pro-6m",
        ("PRO", 12): "multi-guard-assist-pro-12m",
    }
    env_names = {
        ("STANDARD", 3): "MULTIGUARD_PLAN_STANDARD_3M",
        ("STANDARD", 6): "MULTIGUARD_PLAN_STANDARD_6M",
        ("STANDARD", 12): "MULTIGUARD_PLAN_STANDARD_12M",
        ("PRO", 3): "MULTIGUARD_PLAN_PRO_3M",
        ("PRO", 6): "MULTIGUARD_PLAN_PRO_6M",
        ("PRO", 12): "MULTIGUARD_PLAN_PRO_12M",
    }
    if key not in defaults:
        raise HTTPException(400, "Obsługiwane okresy to 3, 6 lub 12 miesięcy.")
    return str(_setting(env_names[key], defaults[key])).strip()


def _keygate_request(
    method: str,
    path: str,
    *,
    body: Any | None = None,
    admin: bool = False,
    ignore_404: bool = False,
) -> Any:
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if admin:
        headers["Authorization"] = (
            "Bearer " + _required_env("MULTIGUARD_KEYGATE_LICENSES_TOKEN")
        )

    data = (
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if body is not None
        else None
    )
    request = urllib.request.Request(
        _keygate_base_url() + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
            payload = json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if ignore_404 and exc.code == 404:
            return None
        detail = exc.read().decode("utf-8", errors="replace")[:1200]
        raise HTTPException(exc.code, f"KeyGate: {detail}") from exc
    except Exception as exc:
        raise HTTPException(502, f"Brak połączenia z KeyGate: {exc}") from exc

    if isinstance(payload, dict) and payload.get("success") is False:
        raise HTTPException(502, f"KeyGate odrzucił operację: {payload.get('error')}")
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _find_plan_id(edition: str, months: int) -> str:
    product_slug = _required_env("MULTIGUARD_KEYGATE_PRODUCT_SLUG")
    slug = _plan_slug(edition, months)
    data = _keygate_request(
        "GET",
        "/api/v1/products/"
        + urllib.parse.quote(product_slug, safe="")
        + "/plans",
    )
    plans = data.get("plans", []) if isinstance(data, dict) else []
    for plan in plans:
        if isinstance(plan, dict) and str(plan.get("slug", "")).strip() == slug:
            plan_id = str(plan.get("id", "")).strip()
            if plan_id:
                return plan_id
    raise HTTPException(503, f"KeyGate nie ma aktywnego planu {slug}.")


def _keygate_create_license(
    *,
    reception_number: str,
    edition: str,
    months: int,
) -> dict[str, Any]:
    product_id = _required_env("MULTIGUARD_KEYGATE_PRODUCT_ID")
    plan_id = _find_plan_id(edition, months)
    result = _keygate_request(
        "POST",
        "/api/v1/admin/licenses",
        admin=True,
        body={
            "product_id": product_id,
            "plan_id": plan_id,
            "email": str(
                _setting(
                    "MULTIGUARD_LICENSE_EMAIL",
                    "licencje@multi-servis.pl",
                )
            ).strip(),
            "notes": (
                f"Multi-Servis {reception_number}; okres licencji zaczyna się "
                "dopiero po akceptacji klienta."
            ),
            "external_workspace_id": reception_number,
        },
    )
    if not isinstance(result, dict):
        raise HTTPException(502, "KeyGate zwrócił nieprawidłową odpowiedź.")
    license_id = str(result.get("id", "")).strip()
    license_key = str(result.get("license_key", "")).strip().upper()
    if not license_id or not license_key:
        raise HTTPException(502, "KeyGate nie zwrócił ID lub klucza licencji.")
    result["_plan_id"] = plan_id
    result["_license_key"] = license_key
    return result


def _keygate_activate(
    license_key: str, device_id: str, installation_id: str
) -> dict[str, Any]:
    result = _keygate_request(
        "POST",
        "/api/v1/license/activate",
        body={
            "license_key": license_key,
            "identifier": device_id,
            "identifier_type": "device",
            "label": f"Multi-Guard {installation_id[:12]}",
        },
    )
    if not isinstance(result, dict):
        raise HTTPException(502, "KeyGate zwrócił nieprawidłową aktywację.")
    return result


def _keygate_license(license_id: str) -> dict[str, Any]:
    result = _keygate_request(
        "GET", f"/api/v1/admin/licenses/{license_id}", admin=True
    )
    if not isinstance(result, dict):
        raise HTTPException(502, "KeyGate zwrócił nieprawidłową licencję.")
    return result


def _keygate_reveal(license_id: str) -> str:
    result = _keygate_request(
        "GET", f"/api/v1/admin/licenses/{license_id}/key", admin=True
    )
    if isinstance(result, dict):
        value = result.get("license_key") or result.get("key")
        if value:
            return str(value).strip().upper()
    raise HTTPException(502, "KeyGate nie zwrócił klucza licencji.")


def _keygate_set_valid_until(license_id: str, valid_until: datetime) -> None:
    _keygate_request(
        "POST",
        f"/api/v1/admin/licenses/{license_id}/valid-until",
        admin=True,
        body={"valid_until": _iso(valid_until)},
    )


def _keygate_deactivate(license_key: str, device_id: str) -> None:
    _keygate_request(
        "POST",
        "/api/v1/license/deactivate",
        body={"license_key": license_key, "identifier": device_id},
        ignore_404=True,
    )


def _signing_key() -> Ed25519PrivateKey:
    encoded = _required_env("MULTIGUARD_SIGNING_SEED_B64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise HTTPException(
            503, "MULTIGUARD_SIGNING_SEED_B64 nie jest poprawnym Base64."
        ) from exc
    if len(raw) != 32:
        raise HTTPException(
            503, "MULTIGUARD_SIGNING_SEED_B64 musi zawierać dokładnie 32 bajty."
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key_b64() -> str:
    raw = _signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _signed_envelope(link: dict[str, Any]) -> dict[str, str]:
    payload_obj = {
        "schemaVersion": 1,
        "licenseId": link["keygate_license_id"],
        "serviceDeviceId": (str(link["service_device_id"]) if link.get("service_device_id") else None),
        "installationId": str(link["installation_id"] or ""),
        "deviceId": link.get("device_id") or "",
        "planCode": link["plan_code"],
        "releaseChannel": link.get("release_channel") or "STABLE",
        "lifecycle": link["lifecycle"],
        "validFrom": _iso(link.get("valid_from")),
        "validUntil": _iso(link.get("valid_until")),
        "acceptedAt": _iso(link.get("accepted_at")),
        "acceptedDocuments": link.get("accepted_documents") or [],
        "serverTime": _iso(_utcnow()),
    }
    payload = json.dumps(
        payload_obj,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    signature = _signing_key().sign(payload.encode("utf-8"))
    return {
        "payload": payload,
        "signatureB64": base64.b64encode(signature).decode("ascii"),
    }


_SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS guard;

CREATE TABLE IF NOT EXISTS guard.license_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reception_id UUID UNIQUE REFERENCES service.service_orders(id) ON DELETE CASCADE,
    reception_number TEXT NOT NULL UNIQUE,
    service_device_id UUID REFERENCES core.devices(id) ON DELETE RESTRICT,
    keygate_license_id TEXT NOT NULL UNIQUE,
    sale_kind TEXT NOT NULL DEFAULT 'SERVICE' CHECK (sale_kind IN ('SERVICE','DIRECT')),
    keygate_plan_id TEXT NOT NULL,
    license_key_hash TEXT NOT NULL UNIQUE,
    plan_code TEXT NOT NULL CHECK (plan_code IN ('multi_guard','multi_guard_pro')),
    duration_months INTEGER NOT NULL CHECK (duration_months IN (3,6,12)),
    release_channel TEXT NOT NULL DEFAULT 'STABLE'
        CHECK (release_channel IN ('STABLE','PILOT')),
    lifecycle TEXT NOT NULL DEFAULT 'UNASSIGNED'
        CHECK (lifecycle IN ('UNASSIGNED','SERVICE_TEST','PENDING_ACCEPTANCE','ACTIVE','EXPIRED','REVOKED')),
    installation_id UUID UNIQUE,
    device_id TEXT,
    credential_sha256 TEXT,
    app_version TEXT NOT NULL DEFAULT '',
    rebind_pending BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provisioned_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    rebind_requested_at TIMESTAMPTZ,
    accepted_documents JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_guard_license_links_device
    ON guard.license_links(service_device_id);
CREATE INDEX IF NOT EXISTS idx_guard_license_links_lifecycle
    ON guard.license_links(lifecycle);

-- Durable trace of KeyGate DIRECT creation attempts. Keep this independent
-- of licence_links: an external licence may exist after SQL rollback.
CREATE TABLE IF NOT EXISTS guard.direct_keygate_attempts (
    installation_id UUID PRIMARY KEY,
    workspace_reference TEXT NOT NULL UNIQUE,
    edition TEXT,
    duration_months INTEGER,
    release_channel TEXT,
    state TEXT NOT NULL CHECK (state IN ('STARTED','CREATED','RECONCILIATION_REQUIRED')),
    keygate_license_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE guard.direct_keygate_attempts ADD COLUMN IF NOT EXISTS edition TEXT;
ALTER TABLE guard.direct_keygate_attempts ADD COLUMN IF NOT EXISTS duration_months INTEGER;
ALTER TABLE guard.direct_keygate_attempts ADD COLUMN IF NOT EXISTS release_channel TEXT;
CREATE INDEX IF NOT EXISTS idx_guard_direct_keygate_attempts_state
    ON guard.direct_keygate_attempts(state);

CREATE TABLE IF NOT EXISTS guard.license_extensions (
    id UUID PRIMARY KEY,
    license_link_id UUID NOT NULL
        REFERENCES guard.license_links(id) ON DELETE RESTRICT,
    keygate_license_id TEXT NOT NULL,
    months INTEGER NOT NULL CHECK (months IN (3,6,12)),
    previous_valid_until TIMESTAMPTZ NOT NULL,
    new_valid_until TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('WEB','ANDROID')),
    payment_confirmed BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (new_valid_until > previous_valid_until)
);
CREATE INDEX IF NOT EXISTS idx_guard_license_extensions_license
    ON guard.license_extensions(license_link_id,created_at DESC);

CREATE TABLE IF NOT EXISTS guard.pending_installations (
    installation_id UUID PRIMARY KEY,
    device_id TEXT NOT NULL,
    discovery_credential_sha256 TEXT NOT NULL
        CHECK (length(discovery_credential_sha256)=64),
    app_version TEXT NOT NULL DEFAULT '',
    hostname TEXT,
    manufacturer TEXT,
    model TEXT,
    serial_number TEXT,
    os_version TEXT,
    status TEXT NOT NULL DEFAULT 'WAITING'
        CHECK (status IN ('WAITING','ASSIGNED','PROVISIONED','IGNORED','ARCHIVED','UNINSTALLED')),
    assigned_reception_id UUID REFERENCES service.service_orders(id) ON DELETE SET NULL,
    assigned_license_id TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_at TIMESTAMPTZ,
    provisioned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_pending_installations_status_seen
    ON guard.pending_installations(status,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_pending_installations_serial
    ON guard.pending_installations(serial_number)
    WHERE serial_number IS NOT NULL AND serial_number <> '';

-- OWNER only removes pending installations from the working queue.
-- Historical installation IDs stay in the database for audit/reinstall.
CREATE TABLE IF NOT EXISTS guard.discovery_uninstalls (
    event_id UUID PRIMARY KEY,
    installation_id UUID NOT NULL REFERENCES guard.pending_installations(installation_id),
    previously_assigned BOOLEAN NOT NULL DEFAULT FALSE,
    app_version TEXT NOT NULL DEFAULT '',
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_discovery_uninstalls_id
    ON guard.discovery_uninstalls(installation_id,reported_at DESC);

CREATE TABLE IF NOT EXISTS guard.pending_archive_events (
    id BIGSERIAL PRIMARY KEY,
    installation_id UUID NOT NULL
      REFERENCES guard.pending_installations(installation_id),
    previous_status TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'OWNER',
    reason TEXT NOT NULL DEFAULT '',
    archived_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_pending_archive_events_id
    ON guard.pending_archive_events(installation_id,archived_at DESC);

CREATE TABLE IF NOT EXISTS guard.workshop_grants (
    installation_id UUID PRIMARY KEY
        REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
    edition TEXT NOT NULL CHECK (edition IN ('STANDARD','PRO')),
    release_channel TEXT NOT NULL DEFAULT 'STABLE'
        CHECK (release_channel IN ('STABLE','PILOT')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    monitoring_profile TEXT NOT NULL DEFAULT 'OFF',
    associated_reception_id UUID REFERENCES service.service_orders(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE guard.workshop_grants ADD COLUMN IF NOT EXISTS monitoring_profile TEXT NOT NULL DEFAULT 'OFF';
ALTER TABLE guard.workshop_grants ADD COLUMN IF NOT EXISTS associated_reception_id UUID REFERENCES service.service_orders(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS guard.workshop_grant_audit (
    id BIGSERIAL PRIMARY KEY,
    installation_id UUID NOT NULL,
    before_state JSONB NOT NULL,
    after_state JSONB NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS guard.workshop_reports (
    installation_id UUID PRIMARY KEY
        REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS guard.workshop_report_history (
    id BIGSERIAL PRIMARY KEY,
    installation_id UUID NOT NULL
        REFERENCES guard.pending_installations(installation_id) ON DELETE CASCADE,
    summary JSONB NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_workshop_report_history_installation
    ON guard.workshop_report_history(installation_id,reported_at DESC);

CREATE TABLE IF NOT EXISTS guard.installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_device_id UUID REFERENCES core.devices(id) ON DELETE CASCADE,
    installation_external_id UUID NOT NULL UNIQUE,
    device_id_hash TEXT NOT NULL,
    credential_sha256 TEXT NOT NULL CHECK (length(credential_sha256)=64),
    license_id TEXT,
    plan_code TEXT NOT NULL DEFAULT 'STANDARD'
        CHECK (plan_code IN ('STANDARD','PRO')),
    lifecycle TEXT NOT NULL DEFAULT 'SERVICE_TEST'
        CHECK (lifecycle IN ('SERVICE_TEST','PENDING_ACCEPTANCE','ACTIVE','EXPIRED','REVOKED','UNKNOWN','ERROR')),
    valid_until TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    app_version TEXT,
    release_channel TEXT NOT NULL DEFAULT 'STABLE'
        CHECK (release_channel IN ('STABLE','PILOT')),
    health_level TEXT NOT NULL DEFAULT 'GREEN'
        CHECK (health_level IN ('GREEN','YELLOW','ORANGE','RED')),
    last_seen_at TIMESTAMPTZ,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_installations_device
    ON guard.installations(service_device_id, is_current, updated_at DESC);

CREATE TABLE IF NOT EXISTS guard.activation_events (
    id BIGSERIAL PRIMARY KEY,
    reception_id UUID REFERENCES service.service_orders(id) ON DELETE CASCADE,
    reception_number TEXT NOT NULL,
    keygate_license_id TEXT NOT NULL UNIQUE,
    edition TEXT NOT NULL CHECK (edition IN ('STANDARD','PRO')),
    duration_months INTEGER NOT NULL CHECK (duration_months IN (3,6,12)),
    valid_until TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_activation_events_created
    ON guard.activation_events(id DESC);

ALTER TABLE guard.license_links ALTER COLUMN reception_id DROP NOT NULL;
ALTER TABLE guard.license_links ALTER COLUMN service_device_id DROP NOT NULL;
ALTER TABLE guard.license_links
    ADD COLUMN IF NOT EXISTS sale_kind TEXT NOT NULL DEFAULT 'SERVICE'
        CHECK (sale_kind IN ('SERVICE','DIRECT'));
ALTER TABLE guard.installations ALTER COLUMN service_device_id DROP NOT NULL;
ALTER TABLE guard.activation_events ALTER COLUMN reception_id DROP NOT NULL;
ALTER TABLE guard.license_links
    ADD COLUMN IF NOT EXISTS release_channel TEXT NOT NULL DEFAULT 'STABLE';
ALTER TABLE guard.installations
    ADD COLUMN IF NOT EXISTS release_channel TEXT NOT NULL DEFAULT 'STABLE';
-- Migrate the CHECK constraint on existing PostgreSQL installations.
ALTER TABLE guard.pending_installations
    DROP CONSTRAINT IF EXISTS pending_installations_status_check;
ALTER TABLE guard.pending_installations
    ADD CONSTRAINT pending_installations_status_check
    CHECK (status IN ('WAITING','ASSIGNED','PROVISIONED','IGNORED','ARCHIVED','UNINSTALLED'));
"""


def _ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with engine.begin() as connection:
            for statement in [s.strip() for s in _SCHEMA_SQL.split(";") if s.strip()]:
                connection.execute(text(statement))
        _SCHEMA_READY = True


def _link_by_reception_id(reception_id: uuid.UUID) -> dict[str, Any] | None:
    _ensure_schema()
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT * FROM guard.license_links WHERE reception_id=:id LIMIT 1"),
            {"id": reception_id},
        ).mappings().first()
    return dict(row) if row else None


def _link_by_key(license_key: str) -> dict[str, Any] | None:
    _ensure_schema()
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT * FROM guard.license_links "
                "WHERE license_key_hash=:h LIMIT 1"
            ),
            {"h": _hash(license_key.strip().upper())},
        ).mappings().first()
    return dict(row) if row else None


def _link_by_installation(installation_id: uuid.UUID) -> dict[str, Any] | None:
    _ensure_schema()
    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT * FROM guard.license_links "
                "WHERE installation_id=:id LIMIT 1"
            ),
            {"id": installation_id},
        ).mappings().first()
    return dict(row) if row else None



def _pending_installation(
    installation_id: uuid.UUID,
) -> dict[str, Any] | None:
    _ensure_schema()
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT *
                FROM guard.pending_installations
                WHERE installation_id=:installation_id
                LIMIT 1
                """
            ),
            {"installation_id": installation_id},
        ).mappings().first()
    return dict(row) if row else None


def _authenticate_pending(
    installation_id: str,
    device_id: str,
    discovery_credential: str,
) -> dict[str, Any]:
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy installationId.") from exc

    pending = _pending_installation(iid)
    if not pending:
        raise HTTPException(404, "Instalacja nie jest zarejestrowana w kolejce.")

    if not secrets.compare_digest(
        str(pending["device_id"]),
        device_id.strip(),
    ):
        raise HTTPException(401, "Identyfikator urządzenia nie pasuje do instalacji.")

    if not secrets.compare_digest(
        str(pending["discovery_credential_sha256"]),
        _hash(discovery_credential),
    ):
        raise HTTPException(401, "Nieprawidłowe poświadczenie wykrywania instalacji.")

    return pending


def _workshop_grant(installation_id: uuid.UUID) -> dict[str, Any] | None:
    _ensure_schema()
    with engine.connect() as connection:
        row = connection.execute(text("""
            SELECT * FROM guard.workshop_grants
            WHERE installation_id=:id
        """), {"id": installation_id}).mappings().first()
    return dict(row) if row else None


def _signed_workshop_grant(pending: dict[str, Any],
                           grant: dict[str, Any]) -> dict[str, str]:
    """Ephemeral, installation-bound entitlement; never touches KeyGate.

    Workshop permission is unlimited while offline. The client must adopt a
    separately signed UNKNOWN payload after a successful server revocation
    check; loss of Internet is never treated as a revocation.
    """
    plan = ("multi_guard_pro" if grant["edition"] == "PRO" else "multi_guard")
    payload = json.dumps({
        "schemaVersion": 1,
        "licenseId": "WORKSHOP-" + str(pending["installation_id"]),
        "serviceDeviceId": None,
        "installationId": str(pending["installation_id"]),
        "deviceId": str(pending["device_id"]),
        "planCode": plan,
        "releaseChannel": grant["release_channel"],
        "lifecycle": "WORKSHOP" if grant["enabled"] else "UNKNOWN",
        "validFrom": None,
        "validUntil": None,
        "acceptedAt": None,
        "acceptedDocuments": [],
        "serverTime": _iso(_utcnow()),
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    signature = _signing_key().sign(payload.encode("utf-8"))
    return {
        "payload": payload,
        "signatureB64": base64.b64encode(signature).decode("ascii"),
    }


def _set_workshop_grant(
    installation_id: uuid.UUID,
    edition: str,
    channel: str,
    enabled: bool,
) -> dict[str, Any]:
    _ensure_schema()
    edition = edition.strip().upper()
    channel = channel.strip().upper()
    if edition not in {"STANDARD", "PRO"}:
        raise HTTPException(400, "Edycja musi być Standard albo Pro.")
    if channel not in {"STABLE", "PILOT"}:
        raise HTTPException(400, "Kanał musi być stabilny albo Beta.")
    with engine.begin() as con:
        pending = con.execute(text("""
            SELECT installation_id,status FROM guard.pending_installations
            WHERE installation_id=:id FOR UPDATE
        """), {"id":installation_id}).mappings().first()
        if not pending:
            raise HTTPException(404, "Instalacja nie została zgłoszona do Multi-Servis.")
        if str(pending["status"]) in ("ASSIGNED", "PROVISIONED"):
            raise HTTPException(409,
                "Komputer ma już przypisaną licencję klienta. "
                "Nie można równocześnie uruchomić trybu serwisowego.")
        existing = con.execute(text("""
            SELECT edition,release_channel,enabled,monitoring_profile
            FROM guard.workshop_grants
            WHERE installation_id=:id FOR UPDATE
        """), {"id": installation_id}).mappings().first()
        previous = dict(existing) if existing else None
        current = {"edition":edition,"release_channel":channel,"enabled":enabled}
        con.execute(text("""
            INSERT INTO guard.workshop_grants(
                installation_id,edition,release_channel,enabled
            ) VALUES (:id,:edition,:channel,:enabled)
            ON CONFLICT (installation_id) DO UPDATE
              SET edition=EXCLUDED.edition,
                  release_channel=EXCLUDED.release_channel,
                  enabled=EXCLUDED.enabled,
                  monitoring_profile='OFF',
                  updated_at=now()
        """), {"id":installation_id,"edition":edition,"channel":channel,"enabled":enabled})
        if previous != current:
            con.execute(text("""
                INSERT INTO guard.workshop_grant_audit(
                    installation_id,before_state,after_state
                ) VALUES (:id,CAST(:before AS jsonb),CAST(:after AS jsonb))
            """), {"id":installation_id,
                    "before":json.dumps(previous),
                    "after":json.dumps(current)})
    return current


def _pending_public(
    row: dict[str, Any],
    *,
    match_score: int = 0,
) -> dict[str, Any]:
    last_seen = row.get("last_seen_at")
    online = False
    if last_seen:
        try:
            online = (_utcnow() - last_seen).total_seconds() <= 300
        except Exception:
            online = False

    installation_id = str(row["installation_id"])
    return {
        "installationId": installation_id,
        "shortId": "MG-" + installation_id.replace("-", "")[:8].upper(),
        "deviceId": str(row.get("device_id") or ""),
        "appVersion": str(row.get("app_version") or ""),
        "hostname": str(row.get("hostname") or ""),
        "manufacturer": str(row.get("manufacturer") or ""),
        "model": str(row.get("model") or ""),
        "serialNumber": str(row.get("serial_number") or ""),
        "osVersion": str(row.get("os_version") or ""),
        "status": str(row.get("status") or "WAITING"),
        "online": online,
        "firstSeenAt": _iso(row.get("first_seen_at")),
        "lastSeenAt": _iso(last_seen),
        "assignedReceptionId": (
            str(row["assigned_reception_id"])
            if row.get("assigned_reception_id")
            else None
        ),
        "assignedLicenseId": row.get("assigned_license_id"),
        "matchScore": int(match_score),
        "recommended": int(match_score) >= 80,
    }


def _assign_pending_to_reception(
    installation_id: uuid.UUID,
    reception_id: uuid.UUID,
    edition: str,
    months: int,
    release_channel: str,
) -> dict[str, Any]:
    pending = _pending_installation(installation_id)
    if not pending:
        raise HTTPException(404, "Nie znaleziono oczekującej instalacji Multi-Guard.")
    if pending["status"] == "PROVISIONED":
        raise HTTPException(409, "Ta instalacja Multi-Guard jest już powiązana.")

    reception = _reception(reception_id)
    existing = _link_by_reception_id(reception_id)

    edition = edition.strip().upper()
    release_channel = release_channel.strip().upper()
    if edition not in {"STANDARD", "PRO"}:
        raise HTTPException(400, "Edycja musi być STANDARD albo PRO.")
    if months not in {3, 6, 12}:
        raise HTTPException(400, "Okres musi wynosić 3, 6 albo 12 miesięcy.")
    if release_channel not in {"STABLE", "PILOT"}:
        raise HTTPException(400, "Kanał aktualizacji musi być STABLE albo PILOT.")

    if existing:
        existing_edition = (
            "PRO"
            if existing["plan_code"] == "multi_guard_pro"
            else "STANDARD"
        )
        if (
            existing_edition != edition
            or int(existing["duration_months"]) != int(months)
            or str(existing.get("release_channel") or "STABLE").upper()
            != release_channel
        ):
            raise HTTPException(
                409,
                "Zlecenie ma już inną licencję Multi-Guard. "
                "Użyj parametrów zapisanej licencji albo zmień ją osobno.",
            )
        if (
            existing.get("installation_id")
            and existing["installation_id"] != installation_id
        ):
            raise HTTPException(
                409,
                "Licencja tego zlecenia jest już przypisana do innej instalacji.",
            )
        link = existing
    else:
        link, _ = _generate_license_link(
            reception_id=reception_id,
            edition=edition,
            months=months,
            release_channel=release_channel,
        )

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE guard.pending_installations
                SET
                    status='ASSIGNED',
                    assigned_reception_id=:reception_id,
                    assigned_license_id=:license_id,
                    assigned_at=COALESCE(assigned_at,now()),
                    updated_at=now()
                WHERE installation_id=:installation_id
                """
            ),
            {
                "reception_id": reception["id"],
                "license_id": link["keygate_license_id"],
                "installation_id": installation_id,
            },
        )
        # Paid rights and revocation of previous service rights must commit
        # atomically. Otherwise a backend failure could leave both valid.
        connection.execute(text("""
            UPDATE guard.workshop_grants
               SET enabled=FALSE,monitoring_profile='OFF',updated_at=now()
             WHERE installation_id=:iid AND enabled=TRUE
        """),{"iid":installation_id})

    return link



def _assign_direct_customer_license(
    installation_id: uuid.UUID, edition: str, months: int, channel: str
) -> dict[str, Any]:
    """Assign paid client rights without creating a repair order."""
    edition = edition.strip().upper()
    channel = channel.strip().upper()
    if edition not in {"STANDARD", "PRO"} or months not in {3, 6, 12}:
        raise HTTPException(400, "Wybierz Standard/Pro i okres 3, 6 lub 12 miesięcy.")
    if channel not in {"STABLE", "PILOT"}:
        raise HTTPException(400, "Kanał musi być Stabilna albo Beta.")
    _ensure_schema()
    with engine.begin() as con:
        pending = con.execute(text("""
            SELECT * FROM guard.pending_installations
            WHERE installation_id=:id
        """), {"id": installation_id}).mappings().first()
        if pending is None:
            raise HTTPException(404, "Komputer nie został zarejestrowany.")
        if pending["status"] != "WAITING" or pending["assigned_license_id"]:
            raise HTTPException(409, "Komputer ma już przypisaną licencję.")
        existing = con.execute(text("""
            SELECT id FROM guard.license_links
            WHERE installation_id=:id LIMIT 1
        """), {"id": installation_id}).first()
        if existing:
            raise HTTPException(409, "Istnieje już powiązanie tej instalacji.")
    # A KeyGate workspace reference identifies the installation, not
    # an imaginary repair order. No service.order record is created.
    reference = "MG-DIRECT-" + installation_id.hex
    # A separately committed attempt survives rollback of this transaction.
    # Duplicate submissions fail closed until an OWNER reconciles KeyGate.
    with engine.begin() as audit:
        reserved = audit.execute(text("""
            INSERT INTO guard.direct_keygate_attempts(
                installation_id,workspace_reference,edition,duration_months,release_channel,state
            ) VALUES (:installation_id,:reference,:edition,:months,:channel,'STARTED')
            ON CONFLICT (installation_id) DO NOTHING
            RETURNING installation_id
        """), {"installation_id":installation_id,"reference":reference,
            "edition":edition,"months":months,"channel":channel}).scalar_one_or_none()
    if reserved is None:
        raise HTTPException(
            409, "Poprzednia próba w KeyGate wymaga sprawdzenia przez OWNER "
                 "przed ponownym utworzeniem licencji."
        )
    try:
        created = _keygate_create_license(
            reception_number=reference, edition=edition, months=months,
        )
    except Exception:
        # An interrupted HTTP call can succeed remotely. Never auto-retry.
        # Keep the original KeyGate error even if the audit DB is down:
        # STARTED is already durable and blocks repeated creation.
        try:
            with engine.begin() as audit:
                audit.execute(text("""
                    UPDATE guard.direct_keygate_attempts
                    SET state='RECONCILIATION_REQUIRED',updated_at=now()
                    WHERE installation_id=:id
                """), {"id":installation_id})
        except Exception:
            logger.exception("Could not update ambiguous KeyGate attempt audit")
        raise
    with engine.begin() as audit:
        audit.execute(text("""
            UPDATE guard.direct_keygate_attempts
            SET state='CREATED',keygate_license_id=:license_id,updated_at=now()
            WHERE installation_id=:id
        """), {"id":installation_id,"license_id":str(created["id"])})
    try:
        with engine.begin() as con:
            lic = con.execute(text("""
                INSERT INTO guard.license_links(
                    reception_id,reception_number,service_device_id,
                    sale_kind,installation_id,
                    keygate_license_id,keygate_plan_id,license_key_hash,
                    plan_code,duration_months,release_channel,lifecycle
                ) VALUES (
                    NULL,:reference,NULL,'DIRECT',:installation_id,
                    :license_id,:plan_id,:key_hash,:plan,:months,:channel,'UNASSIGNED'
                ) RETURNING *
            """), {
                "reference":reference, "installation_id":installation_id,
                "license_id":str(created["id"]), "plan_id":created["_plan_id"],
                "key_hash":_hash(created["_license_key"]),
                "plan":"multi_guard_pro" if edition=="PRO" else "multi_guard",
                "months":months,"channel":channel,
            }).mappings().one()
            updated = con.execute(text("""
                UPDATE guard.pending_installations SET
                    status='ASSIGNED',assigned_reception_id=NULL,
                    assigned_license_id=:license_id,
                    assigned_at=now(),updated_at=now()
                WHERE installation_id=:id
                  AND status='WAITING'
                  AND assigned_license_id IS NULL
                RETURNING installation_id
            """), {"license_id":lic["keygate_license_id"],"id":installation_id}).scalar_one_or_none()
            if updated is None:
                raise RuntimeError("Instalacja zmieniła status podczas operacji KeyGate.")
            con.execute(text("""
                UPDATE guard.workshop_grants
                SET enabled=FALSE,monitoring_profile='OFF',updated_at=now()
                WHERE installation_id=:id AND enabled=TRUE
            """), {"id":installation_id})
    except Exception:
        # KeyGate has already acknowledged creation. The SQL transaction
        # rolls back, but the external licence cannot be rolled back here.
        # Do NOT silently retry: doing so can generate duplicate licences.
        try:
            with engine.begin() as audit:
                audit.execute(text("""
                    UPDATE guard.direct_keygate_attempts
                    SET state='RECONCILIATION_REQUIRED',updated_at=now()
                    WHERE installation_id=:id
                """), {"id":installation_id})
        except Exception:
            logger.exception("Could not persist DIRECT reconciliation state")
        logger.exception(
            "Multi-Guard DIRECT needs manual KeyGate reconciliation: "
            "workspace=%s external_license_id=%s",
            reference, str(created.get("id", "")),
        )
        raise HTTPException(
            503,
            "Nie zakończono przypisania licencji. Wymagana weryfikacja "
            "w KeyGate przed ponowieniem operacji.",
        ) from None
    return _normalize_link(dict(lic))


def _handover_direct_customer(installation_id: uuid.UUID) -> dict[str, Any]:
    """Require customer document acceptance before starting paid time."""
    _ensure_schema()
    with engine.begin() as con:
        pending = con.execute(text("""
            SELECT assigned_license_id FROM guard.pending_installations
            WHERE installation_id=:id FOR UPDATE
        """), {"id":installation_id}).mappings().first()
        if not pending or not pending["assigned_license_id"]:
            raise HTTPException(404, "Nie znaleziono przypisanej licencji.")
        link = con.execute(text("""
            SELECT * FROM guard.license_links
            WHERE keygate_license_id=:license_id AND sale_kind='DIRECT'
                  AND installation_id=:installation_id
            FOR UPDATE
        """), {"license_id":pending["assigned_license_id"],
                "installation_id":installation_id}).mappings().first()
        if not link:
            raise HTTPException(404, "Brak bezpośredniej licencji klienta.")
        if link["lifecycle"] in {"REVOKED", "EXPIRED"}:
            raise HTTPException(409, "Licencja została cofnięta lub wygasła.")
        if link["lifecycle"] in {"ACTIVE", "PENDING_ACCEPTANCE"}:
            return _normalize_link(dict(link))
        updated = con.execute(text("""
            UPDATE guard.license_links
            SET lifecycle='PENDING_ACCEPTANCE',
                approved_at=COALESCE(approved_at,now()),updated_at=now()
            WHERE id=:id RETURNING *
        """), {"id":link["id"]}).mappings().one()
        result = _normalize_link(dict(updated))
        _update_installation_mirror(con,result)
        return result


def _reception(reception_id: uuid.UUID) -> dict[str, Any]:
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT so.id, so.reception_number, so.device_id, so.status
                FROM service.service_orders so
                WHERE so.id=:id
                LIMIT 1
                """
            ),
            {"id": reception_id},
        ).mappings().first()
    if not row:
        raise HTTPException(404, "Nie znaleziono zlecenia.")
    if not row["device_id"]:
        raise HTTPException(409, "Zlecenie nie ma przypisanego urządzenia.")
    return dict(row)


def _reception_by_number(reception_number: str) -> dict[str, Any]:
    value = reception_number.strip()
    if not value:
        raise HTTPException(400, "Numer zlecenia jest wymagany.")
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT so.id, so.reception_number, so.device_id, so.status
                FROM service.service_orders so
                WHERE upper(so.reception_number)=upper(:number)
                LIMIT 1
                """
            ),
            {"number": value},
        ).mappings().first()
    if not row:
        raise HTTPException(404, "Nie znaleziono zlecenia o podanym numerze.")
    if not row["device_id"]:
        raise HTTPException(409, "Zlecenie nie ma przypisanego urządzenia.")
    return dict(row)


def _panel_auth(
    credentials: HTTPBasicCredentials | None = Depends(_panel_security),
) -> None:
    expected_user = _required_env("MULTIGUARD_PANEL_USER")
    expected_password = _required_env("MULTIGUARD_PANEL_PASSWORD")
    if (
        credentials is None
        or not secrets.compare_digest(credentials.username, expected_user)
        or not secrets.compare_digest(credentials.password, expected_password)
    ):
        raise HTTPException(
            status_code=401,
            detail="Nieprawidłowy login lub hasło.",
            headers={"WWW-Authenticate": 'Basic realm="Multi-Servis Licencje"'},
        )


def _panel_html(body: str) -> str:
    """One owner workspace. Gold + crimson reference V12 product editions,
    but the web console has no Standard/Pro editions of its own.
    """
    return f"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Multi-Servis | Centrum zarządzania</title>
<style>{PANEL_CSS}</style>
</head>
<body>
<div class="workspace-shell">
  <aside class="workspace-sidebar" aria-label="Nawigacja Multi-Servis">
    <a class="brand-home" href="/multiguard/panel/dashboard">
      <span class="brand-emblem" aria-hidden="true">
        <img alt="" width="48" height="48" class="owner-approved-shield" src="data:image/png;base64,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">
      </span>
      <span><span class="brand-name"><span class="brand-multi">Multi</span><span class="brand-servis">-Servis</span></span>
      <span class="brand-caption">CENTRUM ZARZĄDZANIA</span></span>
    </a>
    <p class="nav-group-label">Panel właściciela</p>
    <nav aria-label="Sekcje panelu">
      <a href="/multiguard/panel/dashboard"><span class="nav-icon" aria-hidden="true">⌂</span>Pulpit</a>
      <a href="/multiguard/panel/computers"><span class="nav-icon" aria-hidden="true">▤</span>Komputery</a>
      <a href="/multiguard/panel/service"><span class="nav-icon" aria-hidden="true">◇</span>Zlecenia serwisowe</a>
      <a href="/multiguard/panel/statistics"><span class="nav-icon" aria-hidden="true">▥</span>Statystyki</a>
      <a href="/multiguard/panel/telemetry"><span class="nav-icon" aria-hidden="true">⌁</span>Telemetria i błędy</a>
      <a href="/multiguard/panel/licenses"><span class="nav-icon" aria-hidden="true">▣</span>Licencje</a>
      <a href="/multiguard/panel/versions"><span class="nav-icon" aria-hidden="true">≡</span>Historia wersji</a>
      <a href="/multiguard/panel/settings"><span class="nav-icon" aria-hidden="true">⚙</span>Ustawienia</a>
    </nav>
    <p class="nav-group-label">Szybkie działania</p>
    <nav aria-label="Działania">
      <a href="/multiguard/panel"><span class="nav-icon" aria-hidden="true">＋</span>Nowa licencja</a>
    </nav>
  </aside>
  <div class="workspace-content">
    <header class="workspace-topbar">
      <div>
        <span class="topbar-kicker">MULTI-SERVIS · PANEL WWW</span>
        <span class="topbar-title">Sprzęt · naprawy · licencje · diagnostyka</span>
      </div>
      <div class="topbar-owner" aria-label="Panel właściciela">Dostęp właściciela</div>
    </header>
    <main id="content">{body}</main>
  </div>
</div>
<script>
(() => {{
  const path = window.location.pathname;
  const links = document.querySelectorAll('.workspace-sidebar nav a');
  for (const link of links) {{
    const target = new URL(link.href, window.location.origin);
    const chosen = target.pathname === path ||
      (target.pathname === '/multiguard/panel/computers' && path.startsWith('/multiguard/panel/device/')) ||
      (target.pathname === '/multiguard/panel/service' && path.startsWith('/multiguard/panel/service/')) ||
      (target.pathname === '/multiguard/panel/telemetry' && path.startsWith('/multiguard/panel/telemetry/'));
    // Distinct sections, exactly one active navigation item.
    if (chosen) link.setAttribute('aria-current', 'page');
  }}
}})();
  // SERVICE is deliberately two-step; changing the period must never
  // silently grant an unmetered workshop entitlement.
  for (const form of document.querySelectorAll('form[data-owner-service-form]')) {{
    const period=form.querySelector('select[name="months"]');
    const approval=form.querySelector('input[name="service_confirm"]');
    const submit=form.querySelector('[data-owner-service-submit]');
    const dialog=form.querySelector('.owner-service-confirm-dialog');
    const normalLabel=submit.textContent.trim();
    const refresh=()=>{{
      approval.value='';
      submit.textContent=period.value==='SERVICE' ? 'WŁĄCZ TRYB SERWISOWY' : normalLabel;
    }};
    period.addEventListener('change',refresh);
    refresh();
    form.addEventListener('submit',event=>{{
      if(period.value==='SERVICE' && approval.value!=='CONFIRM_WORKSHOP'){{
        event.preventDefault();
        dialog.showModal();
      }}
    }});
    dialog.querySelector('[data-service-approve]').addEventListener('click',()=>{{
      approval.value='CONFIRM_WORKSHOP';
      dialog.close();
      form.requestSubmit();
    }});
  }}

  // The profile selector only becomes active after explicit opt-in.
  // OFF is the default even if the owner leaves all fields untouched.
  for (const form of document.querySelectorAll('form[data-owner-monitor-form]')) {{
    const toggle=form.querySelector('[data-owner-monitor-toggle]');
    const profile=form.querySelector('[data-owner-monitor-profile]');
    const state=form.querySelector('[data-owner-monitor-state]');
    const save=form.querySelector('[data-owner-monitor-save]');
    if (!toggle || !profile) continue;
    const initiallyEnabled=toggle.checked;
    const initialProfile=profile.value;
    const update=()=>{{
      profile.disabled=!toggle.checked;
      if(toggle.checked && !['STANDARD','OBSERVATION','INTENSIVE'].includes(profile.value)){{
        profile.value='STANDARD';
      }}
      const changed=toggle.checked!==initiallyEnabled ||
        (toggle.checked && profile.value!==initialProfile);
      if(state) state.textContent=changed
        ? (toggle.checked ? 'Włączone · niezapisane' : 'Wyłączone · niezapisane')
        : (toggle.checked ? 'Włączone' : 'Wyłączone');
      if(save) save.disabled=!changed;
    }};
    toggle.addEventListener('change',update);
    profile.addEventListener('change',update);
    update();
  }}

  // OWNER-only live suggestions (3 digits): no orders are revealed on the
  // public discovery API. A chosen datalist value becomes the exact order ID.
  for (const input of document.querySelectorAll('input[data-owner-order-suggest]')) {{
    const list=document.getElementById(input.getAttribute('list'));
    if(!list)continue;
    let timer;
    input.addEventListener('input',()=>{{
      clearTimeout(timer);
      list.replaceChildren();
      const query=input.value.replace(/\D/g,'');
      if(query.length<3)return;
      timer=setTimeout(async()=>{{
        try{{
          const response=await fetch(
            '/multiguard/panel/service-orders/suggest?q='+encodeURIComponent(query),
            {{credentials:'same-origin',cache:'no-store'}}
          );
          if(!response.ok)return;
          const result=await response.json();
          if(input.value.replace(/\D/g,'')!==query)return;
          for(const item of result.results||[]){{
            const option=document.createElement('option');
            option.value=item.number;
            option.label=item.label;
            list.appendChild(option);
          }}
        }}catch(_err){{ /* typing remains possible without connectivity */ }}
      }},240);
    }});
  }}

</script>
</body>
</html>"""


def _accepted_documents(link: dict[str, Any]) -> list[dict[str, Any]]:
    value = link.get("accepted_documents") or []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return []
    return list(value) if isinstance(value, list) else []


def _normalize_link(link: dict[str, Any]) -> dict[str, Any]:
    link = dict(link)
    link["accepted_documents"] = _accepted_documents(link)
    return link


def _required_documents() -> list[dict[str, str]]:
    source = _setting("MULTIGUARD_REQUIRED_DOCUMENTS", [])
    if isinstance(source, str):
        raw = source.strip()
        if not raw:
            return []
        try:
            source = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                503, "MULTIGUARD_REQUIRED_DOCUMENTS ma błędny JSON."
            ) from exc
    if not source:
        return []
    if not isinstance(source, list):
        raise HTTPException(503, "Dokumenty Multi-Guard muszą być tablicą.")

    result: list[dict[str, str]] = []
    for item in source:
        if not isinstance(item, dict):
            raise HTTPException(503, "Dokument Multi-Guard ma błędny format.")
        kind = str(item.get("kind", "")).strip()
        version = str(item.get("version", "")).strip()
        title = str(item.get("title", "")).strip()
        content = str(item.get("content_markdown", ""))
        if not all((kind, version, title, content)):
            raise HTTPException(503, "Dokument Multi-Guard jest niekompletny.")
        result.append(
            {
                "kind": kind,
                "version": version,
                "title": title,
                "contentMarkdown": content,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )
    return result


def _authenticate_installation(req: RefreshRequest) -> dict[str, Any]:
    try:
        iid = uuid.UUID(req.installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy installationId.") from exc
    link = _link_by_installation(iid)
    if not link:
        raise HTTPException(404, "Nie znaleziono instalacji Multi-Guard.")
    link = _normalize_link(link)
    if (link.get("device_id") or "") != req.device_id:
        raise HTTPException(403, "Licencja jest przypisana do innego komputera.")
    expected = link.get("credential_sha256") or ""
    actual = _hash(req.installation_credential)
    if not expected or not secrets.compare_digest(expected, actual):
        raise HTTPException(403, "Nieprawidłowe poświadczenie instalacji.")
    return link


def _update_installation_mirror(connection, link: dict[str, Any]) -> None:
    if not link.get("installation_id") or not link.get("credential_sha256"):
        return
    plan = "PRO" if link["plan_code"] == "multi_guard_pro" else "STANDARD"
    lifecycle = link["lifecycle"]
    if lifecycle == "UNASSIGNED":
        lifecycle = "SERVICE_TEST"
    connection.execute(
        text(
            """
            UPDATE guard.installations
            SET is_current=FALSE, updated_at=now()
            WHERE service_device_id=:service_device_id
              AND installation_external_id<>:installation_id
              AND is_current=TRUE
            """
        ),
        {
            "service_device_id": link["service_device_id"],
            "installation_id": link["installation_id"],
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO guard.installations (
                service_device_id, installation_external_id, device_id_hash,
                credential_sha256, license_id, plan_code, lifecycle,
                valid_until, accepted_at, app_version, release_channel, is_current, updated_at
            )
            VALUES (
                :service_device_id, :installation_id, :device_id,
                :credential_sha256, :license_id, :plan_code, :lifecycle,
                :valid_until, :accepted_at, :app_version, :release_channel, TRUE, now()
            )
            ON CONFLICT (installation_external_id) DO UPDATE SET
                service_device_id=EXCLUDED.service_device_id,
                device_id_hash=EXCLUDED.device_id_hash,
                credential_sha256=EXCLUDED.credential_sha256,
                license_id=EXCLUDED.license_id,
                plan_code=EXCLUDED.plan_code,
                lifecycle=EXCLUDED.lifecycle,
                valid_until=EXCLUDED.valid_until,
                accepted_at=EXCLUDED.accepted_at,
                app_version=EXCLUDED.app_version,
                release_channel=EXCLUDED.release_channel,
                is_current=TRUE,
                updated_at=now()
            """
        ),
        {
            "service_device_id": link["service_device_id"],
            "installation_id": link["installation_id"],
            "device_id": link.get("device_id") or "",
            "credential_sha256": link["credential_sha256"],
            "license_id": link["keygate_license_id"],
            "plan_code": plan,
            "lifecycle": lifecycle,
            "valid_until": link.get("valid_until"),
            "accepted_at": link.get("accepted_at"),
            "app_version": link.get("app_version") or "",
            "release_channel": link.get("release_channel") or "STABLE",
        },
    )


def _public_status(link: dict[str, Any] | None) -> dict[str, Any]:
    if not link:
        return {"configured": False, "installed": False}
    link = _normalize_link(link)
    return {
        "configured": True,
        "installed": bool(link.get("installation_id")),
        "licenseId": link["keygate_license_id"],
        "serviceDeviceId": (str(link["service_device_id"]) if link.get("service_device_id") else None),
        "receptionNumber": link["reception_number"],
        "edition": "PRO" if link["plan_code"] == "multi_guard_pro" else "STANDARD",
        "planCode": link["plan_code"],
        "durationMonths": link["duration_months"],
        "releaseChannel": link.get("release_channel") or "STABLE",
        "lifecycle": link["lifecycle"],
        "appVersion": link.get("app_version") or "",
        "validFrom": _iso(link.get("valid_from")),
        "validUntil": _iso(link.get("valid_until")),
        "acceptedAt": _iso(link.get("accepted_at")),
        "rebindPending": bool(link.get("rebind_pending")),
    }



@router.post("/v1/multi-guard/discovery/register")
def discovery_register(req: DiscoveryRegisterRequest):
    _ensure_schema()
    try:
        installation_id = uuid.UUID(req.installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy installationId.") from exc

    credential_hash = _hash(req.discovery_credential)
    now = _utcnow()

    with engine.begin() as connection:
        existing = connection.execute(
            text(
                """
                SELECT *
                FROM guard.pending_installations
                WHERE installation_id=:installation_id
                FOR UPDATE
                """
            ),
            {"installation_id": installation_id},
        ).mappings().first()

        if existing:
            if not secrets.compare_digest(
                str(existing["device_id"]),
                req.device_id.strip(),
            ):
                raise HTTPException(
                    409,
                    "installationId jest już powiązany z innym urządzeniem.",
                )
            if not secrets.compare_digest(
                str(existing["discovery_credential_sha256"]),
                credential_hash,
            ):
                raise HTTPException(
                    401,
                    "Nieprawidłowe poświadczenie wykrywania instalacji.",
                )

            row = connection.execute(
                text(
                    """
                    UPDATE guard.pending_installations
                    SET
                        app_version=:app_version,
                        hostname=NULLIF(:hostname,''),
                        manufacturer=NULLIF(:manufacturer,''),
                        model=NULLIF(:model,''),
                        serial_number=NULLIF(:serial_number,''),
                        os_version=NULLIF(:os_version,''),
                        last_seen_at=:now,
                        updated_at=:now
                    WHERE installation_id=:installation_id
                    RETURNING *
                    """
                ),
                {
                    "app_version": req.app_version.strip(),
                    "hostname": req.hostname.strip(),
                    "manufacturer": req.manufacturer.strip(),
                    "model": req.model.strip(),
                    "serial_number": req.serial_number.strip(),
                    "os_version": req.os_version.strip(),
                    "now": now,
                    "installation_id": installation_id,
                },
            ).mappings().one()
        else:
            row = connection.execute(
                text(
                    """
                    INSERT INTO guard.pending_installations(
                        installation_id,device_id,discovery_credential_sha256,
                        app_version,hostname,manufacturer,model,serial_number,
                        os_version,first_seen_at,last_seen_at,updated_at
                    )
                    VALUES(
                        :installation_id,:device_id,:credential_sha256,
                        :app_version,NULLIF(:hostname,''),NULLIF(:manufacturer,''),
                        NULLIF(:model,''),NULLIF(:serial_number,''),
                        NULLIF(:os_version,''),:now,:now,:now
                    )
                    RETURNING *
                    """
                ),
                {
                    "installation_id": installation_id,
                    "device_id": req.device_id.strip(),
                    "credential_sha256": credential_hash,
                    "app_version": req.app_version.strip(),
                    "hostname": req.hostname.strip(),
                    "manufacturer": req.manufacturer.strip(),
                    "model": req.model.strip(),
                    "serial_number": req.serial_number.strip(),
                    "os_version": req.os_version.strip(),
                    "now": now,
                },
            ).mappings().one()

    return {
        **_pending_public(dict(row)),
        "serverTime": _iso(now),
    }


@router.post("/v1/multi-guard/discovery/uninstall")
def discovery_uninstall(req: DiscoveryUninstallRequest):
    """One authenticated positive uninstall receipt, including NO-LICENSE apps.

    A missing heartbeat is not proof of removal. Preserve the device, license,
    payment history and event IDs; only remove it from the pending queue.
    """
    pending = _authenticate_pending(
        req.installation_id, req.device_id, req.discovery_credential
    )
    _ensure_schema()
    # Create the runtime uninstall ledger before opening this transaction:
    # schema migrations must not run on a competing DB connection mid-write.
    from app.routers.multiguard_runtime import _ensure_schema as runtime_schema
    runtime_schema()
    with engine.begin() as connection:
        earlier = connection.execute(text("""
            SELECT installation_id FROM guard.discovery_uninstalls
            WHERE event_id=:event_id
        """), {"event_id":req.uninstall_event_id}).scalar_one_or_none()
        if earlier is not None:
            if earlier != pending["installation_id"]:
                raise HTTPException(409, "Identyfikator odinstalowania został już użyty.")
            return {"accepted":True, "duplicate":True, "status":"UNINSTALLED"}
        current = connection.execute(text("""
            SELECT status,assigned_license_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """), {"iid":pending["installation_id"]}).mappings().first()
        if current is None:
            raise HTTPException(404, "Instalacja nie istnieje.")
        # This can also happen after an earlier successful uninstall under
        # a different event UUID. Keep an audit trail but never reinterpret
        # an old install as newly licensed.
        connection.execute(text("""
            INSERT INTO guard.discovery_uninstalls
              (event_id,installation_id,previously_assigned,app_version)
            VALUES (:event_id,:iid,:assigned,:version)
        """), {"event_id":req.uninstall_event_id,
                "iid":pending["installation_id"],
                "assigned":bool(current["assigned_license_id"]),
                "version":req.app_version.strip()})
        connection.execute(text("""
            UPDATE guard.pending_installations
            SET status='UNINSTALLED',updated_at=now()
            WHERE installation_id=:iid
        """), {"iid":pending["installation_id"]})
        # A previously prepared, server-granted SERVICE permission must not
        # linger on an uninstalled device. It is NOT a paid cancellation.
        connection.execute(text("""
            UPDATE guard.workshop_grants
            SET enabled=FALSE,updated_at=now()
            WHERE installation_id=:iid AND enabled=TRUE
        """), {"iid":pending["installation_id"]})
        installation = connection.execute(text("""
            SELECT id FROM guard.installations
            WHERE installation_external_id=:iid AND is_current=TRUE LIMIT 1
        """), {"iid":pending["installation_id"]}).scalar_one_or_none()
        if installation is not None:
            # Paid/provisioned installations are shown as removed as well.
            connection.execute(text("""
                INSERT INTO guard.agent_uninstalls
                  (installation_id,event_id,client_occurred_at)
                VALUES (:internal_id,:event_id,now())
                ON CONFLICT (installation_id) DO UPDATE SET
                    event_id=EXCLUDED.event_id,
                    client_occurred_at=EXCLUDED.client_occurred_at,
                    reported_at=now()
            """), {"internal_id":installation,"event_id":req.uninstall_event_id})
    return {"accepted":True,"duplicate":False,"status":"UNINSTALLED"}


@router.post("/v1/multi-guard/discovery/assignment")
def discovery_assignment(req: DiscoveryAssignmentRequest):
    pending = _authenticate_pending(
        req.installation_id,
        req.device_id,
        req.discovery_credential,
    )

    # This is a trusted, authenticated contact from the installed program.
    # Revival happens in the previously approved discovery/assignment route,
    # not in registration: archived or removed computers return to the OWNER
    # queue only when the client actually asks for its assignment again.
    with engine.begin() as connection:
        current_status = connection.execute(text("""
            UPDATE guard.pending_installations
            SET status=CASE
                WHEN status IN ('ARCHIVED','UNINSTALLED')
                    THEN CASE WHEN assigned_license_id IS NOT NULL
                         THEN 'ASSIGNED' ELSE 'WAITING' END
                ELSE status END,
                last_seen_at=now(),updated_at=now()
            WHERE installation_id=:installation_id
            RETURNING status
        """), {"installation_id":pending["installation_id"]}).scalar_one()
    pending = dict(pending)
    pending["status"] = current_status

    reception_id = pending.get("assigned_reception_id")
    # Direct client licences have no reception_id. Use the stored KeyGate
    # licence identity, never a fabricated repair order.
    if (not reception_id and pending["status"] == "ASSIGNED"
            and pending.get("assigned_license_id")):
        with engine.connect() as con:
            direct = con.execute(text("""
                SELECT * FROM guard.license_links
                WHERE keygate_license_id=:id AND sale_kind='DIRECT'
                  AND installation_id=:installation_id
                LIMIT 1
            """), {"id":pending["assigned_license_id"],
                    "installation_id":pending["installation_id"]}).mappings().first()
        if direct:
            link = _normalize_link(dict(direct))
            return {
                "assigned":True,
                "status":pending["status"],
                "edition": "PRO" if link["plan_code"]=="multi_guard_pro" else "STANDARD",
                "durationMonths":int(link["duration_months"]),
                "releaseChannel":link.get("release_channel") or "STABLE",
                "provisioningToken":_keygate_reveal(link["keygate_license_id"]),
                "serverTime":_iso(_utcnow()),
            }
        raise HTTPException(409, "Nie znaleziono powiązanej licencji klienta.")
    if not reception_id or pending["status"] == "WAITING":
        grant = _workshop_grant(pending["installation_id"])
        if grant is not None:
            # Even revocation is a signed UNKNOWN envelope. The Windows app
            # must never infer revocation from lost Internet or missing JSON.
            return {
                "assigned": False,
                "status": "WORKSHOP" if grant["enabled"] else "WAITING",
                "releaseChannel": grant["release_channel"] if grant["enabled"] else None,
                "workshopLease": _signed_workshop_grant(pending, grant),
                "workshopMonitoring": {
                    "enabled": grant["enabled"] and grant.get("monitoring_profile","OFF") != "OFF",
                    "profile": grant.get("monitoring_profile") if grant["enabled"] else "OFF",
                },
                "serverTime": _iso(_utcnow()),
            }
        return {
            "assigned": False,
            "status": pending["status"],
            "serverTime": _iso(_utcnow()),
        }

    link = _link_by_reception_id(reception_id)
    if not link:
        raise HTTPException(
            409,
            "Instalacja jest przypisana do zlecenia bez licencji Multi-Guard.",
        )

    if (
        link.get("installation_id")
        and link["installation_id"] != pending["installation_id"]
    ):
        raise HTTPException(
            409,
            "Licencja została przypisana do innej instalacji Multi-Guard.",
        )

    return {
        "assigned": True,
        "status": pending["status"],
        "receptionId": str(link["reception_id"]),
        "receptionNumber": link["reception_number"],
        "edition": (
            "PRO"
            if link["plan_code"] == "multi_guard_pro"
            else "STANDARD"
        ),
        "durationMonths": int(link["duration_months"]),
        "releaseChannel": link.get("release_channel") or "STABLE",
        "provisioningToken": _keygate_reveal(link["keygate_license_id"]),
        "serverTime": _iso(_utcnow()),
    }


@router.post("/v1/multi-guard/workshop/report")
def workshop_report(req: WorkshopReportRequest):
    """Receive only OWNER-enabled diagnostic metrics; never user file contents."""
    pending = _authenticate_pending(
        req.installation_id, req.device_id, req.discovery_credential,
    )
    raw = json.dumps(req.summary, ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > 16_384:
        raise HTTPException(413, "Raport diagnostyczny jest zbyt duży.")
    allowed = {
        "defenderAvailable", "realtimeProtection", "activeThreatCount",
        "firewallProtected", "whea24h", "kernelPower7d",
        "diskProblemCount", "browserInstalledCount", "browserActiveCount",
        "browserNeedsAttentionCount", "capturedAt", "appVersion",
        "monitoringProfile", "samples",
    }
    if not isinstance(req.summary, dict) or not set(req.summary).issubset(allowed):
        raise HTTPException(400, "Raport zawiera nieobsługiwane pola.")
    samples = req.summary.get("samples", [])
    if not isinstance(samples, list) or len(samples) > 60:
        raise HTTPException(400, "Nieprawidłowa liczba próbek diagnostycznych.")
    numeric_keys = {
        "cpuLoadPercent", "cpuTemperatureC", "ramUsedPercent",
        "gpuLoadPercent", "gpuTemperatureC",
    }
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != numeric_keys | {"capturedAt"}:
            raise HTTPException(400, "Nieprawidłowa próbka diagnostyczna.")
        if not isinstance(sample["capturedAt"], str) or len(sample["capturedAt"]) > 40:
            raise HTTPException(400, "Nieprawidłowy czas próbki diagnostycznej.")
        for key in numeric_keys:
            value = sample[key]
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise HTTPException(400, "Nieprawidłowy pomiar diagnostyczny.")
            if not (-50 <= value <= 200):
                raise HTTPException(400, "Pomiar diagnostyczny poza zakresem.")
    _ensure_schema()
    with engine.begin() as con:
        grant = con.execute(text("""
            SELECT enabled,monitoring_profile FROM guard.workshop_grants
            WHERE installation_id=:id FOR UPDATE
        """), {"id":pending["installation_id"]}).mappings().first()
        if not grant or not grant["enabled"]:
            raise HTTPException(403, "Tryb serwisowy nie jest aktywny.")
        profile = grant["monitoring_profile"] or "OFF"
        if samples and profile == "OFF":
            raise HTTPException(409, "Rozszerzone monitorowanie nie jest włączone.")
        if req.summary.get("monitoringProfile", profile) not in {profile, None}:
            # A stale report after changing the profile must not impersonate
            # a higher cadence setting chosen by the OWNER.
            raise HTTPException(409, "Ustawienia monitorowania zmieniono. Odśwież je.")
        con.execute(text("""
            INSERT INTO guard.workshop_reports(installation_id,summary,reported_at)
            VALUES (:id,CAST(:data AS jsonb),now())
            ON CONFLICT(installation_id) DO UPDATE
              SET summary=EXCLUDED.summary,reported_at=now()
        """), {"id":pending["installation_id"],"data":raw})
        if profile != "OFF":
            con.execute(text("""
                INSERT INTO guard.workshop_report_history(installation_id,summary)
                VALUES (:id,CAST(:data AS jsonb))
            """), {"id":pending["installation_id"],"data":raw})
            con.execute(text("""
                DELETE FROM guard.workshop_report_history
                WHERE installation_id=:id
                  AND (reported_at < now() - interval '30 days'
                   OR id NOT IN (
                     SELECT id FROM guard.workshop_report_history
                     WHERE installation_id=:id ORDER BY id DESC LIMIT 43200
                   ))
            """), {"id":pending["installation_id"]})
    return {"saved":True,"serverTime":_iso(_utcnow())}


@router.get("/v1/multi-guard/license/pubkey")
def license_pubkey():
    return {
        "algorithm": "ed25519",
        "format": "base64",
        "public_key": _public_key_b64(),
    }


@router.post("/v1/multi-guard/provision")
def provision(req: ProvisionRequest):
    license_key = req.provisioning_token.strip().upper()
    if not _KEY_PATTERN.fullmatch(license_key):
        raise HTTPException(400, "Nieprawidłowy klucz licencji Multi-Guard.")
    try:
        installation_id = uuid.UUID(req.installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy installationId.") from exc

    # Never bind a previously prepared licence to an installation that
    # OWNER archived or whose removal the installer already confirmed.
    # A real subsequent discovery handshake restores a valid waiting state.
    pending = _pending_installation(installation_id)
    if pending and pending["status"] in {"ARCHIVED", "UNINSTALLED"}:
        raise HTTPException(
            409, "Instalacja została wycofana. Uruchom Multi-Guard ponownie "
                 "i poczekaj na ponowną rejestrację przed aktywacją."
        )

    link = _link_by_key(license_key)
    if not link:
        raise HTTPException(
            403, "Ten klucz nie został wystawiony przez Multi-Servis."
        )
    link = _normalize_link(link)

    if link.get("installation_id") and link["installation_id"] != installation_id:
        raise HTTPException(
            409, "Licencja jest już przypisana do innej instalacji."
        )
    if link.get("device_id") and link["device_id"] != req.device_id:
        raise HTTPException(409, "Licencja jest już przypisana do innego komputera.")
    if link["lifecycle"] in {"EXPIRED", "REVOKED"}:
        raise HTTPException(409, f"Licencja ma stan {link['lifecycle']}.")

    activated = _keygate_activate(
        license_key, req.device_id, str(installation_id)
    )
    returned_license_id = str(activated.get("license_id", "")).strip()
    if returned_license_id and returned_license_id != link["keygate_license_id"]:
        raise HTTPException(409, "KeyGate zwrócił inną licencję.")

    credential = secrets.token_urlsafe(48)
    credential_hash = _hash(credential)
    # Keep an explicit OWNER handover even when the computer provisions
    # later. Do not silently downgrade to workshop privileges.
    lifecycle = (
        link["lifecycle"]
        if (link.get("rebind_pending")
            or link.get("sale_kind") == "DIRECT")
            and link["lifecycle"] != "UNASSIGNED"
        else "SERVICE_TEST"
    )

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET installation_id=:installation_id,
                    device_id=:device_id,
                    credential_sha256=:credential_sha256,
                    app_version=:app_version,
                    lifecycle=:lifecycle,
                    provisioned_at=COALESCE(provisioned_at,now()),
                    rebind_pending=FALSE,
                    updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {
                "installation_id": installation_id,
                "device_id": req.device_id,
                "credential_sha256": credential_hash,
                "app_version": req.app_version,
                "lifecycle": lifecycle,
                "id": link["id"],
            },
        ).mappings().one()
        link = _normalize_link(dict(row))
        _update_installation_mirror(connection, link)
        connection.execute(
            text(
                """
                UPDATE guard.pending_installations
                SET
                    status='PROVISIONED',
                    assigned_reception_id=:reception_id,
                    assigned_license_id=:license_id,
                    provisioned_at=COALESCE(provisioned_at,now()),
                    last_seen_at=now(),
                    updated_at=now()
                WHERE installation_id=:installation_id
                """
            ),
            {
                "reception_id": link["reception_id"],
                "license_id": link["keygate_license_id"],
                "installation_id": installation_id,
            },
        )

    return {
        "requestId": req.request_id,
        "signedLicense": _signed_envelope(link),
        "installationCredential": credential,
        "requiredDocuments": (
            _required_documents() if link["lifecycle"] == "PENDING_ACCEPTANCE"
            else []
        ),
    }


@router.post("/v1/multi-guard/refresh")
def refresh(req: RefreshRequest):
    link = _authenticate_installation(req)
    keygate = _keygate_license(link["keygate_license_id"])
    keygate_status = str(keygate.get("status", "")).strip().lower()

    lifecycle = link["lifecycle"]
    if keygate_status in {"revoked", "suspended", "canceled", "cancelled"}:
        lifecycle = "REVOKED"
    elif keygate_status == "expired":
        lifecycle = "EXPIRED"
    elif link.get("valid_until") and _utcnow() >= link["valid_until"]:
        lifecycle = "EXPIRED"

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET lifecycle=:lifecycle, app_version=:app_version, updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {
                "lifecycle": lifecycle,
                "app_version": req.app_version,
                "id": link["id"],
            },
        ).mappings().one()
        link = _normalize_link(dict(row))
        _update_installation_mirror(connection, link)

    documents = (
        _required_documents() if link["lifecycle"] == "PENDING_ACCEPTANCE" else []
    )
    return {
        "requestId": req.request_id,
        "signedLicense": _signed_envelope(link),
        "requiredDocuments": documents,
    }


@router.post("/v1/multi-guard/acceptance")
def acceptance(req: AcceptanceRequest):
    link = _authenticate_installation(req)
    if link["lifecycle"] != "PENDING_ACCEPTANCE":
        raise HTTPException(409, "Licencja nie oczekuje na akceptację klienta.")

    required = _required_documents()
    if len(required) != 3:
        raise HTTPException(
            503, "Przed aktywacją muszą być skonfigurowane dokładnie 3 dokumenty."
        )

    expected = {
        (item["kind"], item["version"], item["sha256"].lower())
        for item in required
    }
    received = {
        (item.kind, item.version, item.sha256.lower()) for item in req.documents
    }
    if len(req.documents) != len(required) or received != expected:
        raise HTTPException(400, "Zaakceptowane dokumenty nie są aktualnym zestawem.")

    started = _utcnow()
    valid_until = _add_months(started, int(link["duration_months"]))
    _keygate_set_valid_until(link["keygate_license_id"], valid_until)

    accepted_documents = [item.model_dump() for item in req.documents]
    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET lifecycle='ACTIVE',
                    accepted_at=:started,
                    valid_from=:started,
                    valid_until=:valid_until,
                    accepted_documents=CAST(:documents AS jsonb),
                    app_version=:app_version,
                    updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {
                "started": started,
                "valid_until": valid_until,
                "documents": json.dumps(
                    accepted_documents, ensure_ascii=False, separators=(",", ":")
                ),
                "app_version": req.app_version,
                "id": link["id"],
            },
        ).mappings().one()
        link = _normalize_link(dict(row))
        _update_installation_mirror(connection, link)
        connection.execute(
            text(
                """
                INSERT INTO guard.activation_events (
                    reception_id,
                    reception_number,
                    keygate_license_id,
                    edition,
                    duration_months,
                    valid_until,
                    activated_at
                )
                VALUES (
                    :reception_id,
                    :reception_number,
                    :license_id,
                    :edition,
                    :duration_months,
                    :valid_until,
                    :activated_at
                )
                ON CONFLICT (keygate_license_id) DO NOTHING
                """
            ),
            {
                "reception_id": link["reception_id"],
                "reception_number": link["reception_number"],
                "license_id": link["keygate_license_id"],
                "edition": (
                    "PRO"
                    if link["plan_code"] == "multi_guard_pro"
                    else "STANDARD"
                ),
                "duration_months": link["duration_months"],
                "valid_until": link["valid_until"],
                "activated_at": link["accepted_at"],
            },
        )

    return {
        "requestId": req.request_id,
        "signedLicense": _signed_envelope(link),
    }


@router.get("/multiguard/activation-events")
def activation_events(
    after_id: int = 0,
    limit: int = 20,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    after_id = max(0, int(after_id))
    limit = min(max(1, int(limit)), 100)

    with engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    id,
                    reception_id,
                    reception_number,
                    keygate_license_id,
                    edition,
                    duration_months,
                    valid_until,
                    activated_at
                FROM guard.activation_events
                WHERE id > :after_id
                ORDER BY id ASC
                LIMIT :limit
                """
            ),
            {
                "after_id": after_id,
                "limit": limit,
            },
        ).mappings().all()

        latest_id = connection.execute(
            text("SELECT COALESCE(MAX(id),0) FROM guard.activation_events")
        ).scalar_one()

    return {
        "latestId": int(latest_id or 0),
        "events": [
            {
                "id": int(row["id"]),
                "receptionId": str(row["reception_id"]),
                "receptionNumber": row["reception_number"],
                "licenseId": row["keygate_license_id"],
                "edition": row["edition"],
                "durationMonths": row["duration_months"],
                "validUntil": _iso(row["valid_until"]),
                "activatedAt": _iso(row["activated_at"]),
            }
            for row in rows
        ],
    }


@router.get("/multiguard/licenses/receptions/{reception_id}")
def reception_license_status(
    reception_id: str,
    user: CurrentUser = Depends(require_staff),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc
    return _public_status(_link_by_reception_id(rid))


def _generate_license_link(
    reception_id: uuid.UUID,
    edition: str,
    months: int,
    release_channel: str = "STABLE",
) -> tuple[dict[str, Any], str]:
    edition = edition.strip().upper()
    release_channel = release_channel.strip().upper()
    if edition not in {"STANDARD", "PRO"}:
        raise HTTPException(400, "Edycja musi być STANDARD albo PRO.")
    if months not in {3, 6, 12}:
        raise HTTPException(400, "Okres musi wynosić 3, 6 albo 12 miesięcy.")
    if release_channel not in {"STABLE", "PILOT"}:
        raise HTTPException(400, "Kanał aktualizacji musi być STABLE albo PILOT.")

    _ensure_schema()
    reception = _reception(reception_id)
    existing = _link_by_reception_id(reception_id)
    if existing:
        raise HTTPException(409, "To zlecenie ma już licencję Multi-Guard.")

    created = _keygate_create_license(
        reception_number=reception["reception_number"],
        edition=edition,
        months=months,
    )
    license_key = created["_license_key"]
    plan_code = "multi_guard_pro" if edition == "PRO" else "multi_guard"

    try:
        with engine.begin() as connection:
            row = connection.execute(
                text(
                    """
                    INSERT INTO guard.license_links (
                        reception_id,reception_number,service_device_id,
                        keygate_license_id,keygate_plan_id,license_key_hash,
                        plan_code,duration_months,release_channel,lifecycle
                    )
                    VALUES (
                        :reception_id,:reception_number,:service_device_id,
                        :license_id,:plan_id,:license_key_hash,
                        :plan_code,:months,:release_channel,'UNASSIGNED'
                    )
                    RETURNING *
                    """
                ),
                {
                    "reception_id": reception_id,
                    "reception_number": reception["reception_number"],
                    "service_device_id": reception["device_id"],
                    "license_id": str(created["id"]),
                    "plan_id": created["_plan_id"],
                    "license_key_hash": _hash(license_key),
                    "plan_code": plan_code,
                    "months": months,
                    "release_channel": release_channel,
                },
            ).mappings().one()
            link = _normalize_link(dict(row))
    except Exception as exc:
        raise HTTPException(
            500,
            "KeyGate utworzył licencję, ale nie udało się zapisać jej "
            f"w Multi-Servis. Nie generuj drugiej licencji: {exc}",
        ) from exc

    return link, license_key



@router.get("/multiguard/pending-installations")
def pending_installations(
    reception_id: str = "",
    include_assigned: bool = True,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    target = None

    if reception_id.strip():
        try:
            rid = uuid.UUID(reception_id)
        except ValueError as exc:
            raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc

        with engine.connect() as connection:
            target = connection.execute(
                text(
                    """
                    SELECT
                        d.manufacturer,d.model,d.serial_number,d.hostname
                    FROM service.service_orders so
                    LEFT JOIN core.devices d ON d.id=so.device_id
                    WHERE so.id=:reception_id
                    LIMIT 1
                    """
                ),
                {"reception_id": rid},
            ).mappings().first()

    where = (
        "WHERE status IN ('WAITING','ASSIGNED')"
        if include_assigned
        else "WHERE status='WAITING'"
    )
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                f"""
                SELECT *
                FROM guard.pending_installations
                {where}
                ORDER BY
                    CASE status WHEN 'WAITING' THEN 0 ELSE 1 END,
                    last_seen_at DESC
                LIMIT 250
                """
            )
        ).mappings().all()

    result = []
    for raw in rows:
        row = dict(raw)
        score = 0
        if target:
            pending_serial = str(row.get("serial_number") or "").strip().lower()
            target_serial = str(target["serial_number"] or "").strip().lower()
            if pending_serial and target_serial and pending_serial == target_serial:
                score += 100

            pending_model = str(row.get("model") or "").strip().lower()
            target_model = str(target["model"] or "").strip().lower()
            if pending_model and target_model and pending_model == target_model:
                score += 35

            pending_manufacturer = (
                str(row.get("manufacturer") or "").strip().lower()
            )
            target_manufacturer = (
                str(target["manufacturer"] or "").strip().lower()
            )
            if (
                pending_manufacturer
                and target_manufacturer
                and pending_manufacturer == target_manufacturer
            ):
                score += 15

        result.append(_pending_public(row, match_score=score))

    result.sort(
        key=lambda item: (
            -int(item["matchScore"]),
            0 if item["online"] else 1,
            item["status"] != "WAITING",
            item["lastSeenAt"] or "",
        )
    )
    return result


@router.post("/multiguard/pending-installations/{installation_id}/assign")
def assign_pending_installation(
    installation_id: str,
    body: AssignPendingInstallationRequest,
    user: CurrentUser = Depends(require_owner),
):
    try:
        iid = uuid.UUID(installation_id)
        rid = uuid.UUID(body.reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowy identyfikator.") from exc

    link = _assign_pending_to_reception(
        iid,
        rid,
        body.edition,
        body.months,
        body.release_channel,
    )
    pending = _pending_installation(iid)
    return {
        **_public_status(link),
        "pendingInstallation": (
            _pending_public(pending) if pending else None
        ),
        "autoProvision": True,
    }




@router.post("/multiguard/pending-installations/{installation_id}/direct")
def assign_direct_license_api(
    installation_id: uuid.UUID,
    body: DirectLicenseRequest,
    user: CurrentUser = Depends(require_owner),
):
    return _public_status(_assign_direct_customer_license(
        installation_id, body.edition, body.months, body.release_channel,
    ))


@router.post("/multiguard/pending-installations/{installation_id}/handover")
def handover_direct_license_api(
    installation_id: uuid.UUID,
    user: CurrentUser = Depends(require_owner),
):
    return _public_status(_handover_direct_customer(installation_id))


@router.post("/multiguard/panel/pending/{installation_id}/direct",
             response_class=HTMLResponse)
def assign_direct_license_web(
    installation_id: uuid.UUID,
    edition: str = Form(...),
    months: str = Form(...),
    release_channel: str = Form("STABLE"),
    service_confirm: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły formularz.")
    if months == "SERVICE":
        if service_confirm != "CONFIRM_WORKSHOP":
            raise HTTPException(400, "Tryb serwisowy wymaga dodatkowego potwierdzenia.")
        _set_workshop_grant(installation_id,edition,release_channel,True)
        with engine.begin() as con:
            con.execute(text("""
                UPDATE guard.workshop_grants SET associated_reception_id=NULL,
                updated_at=now() WHERE installation_id=:id
            """),{"id":installation_id})
        target="/multiguard/panel#service-modes"
    else:
        if months not in {"3","6","12"}:
            raise HTTPException(400, "Wybierz okres 3, 6, 12 lub tryb serwisowy.")
        _assign_direct_customer_license(installation_id,edition,int(months),release_channel)
        target=f"/multiguard/panel/pending/{installation_id}#client-license"
    return RedirectResponse(
        target,status_code=303,headers={"Cache-Control":"private, no-store"},
    )


@router.post("/multiguard/panel/pending/{installation_id}/handover",
             response_class=HTMLResponse)
def handover_direct_license_web(
    installation_id: uuid.UUID,
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły formularz.")
    _handover_direct_customer(installation_id)
    from fastapi.responses import RedirectResponse
    return RedirectResponse(
        f"/multiguard/panel/pending/{installation_id}#client-license", status_code=303,
        headers={"Cache-Control":"private, no-store"},
    )


def _workshop_csrf() -> str:
    from app.routers.multiguard_panel_settings import _csrf_token
    import time
    return _csrf_token(int(time.time() // 3600))


def _owner_confirm_service_dialog(dialog_id: str) -> str:
    """A separate explicit second click before service rights are issued."""
    safe = _panel_escape(dialog_id)
    return f"""
        <dialog class="pending-owner-dialog owner-service-confirm-dialog" id="{safe}">
          <h3>Czy na pewno włączyć tryb serwisowy?</h3>
          <p>To <strong>nie jest licencja czasowa</strong>.
             Program będzie działał bezterminowo także bez Internetu,
             a tryb można wyłączyć wyłącznie z centralnego panelu właściciela.
             Monitorowanie rozszerzone pozostanie domyślnie wyłączone.</p>
          <div class="pending-dialog-buttons">
            <button type="button" class="pending-cancel-button"
              onclick="this.closest('dialog').close()">ANULUJ</button>
            <button type="button" class="pending-confirm-archive"
              data-service-approve>TAK, WŁĄCZ TRYB SERWISOWY</button>
          </div>
        </dialog>"""


# The obsolete standalone "Tryb warsztatowy" OWNER action no longer
# exists. All service grants now require a second confirmation in one
# of the two customer forms. Revocation belongs to central OWNER only.
@router.post("/multiguard/panel/pending/{installation_id}/workshop")
def legacy_workshop_owner_endpoint_retired(
    installation_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    raise HTTPException(410,"Ten formularz został wycofany. Użyj Trybu serwisowego w formularzu licencji.")


@router.get(
    "/multiguard/panel/pending/{installation_id}",
    response_class=HTMLResponse,
)
def multiguard_panel_pending(
    installation_id: str,
    _: None = Depends(_panel_auth),
):
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID instalacji.") from exc

    pending = _pending_installation(iid)
    if not pending:
        raise HTTPException(404, "Nie znaleziono oczekującej instalacji.")

    public = _pending_public(pending)
    from app.routers.multiguard_panel_devices import (
        owner_detected_name, owner_friendly_name, owner_name_form,
    )
    stored_name = owner_friendly_name(iid)
    detected_name = owner_detected_name(pending)
    display_name = stored_name or detected_name
    name_form = owner_name_form(
        iid, stored_name, return_to="pending", detected_name=detected_name,
    )
    grant = _workshop_grant(iid)
    # Avoid suggesting a new paid licence while a previous external KeyGate
    # creation may have succeeded without a local licence link.
    with engine.connect() as audit_con:
        unresolved_attempt = audit_con.execute(text("""
            SELECT a.state,a.keygate_license_id
            FROM guard.direct_keygate_attempts a
            LEFT JOIN guard.license_links l
              ON l.installation_id=a.installation_id
             AND l.keygate_license_id=a.keygate_license_id
            WHERE a.installation_id=:id
              AND (a.state IN ('STARTED','RECONCILIATION_REQUIRED')
                OR (a.state='CREATED' AND l.id IS NULL))
        """), {"id":iid}).mappings().first()
    direct = None
    if pending.get("assigned_license_id"):
        with engine.connect() as direct_con:
            direct = direct_con.execute(text("""
                SELECT * FROM guard.license_links
                WHERE sale_kind='DIRECT' AND installation_id=:iid
                  AND keygate_license_id=:license_id
            """), {"iid":iid,"license_id":pending["assigned_license_id"]}).mappings().first()
    if direct:
        direct_info = (
            "<p class='ok'>Licencja klienta: "
            + _panel_escape("Pro" if direct["plan_code"]=="multi_guard_pro" else "Standard")
            + " · " + str(direct["duration_months"])
            + " miesięcy · " + _panel_escape({"UNASSIGNED":"Przypisana","SERVICE_TEST":"Przygotowana","PENDING_ACCEPTANCE":"Oczekuje na akceptację","ACTIVE":"Aktywna","EXPIRED":"Wygasła","REVOKED":"Cofnięta"}.get(direct["lifecycle"],"Nieznana"))
            + "</p>"
            + (
                f'<p><a class="button-link" href="/multiguard/panel/license/installation/{installation_id}/extend">'
                'PRZEDŁUŻ LICENCJĘ</a></p>'
                if direct["lifecycle"]=="ACTIVE" else ""
            )
        )
        direct_buttons = (
            f'<form method="post" action="/multiguard/panel/pending/{installation_id}/handover">'
            f'<input type="hidden" name="csrf_token" value="{_workshop_csrf()}">'
            '<button type="submit">PRZEKAŻ KLIENTOWI / POPROŚ O AKCEPTACJĘ</button></form>'
            if direct["lifecycle"] in {"UNASSIGNED","SERVICE_TEST"} else
            '<p class="muted">Przekazanie zarejestrowane; komputer pobierze status po synchronizacji.</p>'
        )
    elif pending["status"] == "WAITING":
        direct_info = '<p>Sprzedaż bez przyjęcia sprzętu do warsztatu i bez numeru zlecenia.</p>'
        direct_buttons = f"""
            <form method="post" action="/multiguard/panel/pending/{installation_id}/direct"
              data-owner-service-form>
              <input type="hidden" name="csrf_token" value="{_workshop_csrf()}">
              <input type="hidden" name="service_confirm" value="">
              <label>Edycja<select name="edition">
                <option value="STANDARD">Standard</option>
                <option value="PRO">Pro</option>
              </select></label>
              <label>Okres / tryb<select name="months">
                <option value="3">3 miesiące</option>
                <option value="6">6 miesięcy</option>
                <option value="12" selected>12 miesięcy</option>
                <option value="SERVICE">🔧 Tryb serwisowy (bezterminowy)</option>
              </select></label>
              <label>Kanał<select name="release_channel">
                <option value="STABLE">Stabilna</option>
                <option value="PILOT">Beta</option>
              </select></label>
              <button type="submit" data-owner-service-submit>PRZYPISZ LICENCJĘ KLIENTA</button>
              {_owner_confirm_service_dialog(f"confirm-direct-{installation_id}")}
            </form>
        """
    else:
        direct_info = '<p>Ta instalacja ma już powiązanie ze zleceniem serwisowym.</p>'
        direct_buttons = ''
    if unresolved_attempt:
        direct_buttons = (
            '<p class="bad" role="alert">Blokada bezpieczeństwa KeyGate: '
            'poprzednia próba wymaga ręcznego uzgodnienia przez OWNER. '
            'Nie twórz kolejnej licencji dla tej instalacji.</p>'
        )
    workshop_state_html = (
        '<p class="ok">🔧 TRYB SERWISOWY — AKTYWNY · '
        + _panel_escape(grant["edition"])
        + '. Monitorowanie rozszerzone: '
        + _panel_escape(grant.get("monitoring_profile") or "OFF")
        + '. Zmiany i wyłączenie wyłącznie w '
        + '<a href="/multiguard/panel#service-modes">panelu właściciela</a>.</p>'
        if grant and grant["enabled"] else ""
    )
    return _panel_html(
        f"""
        <section class="card">
          <a href="/multiguard/panel/dashboard">← Wróć do pulpitu</a>
          <h1>Komputer {_panel_escape(public['shortId'])}</h1>
          <p>Nazwa komputera: <strong>{_panel_escape(display_name)}</strong></p>
          <p>
            Wersja Multi-Guard: {_panel_escape(public['appVersion'] or '—')}
            • {'ONLINE' if public['online'] else 'offline'}
          </p>
          <p>
            Serial: {_panel_escape(public['serialNumber'] or '—')}
            • host: {_panel_escape(public['hostname'] or '—')}
          </p>
          {name_form}
          {workshop_state_html}
          <section class="card" id="client-license">
            <div class="eyebrow">LICENCJA KOMERCYJNA</div>
            <h2>Licencja klienta bez zlecenia</h2>
            {direct_info}
            {direct_buttons}
          </section>
          <section class="card"><h2>Licencja klienta — zlecenie serwisowe</h2>
          <form method="post" action="/multiguard/panel/pending/{installation_id}/assign"
            data-owner-service-form>
            <input type="hidden" name="csrf_token" value="{_workshop_csrf()}">
            <input type="hidden" name="service_confirm" value="">
            <label>Numer zlecenia Multi-Servis
              <input name="reception_number" placeholder="np. MS-2026-00123"
                list="owner-order-hints-{installation_id}" data-owner-order-suggest
                autocomplete="off" required>
              <datalist id="owner-order-hints-{installation_id}"></datalist>
            </label>
            <div class="grid">
              <label>Wersja
                <select name="edition">
                  <option value="STANDARD">Multi-Guard Standard</option>
                  <option value="PRO">Multi-Guard Pro</option>
                </select>
              </label>
              <label>Okres / tryb
                <select name="months">
                  <option value="3">3 miesiące</option>
                  <option value="6">6 miesięcy</option>
                  <option value="12" selected>12 miesięcy</option>
                  <option value="SERVICE">🔧 Tryb serwisowy (bezterminowy)</option>
                </select>
              </label>
              <label>Kanał
                <select name="release_channel">
                  <option value="STABLE" selected>Stabilna</option>
                  <option value="PILOT">Beta</option>
                </select>
              </label>
            </div>
            <button type="submit" data-owner-service-submit>PRZYPISZ I PRZYGOTUJ LICENCJĘ</button>
            {_owner_confirm_service_dialog(f"confirm-order-{installation_id}")}
          </form></section>
        </section>
        """
    )


@router.post(
    "/multiguard/panel/pending/{installation_id}/assign",
    response_class=HTMLResponse,
)
def multiguard_panel_pending_assign(
    installation_id: str,
    reception_number: str = Form(...),
    edition: str = Form(...),
    months: str = Form(...),
    release_channel: str = Form("STABLE"),
    service_confirm: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Wygasły lub nieprawidłowy formularz.")
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID instalacji.") from exc

    reception = _reception_by_number(reception_number)
    if months == "SERVICE":
        if service_confirm != "CONFIRM_WORKSHOP":
            raise HTTPException(400,"Tryb serwisowy wymaga dodatkowego potwierdzenia.")
        if _link_by_reception_id(reception["id"]):
            raise HTTPException(409,"Zlecenie ma już licencję czasową Multi-Guard.")
        _set_workshop_grant(iid,edition,release_channel,True)
        with engine.begin() as con:
            con.execute(text("""
                UPDATE guard.workshop_grants
                SET associated_reception_id=:rid,updated_at=now()
                WHERE installation_id=:id
            """),{"rid":reception["id"],"id":iid})
        return RedirectResponse(
            "/multiguard/panel#service-modes",status_code=303,
            headers={"Cache-Control":"private, no-store"},
        )
    if months not in {"3","6","12"}:
        raise HTTPException(400,"Wybierz okres 3, 6, 12 lub tryb serwisowy.")
    link = _assign_pending_to_reception(
        iid,reception["id"],edition,int(months),release_channel,
    )
    pending = _pending_installation(iid)
    public = _pending_public(pending) if pending else {}

    return _panel_html(
        f"""
        <section class="card">
          <h1>Licencja przypisana</h1>
          <p class="ok">
            {_panel_escape(public.get('shortId') or installation_id)}
            → {_panel_escape(link['reception_number'])}
          </p>
          <p>
            Multi-Guard na tym komputerze może teraz automatycznie odebrać
            przypisanie i przejść do SERVICE_TEST bez ręcznego przepisywania klucza.
          </p>
          <a class="button-link" href="/multiguard/panel/dashboard">WRÓĆ DO PULPITU</a>
        </section>
        """
    )


def _owner_workshop_manager_panel() -> str:
    """OWNER central controls; no remote customer API or Windows UI changes."""
    _ensure_schema()
    with engine.connect() as con:
        rows = con.execute(text("""
            SELECT w.installation_id,w.edition,w.release_channel,w.enabled,
                   w.monitoring_profile,w.associated_reception_id,
                   p.hostname,p.manufacturer,p.model,so.reception_number
            FROM guard.workshop_grants w
            JOIN guard.pending_installations p ON p.installation_id=w.installation_id
            LEFT JOIN service.service_orders so ON so.id=w.associated_reception_id
            ORDER BY w.enabled DESC,w.updated_at DESC LIMIT 80
        """)).mappings().all()
    from app.routers.multiguard_panel_devices import owner_detected_name,owner_friendly_name
    token = _workshop_csrf()
    trs = []
    for row in rows:
        iid = row["installation_id"]
        display = _panel_escape(owner_friendly_name(iid) or owner_detected_name(row))
        edition = _panel_escape(row["edition"])
        status = "<span class='badge mg-gold'>AKTYWNY</span>" if row["enabled"] else "<span class='badge'>WYŁĄCZONY</span>"
        selected = row["monitoring_profile"] if row["enabled"] else "OFF"
        link = (
            f'<span class="muted">Zlecenie {_panel_escape(row["reception_number"])}</span>'
            if row["reception_number"] else '<span class="muted">Bez zlecenia</span>'
        )
        controls = '<span class="muted">Oczekuje na nowe uprawnienia</span>'
        if row["enabled"]:
            options = "".join(
                f'<option value="{value}" {"selected" if value==selected else ""}>{label}</option>'
                for value,label in (
                    ("STANDARD","Standardowy"),("OBSERVATION","Obserwacja"),
                    ("INTENSIVE","Intensywny"),
                )
            )
            controls = f"""
              <div class="owner-service-controls">
                <form method="post" action="/multiguard/panel/workshop/{iid}/monitoring"
                    data-owner-monitor-form>
                  <input type="hidden" name="csrf_token" value="{token}">
                  <label class="owner-monitor-toggle">
                    <span class="owner-monitor-label">Monitorowanie rozszerzone
                      <small data-owner-monitor-state>{"Włączone" if selected!="OFF" else "Wyłączone"}</small>
                    </span>
                    <input type="checkbox" name="monitoring_enabled" value="yes"
                      {"checked" if selected!="OFF" else ""} data-owner-monitor-toggle
                      aria-label="Włącz monitorowanie rozszerzone dla {display}">
                    <span class="owner-monitor-switch" aria-hidden="true"></span>
                  </label>
                  <label>Poziom monitorowania
                    <select name="profile" aria-label="Poziom monitorowania dla {display}"
                        data-owner-monitor-profile {"disabled" if selected=="OFF" else ""}>
                      {options}
                    </select>
                  </label>
                  <button type="submit" class="owner-monitor-save" data-owner-monitor-save disabled>ZAPISZ ZMIANY</button>
                </form>
                <div class="owner-service-actions">
                <a class="button-link compact" href="/multiguard/panel/workshop/{iid}/reports">
                  HISTORIA RAPORTÓW
                </a>
                <button type="button" class="pending-archive-trigger"
                  onclick="document.getElementById('disable-workshop-{iid}').showModal()">
                  WYŁĄCZ TRYB SERWISOWY
                </button>
                </div>
                <dialog class="pending-owner-dialog" id="disable-workshop-{iid}"
                  aria-labelledby="disable-workshop-title-{iid}">
                  <h3 id="disable-workshop-title-{iid}">Wyłączyć tryb serwisowy?</h3>
                  <p>Komputer {display} po kolejnym kontakcie z Multi-Servis
                     wróci do stanu „Oczekuje na licencję Multi-Servis”.
                     Bez Internetu zachowa dotychczasowe uprawnienia.</p>
                  <div class="pending-dialog-buttons">
                    <button type="button" class="pending-cancel-button"
                      onclick="this.closest('dialog').close()">ANULUJ</button>
                    <form method="post" action="/multiguard/panel/workshop/{iid}/disable">
                      <input type="hidden" name="csrf_token" value="{token}">
                      <input type="hidden" name="confirmation" value="CONFIRM_DISABLE">
                      <button type="submit" class="pending-confirm-archive">
                        TAK, WYŁĄCZ TRYB SERWISOWY
                      </button>
                    </form>
                  </div>
                </dialog>
              </div>"""
        trs.append(
            f"<tr><td><a href='/multiguard/panel/pending/{iid}'>{display}</a><br>"
            + link + "</td><td><span class='owner-service-edition'>SERWIS · " + edition + "</span></td><td>" + status
            + "</td><td>" + controls + "</td></tr>"
        )
    return f"""
      <section class="card" id="service-modes">
        <div class="eyebrow">MULTI-GUARD / PANEL WŁAŚCICIELA</div>
        <h2>Aktywne tryby serwisowe i monitorowanie</h2>
        <p>Tryb serwisowy działa również bez Internetu. Rozszerzone
           monitorowanie jest domyślnie wyłączone. Możesz wybrać
           Standardowy, Obserwacja lub Intensywny dla każdego komputera.
           Wyłączenie uprawnienia jest możliwe tylko tutaj.</p>
        <div class="table-wrap"><table style="min-width:900px">
          <thead><tr><th>Komputer / zlecenie</th><th>Wariant serwisowy</th>
            <th>Tryb serwisowy</th><th>Monitorowanie i sterowanie</th></tr></thead>
          <tbody>{''.join(trs) or '<tr><td colspan="4">Brak komputerów z trybem serwisowym.</td></tr>'}</tbody>
        </table></div>
      </section>
    """


@router.get("/multiguard/panel/workshop/{installation_id}/reports",
            response_class=HTMLResponse)
def owner_workshop_reports(
    installation_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    """OWNER-only recent time series; no raw private files, no public URL."""
    _ensure_schema()
    with engine.connect() as con:
        grant=con.execute(text("""
            SELECT edition,enabled,monitoring_profile FROM guard.workshop_grants
            WHERE installation_id=:id
        """),{"id":installation_id}).mappings().first()
        if grant is None:
            raise HTTPException(404,"Brak trybu serwisowego tej instalacji.")
        logs=con.execute(text("""
            SELECT reported_at,summary FROM guard.workshop_report_history
            WHERE installation_id=:id ORDER BY reported_at DESC LIMIT 60
        """),{"id":installation_id}).mappings().all()
    trs=[]
    for row in logs:
        summary=row["summary"] if isinstance(row["summary"],dict) else {}
        sample_list=summary.get("samples",[])
        if not isinstance(sample_list,list):
            sample_list=[]
        cpu_values=[v["cpuLoadPercent"] for v in sample_list
                    if isinstance(v,dict) and isinstance(v.get("cpuLoadPercent"),(float,int))]
        avg_cpu=f"{sum(cpu_values)/len(cpu_values):.1f}%" if cpu_values else "—"
        trs.append(
            "<tr><td>"+_panel_escape(row["reported_at"])+"</td>"
            "<td>"+_panel_escape(summary.get("monitoringProfile","—"))+"</td>"
            "<td>"+_panel_escape(len(sample_list))+"</td>"
            "<td>"+_panel_escape(avg_cpu)+"</td>"
            "<td>"+_panel_escape(summary.get("whea24h","—"))+"</td>"
            "<td>"+_panel_escape(summary.get("kernelPower7d","—"))+"</td></tr>"
        )
    return HTMLResponse(_panel_html(f"""
      <section class="card">
        <a href="/multiguard/panel#service-modes">← Tryby serwisowe</a>
        <h1>Historia raportów diagnostycznych</h1>
        <p>Instalacja {_panel_escape(installation_id)} ·
           edycja {_panel_escape(grant["edition"])} ·
           monitorowanie {_panel_escape(grant["monitoring_profile"])}.</p>
        <p>Ostatnie 60 raportów (retencja maksymalnie 30 dni).
           Raportowanie wyłączone nie usuwa starszej historii.</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Otrzymano</th><th>Profil</th><th>Próbki</th>
          <th>Średnie użycie CPU</th><th>Błędy WHEA 24h</th>
          <th>Kernel-Power 7 dni</th></tr></thead>
          <tbody>{''.join(trs) or '<tr><td colspan="6">Brak raportów.</td></tr>'}</tbody>
        </table></div>
      </section>
    """),headers={"Cache-Control":"private, no-store"})


@router.post("/multiguard/panel/workshop/{installation_id}/monitoring")
def owner_set_workshop_monitoring(
    installation_id: uuid.UUID,
    profile: str = Form("STANDARD"),
    monitoring_enabled: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły lub nieprawidłowy formularz.")
    if monitoring_enabled not in {"","yes"} or profile not in {"STANDARD","OBSERVATION","INTENSIVE"}:
        raise HTTPException(400, "Nieprawidłowe ustawienia monitorowania.")
    profile=profile if monitoring_enabled=="yes" else "OFF"
    _ensure_schema()
    with engine.begin() as con:
        grant = con.execute(text("""
            SELECT edition,release_channel,monitoring_profile,enabled
            FROM guard.workshop_grants WHERE installation_id=:id FOR UPDATE
        """), {"id":installation_id}).mappings().first()
        if not grant or not grant["enabled"]:
            raise HTTPException(409, "Tryb serwisowy nie jest aktywny.")
        if grant["monitoring_profile"] != profile:
            con.execute(text("""
                UPDATE guard.workshop_grants
                SET monitoring_profile=:profile,updated_at=now()
                WHERE installation_id=:id
            """), {"profile":profile,"id":installation_id})
            con.execute(text("""
                INSERT INTO guard.workshop_grant_audit(
                    installation_id,before_state,after_state
                ) VALUES (:id,CAST(:before AS jsonb),CAST(:after AS jsonb))
            """), {
                "id":installation_id,
                "before":json.dumps({"monitoring_profile":grant["monitoring_profile"]}),
                "after":json.dumps({"monitoring_profile":profile}),
            })
    return RedirectResponse("/multiguard/panel#service-modes",status_code=303)


@router.post("/multiguard/panel/workshop/{installation_id}/disable")
def owner_disable_workshop(
    installation_id: uuid.UUID,
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły lub nieprawidłowy formularz.")
    if confirmation != "CONFIRM_DISABLE":
        raise HTTPException(400, "Wyłączenie wymaga osobnego potwierdzenia.")
    grant = _workshop_grant(installation_id)
    if not grant or not grant["enabled"]:
        raise HTTPException(409, "Tryb serwisowy nie jest aktywny.")
    _set_workshop_grant(
        installation_id,grant["edition"],grant["release_channel"],False,
    )
    return RedirectResponse("/multiguard/panel#service-modes",status_code=303)


@router.get("/multiguard/panel/service-orders/suggest")
def owner_suggest_service_orders(q: str = "", _: None = Depends(_panel_auth)):
    """Authenticated number fragments only: max 8 matching real service orders."""
    if len(q)>40:
        raise HTTPException(400,"Zbyt długi fragment numeru zlecenia.")
    digits = "".join(ch for ch in q if "0" <= ch <= "9")
    if len(digits)<3:
        return {"results":[]}
    with engine.connect() as con:
        rows=con.execute(text("""
            SELECT so.reception_number,d.manufacturer,d.model
            FROM service.service_orders so
            LEFT JOIN core.devices d ON d.id=so.device_id
            WHERE regexp_replace(so.reception_number,'[^0-9]','','g') LIKE :query
            ORDER BY so.received_at DESC NULLS LAST,so.reception_number DESC
            LIMIT 8
        """),{"query":"%"+digits+"%"}).mappings().all()
    return {"results":[{
        "number":str(row["reception_number"]),
        "label":str(row["reception_number"]) + " — "
                 + " ".join(x for x in (
                     str(row["manufacturer"] or "").strip(),
                     str(row["model"] or "").strip()) if x),
    } for row in rows]}


def _owner_keygate_reconciliation_panel() -> str:
    """Read-only OWNER warning; manual reconciliation must precede any retry."""
    _ensure_schema()
    with engine.connect() as con:
        rows = con.execute(text("""
            SELECT installation_id,workspace_reference,state,keygate_license_id,edition,duration_months,release_channel
            FROM guard.direct_keygate_attempts
            WHERE state IN ('STARTED','RECONCILIATION_REQUIRED')
               OR (state='CREATED' AND NOT EXISTS (
                   SELECT 1 FROM guard.license_links l
                   WHERE l.installation_id=guard.direct_keygate_attempts.installation_id
                     AND l.keygate_license_id=guard.direct_keygate_attempts.keygate_license_id
               ))
            ORDER BY updated_at DESC LIMIT 50
        """)).mappings().all()
    if not rows:
        return ""
    lines = "".join(
        "<li>Instalacja <code>" + _panel_escape(str(row["installation_id"]))
        + "</code> · workspace <code>" + _panel_escape(row["workspace_reference"])
        + "</code> · plan " + _panel_escape(row.get("edition") or "—")
        + " / " + _panel_escape(row.get("duration_months") or "—")
        + " mies. · kanał " + _panel_escape(row.get("release_channel") or "—")
        + " · stan <strong>" + _panel_escape(row["state"])
        + "</strong> · KeyGate ID <code>"
        + _panel_escape(row.get("keygate_license_id") or "nieznane")
        + "</code> · <a href=\"/multiguard/panel/pending/"
        + _panel_escape(str(row["installation_id"]))
        + "\">Szczegóły komputera</a></li>"
        for row in rows
    )
    return (
        '<section class="card" role="alert"><h2>Wymagana weryfikacja KeyGate</h2>'
        '<p>Nie ponawiaj tworzenia licencji. Najpierw uzgodnij stan w KeyGate '
        'i bazie Multi-Servis.</p><ul>' + lines + '</ul></section>'
    )


@router.get("/multiguard/panel", response_class=HTMLResponse)
def multiguard_panel(
    _: None = Depends(_panel_auth),
):
    return _panel_html(
        f"""
        <section class="card owner-overview-hero" aria-labelledby="owner-overview-title">
          <div class="eyebrow">MULTI-SERVIS / CENTRUM WŁAŚCICIELA</div>
          <h1 id="owner-overview-title">Centrum zarządzania</h1>
          <p>Komputery, zlecenia serwisowe i licencje Multi-Guard w jednym miejscu.</p>
          <div class="owner-overview-grid">
            <a class="owner-overview-tile" href="/multiguard/panel/computers">
              <span class="owner-overview-icon" aria-hidden="true">▣</span>
              <strong>Komputery</strong><span>Urządzenia i dostęp do szczegółów</span>
              <em>OTWÓRZ →</em>
            </a>
            <a class="owner-overview-tile" href="/multiguard/panel/service">
              <span class="owner-overview-icon" aria-hidden="true">◇</span>
              <strong>Zlecenia serwisowe</strong><span>Naprawy, notatki i wydania</span>
              <em>OTWÓRZ →</em>
            </a>
            <a class="owner-overview-tile" href="/multiguard/panel/licenses">
              <span class="owner-overview-icon" aria-hidden="true">▤</span>
              <strong>Licencje Multi-Guard</strong><span>Aktywacje i uprawnienia</span>
              <em>OTWÓRZ →</em>
            </a>
            <a class="owner-overview-tile" href="/multiguard/panel/statistics">
              <span class="owner-overview-icon" aria-hidden="true">▥</span>
              <strong>Statystyki</strong><span>Wyniki serwisu i finanse OWNER</span>
              <em>OTWÓRZ →</em>
            </a>
          </div>
        </section>
        {_owner_keygate_reconciliation_panel()}
        {_owner_workshop_manager_panel()}
        <section class="card" id="new-license">
          <div class="eyebrow">MULTI-SERVIS / AKTYWACJA PROGRAMU</div>
          <h1>Nowa licencja Multi-Guard</h1>
          <p>Generowanie klucza i instalacja w serwisie nie uruchamiają okresu licencji.</p>
          <form method="post" action="/multiguard/panel/generate">
            <label>Numer zlecenia Multi-Servis
              <input name="reception_number" placeholder="np. MS-2026-00123" required>
            </label>
            <div class="grid">
              <label>Wersja
                <select name="edition">
                  <option value="STANDARD">Multi-Guard Standard</option>
                  <option value="PRO">Multi-Guard Pro</option>
                </select>
              </label>
              <label>Okres
                <select name="months">
                  <option value="3">3 miesiące</option>
                  <option value="6">6 miesięcy</option>
                  <option value="12" selected>12 miesięcy</option>
                </select>
              </label>
              <label>Kanał
                <select name="release_channel">
                  <option value="STABLE" selected>Stabilna</option>
                  <option value="PILOT">Beta</option>
                </select>
              </label>
              <label>&nbsp;<button type="submit">GENERUJ KLUCZ</button></label>
            </div>
          </form>
        </section>
        """
    )


@router.post("/multiguard/panel/generate", response_class=HTMLResponse)
def multiguard_panel_generate(
    reception_number: str = Form(...),
    edition: str = Form(...),
    months: int = Form(...),
    release_channel: str = Form("STABLE"),
    _: None = Depends(_panel_auth),
):
    reception = _reception_by_number(reception_number)
    link, license_key = _generate_license_link(
        reception_id=reception["id"],
        edition=edition,
        months=months,
        release_channel=release_channel,
    )
    product = (
        "Multi-Guard Pro"
        if link["plan_code"] == "multi_guard_pro"
        else "Multi-Guard Standard"
    )
    return _panel_html(
        f"""
        <section class="card">
          <h1>Klucz gotowy</h1>
          <p class="ok">{product} • {link["duration_months"]} mies. • {"BETA" if link.get("release_channel") == "PILOT" else "STABILNA"} • {link["reception_number"]}</p>
          <code class="key" id="license-key">{license_key}</code>
          <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('license-key').innerText)">KOPIUJ KLUCZ</button>
          <p class="warn">Po wpisaniu klucza program zostanie przygotowany do przekazania klientowi. Okres płatnej licencji rozpocznie się dopiero po akceptacji wymaganych dokumentów.</p>
          <a href="/multiguard/panel">← Wróć do generatora</a>
        </section>
        """
    )


@router.post("/multiguard/licenses/receptions/{reception_id}/generate")
def generate_reception_license(
    reception_id: str,
    body: GenerateLicenseRequest,
    user: CurrentUser = Depends(require_owner),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc

    link, license_key = _generate_license_link(
        reception_id=rid,
        edition=body.edition,
        months=body.months,
        release_channel=body.release_channel,
    )
    return {
        **_public_status(link),
        "licenseKey": license_key,
    }


@router.post("/multiguard/licenses/receptions/{reception_id}/approve")
def approve_reception_license(
    reception_id: str,
    user: CurrentUser = Depends(require_staff),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc
    reception = _reception(rid)
    if str(reception.get("status", "")).upper() != "COMPLETED":
        raise HTTPException(
            409,
            "Multi-Guard może czekać na akceptację dopiero po wydaniu sprzętu.",
        )

    link = _link_by_reception_id(rid)
    if not link:
        raise HTTPException(404, "Zlecenie nie ma licencji Multi-Guard.")
    link = _normalize_link(link)
    if not link.get("installation_id"):
        raise HTTPException(409, "Multi-Guard nie został jeszcze zainstalowany.")
    if link["lifecycle"] == "ACTIVE":
        return {"status": "already_active", **_public_status(link)}
    if link["lifecycle"] in {"EXPIRED", "REVOKED"}:
        raise HTTPException(409, f"Licencja ma stan {link['lifecycle']}.")

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET lifecycle='PENDING_ACCEPTANCE',
                    approved_at=now(),
                    updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {"id": link["id"]},
        ).mappings().one()
        link = _normalize_link(dict(row))
        _update_installation_mirror(connection, link)

    return {"status": "PENDING_ACCEPTANCE", **_public_status(link)}


@router.post("/multiguard/licenses/receptions/{reception_id}/release-channel")
def set_reception_release_channel(
    reception_id: str,
    body: ReleaseChannelRequest,
    user: CurrentUser = Depends(require_owner),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc

    channel = body.release_channel.strip().upper()
    if channel not in {"STABLE", "PILOT"}:
        raise HTTPException(400, "Kanał aktualizacji musi być STABLE albo PILOT.")

    link = _link_by_reception_id(rid)
    if not link:
        raise HTTPException(404, "Zlecenie nie ma licencji Multi-Guard.")

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET release_channel=:release_channel,
                    updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {
                "release_channel": channel,
                "id": link["id"],
            },
        ).mappings().one()
        link = _normalize_link(dict(row))
        _update_installation_mirror(connection, link)

    return _public_status(link)


@router.post("/multiguard/licenses/receptions/{reception_id}/reveal")
def reveal_reception_license(
    reception_id: str,
    user: CurrentUser = Depends(require_owner),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc
    link = _link_by_reception_id(rid)
    if not link:
        raise HTTPException(404, "Zlecenie nie ma licencji Multi-Guard.")
    return {
        **_public_status(link),
        "licenseKey": _keygate_reveal(link["keygate_license_id"]),
    }


@router.post("/multiguard/licenses/receptions/{reception_id}/rebind")
def rebind_reception_license(
    reception_id: str,
    user: CurrentUser = Depends(require_owner),
):
    try:
        rid = uuid.UUID(reception_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID zlecenia.") from exc
    link = _link_by_reception_id(rid)
    if not link:
        raise HTTPException(404, "Zlecenie nie ma licencji Multi-Guard.")
    link = _normalize_link(link)
    if link["lifecycle"] in {"EXPIRED", "REVOKED"}:
        raise HTTPException(409, f"Nie można przenieść licencji {link['lifecycle']}.")

    license_key = _keygate_reveal(link["keygate_license_id"])
    old_device_id = link.get("device_id") or ""
    if old_device_id:
        _keygate_deactivate(license_key, old_device_id)

    with engine.begin() as connection:
        if link.get("installation_id"):
            connection.execute(
                text(
                    """
                    UPDATE guard.installations
                    SET is_current=FALSE, updated_at=now()
                    WHERE installation_external_id=:installation_id
                    """
                ),
                {"installation_id": link["installation_id"]},
            )
        row = connection.execute(
            text(
                """
                UPDATE guard.license_links
                SET installation_id=NULL,
                    device_id=NULL,
                    credential_sha256=NULL,
                    app_version='',
                    rebind_pending=TRUE,
                    rebind_requested_at=now(),
                    updated_at=now()
                WHERE id=:id
                RETURNING *
                """
            ),
            {"id": link["id"]},
        ).mappings().one()
        link = _normalize_link(dict(row))

    return {
        **_public_status(link),
        "licenseKey": license_key,
        "message": "Licencja gotowa do instalacji na nowym komputerze. Data końcowa nie została zmieniona.",
    }


def _extend_active_license(
    reception_id: uuid.UUID,
    months: int,
    operation_id: uuid.UUID,
    *,
    source: str,
    payment_confirmed: bool,
    by_installation: bool = False,
) -> dict[str, Any]:
    """Append time to existing expiry, never to purchase date.

    Serialised per licence, idempotent by operation UUID, auditable.
    The KeyGate operation sets an absolute date rather than adding a period,
    so a retry after a partial failure cannot double-add time. A signed
    refreshed licence reaches the Windows client on its next sync.
    """
    if months not in (3, 6, 12):
        raise HTTPException(400, "Przedłużenie obejmuje 3, 6 albo 12 miesięcy.")
    if not payment_confirmed:
        raise HTTPException(400, "Potwierdź otrzymanie płatności od klienta.")
    if source not in {"WEB", "ANDROID"}:
        raise HTTPException(400, "Nieprawidłowe źródło operacji.")
    _ensure_schema()
    with engine.begin() as connection:
        # Lock the row before checking the existing operation, so two
        # concurrent requests serialize even with distinct request IDs.
        lookup = (
            "installation_id=:id" if by_installation
            else "reception_id=:id"
        )
        link = connection.execute(text(
            "SELECT * FROM guard.license_links WHERE " + lookup + " FOR UPDATE"
        ), {"id":reception_id}).mappings().first()
        if not link:
            raise HTTPException(404, "Zlecenie nie ma licencji Multi-Guard.")
        link = _normalize_link(dict(link))
        earlier = connection.execute(text("""
            SELECT months,previous_valid_until,new_valid_until,
                   license_link_id,created_at
            FROM guard.license_extensions
            WHERE id=:id
        """), {"id": operation_id}).mappings().first()
        if earlier:
            if earlier["license_link_id"] != link["id"] or int(earlier["months"]) != months:
                raise HTTPException(409, "Identyfikator operacji został już wykorzystany.")
            return {
                "status": "ALREADY_EXTENDED",
                "operationId": str(operation_id),
                "months": months,
                "oldValidUntil": _iso(earlier["previous_valid_until"]),
                "newValidUntil": _iso(earlier["new_valid_until"]),
                "edition": ("PRO" if link["plan_code"] == "multi_guard_pro" else "STANDARD"),
            }

        if link["lifecycle"] != "ACTIVE":
            raise HTTPException(409, "Przedłużyć można wyłącznie aktywną licencję klienta.")
        end = link.get("valid_until")
        if end is None or end <= _utcnow():
            raise HTTPException(409, "Licencja wygasła — wymagane osobne odnowienie.")
        new_end = _add_months(end, months)
        # Absolute-date mutation in KeyGate deliberately executes while
        # holding the local row lock. If database commit later fails, a
        # same-ID retry will safely request this absolute date again.
        _keygate_set_valid_until(link["keygate_license_id"], new_end)
        updated = connection.execute(text("""
            UPDATE guard.license_links
            SET valid_until=:end, updated_at=now()
            WHERE id=:id
            RETURNING *
        """), {"id": link["id"], "end": new_end}).mappings().one()
        _update_installation_mirror(connection, _normalize_link(dict(updated)))
        connection.execute(text("""
            INSERT INTO guard.license_extensions (
                id,license_link_id,keygate_license_id,months,
                previous_valid_until,new_valid_until,source,payment_confirmed
            ) VALUES (
                :op,:link,:license_id,:months,:old_end,:new_end,:source,TRUE
            )
        """), {
            "op": operation_id, "link": link["id"],
            "license_id": link["keygate_license_id"], "months": months,
            "old_end": end, "new_end": new_end, "source": source,
        })
        return {
            "status": "EXTENDED",
            "operationId": str(operation_id),
            "months": months,
            "oldValidUntil": _iso(end),
            "newValidUntil": _iso(new_end),
            "edition": ("PRO" if link["plan_code"] == "multi_guard_pro" else "STANDARD"),
        }


@router.post("/multiguard/licenses/receptions/{reception_id}/extend")
def extend_reception_license(
    reception_id: uuid.UUID,
    body: ExtendLicenseRequest,
    user: CurrentUser = Depends(require_owner),
):
    """OWNER Android/API endpoint. STAFF may not change paid licences."""
    return _extend_active_license(
        reception_id, body.months, body.operation_id,
        source="ANDROID", payment_confirmed=body.payment_confirmed,
    )


@router.post("/multiguard/licenses/installations/{installation_id}/extend")
def extend_direct_license_api(
    installation_id: uuid.UUID,
    body: ExtendLicenseRequest,
    user: CurrentUser = Depends(require_owner),
):
    """Owner-only extension for direct licences without repair orders."""
    _ensure_schema()
    with engine.connect() as con:
        direct = con.execute(text("""
            SELECT sale_kind FROM guard.license_links
            WHERE installation_id=:id
        """), {"id":installation_id}).mappings().first()
    if not direct or direct["sale_kind"] != "DIRECT":
        raise HTTPException(404, "Brak licencji bezpośredniej dla komputera.")
    return _extend_active_license(
        installation_id, body.months, body.operation_id, source="ANDROID",
        payment_confirmed=body.payment_confirmed, by_installation=True,
    )



@router.get("/multiguard/panel/license/installation/{installation_id}/extend",
            response_class=HTMLResponse)
def panel_direct_extension(
    installation_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    _ensure_schema()
    with engine.connect() as con:
        link = con.execute(text("""
            SELECT * FROM guard.license_links
            WHERE installation_id=:id AND sale_kind='DIRECT' LIMIT 1
        """), {"id":installation_id}).mappings().first()
    if not link:
        raise HTTPException(404, "Nie znaleziono licencji tego komputera.")
    link = _normalize_link(dict(link))
    if link["lifecycle"] != "ACTIVE" or not link.get("valid_until"):
        raise HTTPException(409, "Licencja nie jest aktywna.")
    title = _panel_escape("Pro" if link["plan_code"] == "multi_guard_pro" else "Standard")
    date = _panel_escape(link["valid_until"].strftime("%d.%m.%Y"))
    return HTMLResponse(_panel_html(f"""
      <section class="card">
        <a href="/multiguard/panel/pending/{installation_id}">← Komputer</a>
        <h1>Przedłuż licencję klienta — {title}</h1>
        <p>Obecna ważność do: <strong>{date}</strong></p>
        <p>Nowy okres doliczamy do obecnej daty wygaśnięcia, nie do dzisiaj.
           Zachowujemy dotychczasową edycję i dokumenty klienta.</p>
        <form method="post" action="/multiguard/panel/license/installation/{installation_id}/extend">
          <input type="hidden" name="csrf_token" value="{_workshop_csrf()}">
          <input type="hidden" name="operation_id" value="{uuid.uuid4()}">
          <label>Okres<select name="months">
            <option value="3">+3 miesiące</option>
            <option value="6">+6 miesięcy</option>
            <option value="12" selected>+12 miesięcy</option>
          </select></label>
          <label><input type="checkbox" name="payment_confirmed" value="yes" required>
            Potwierdzam otrzymanie płatności</label>
          <button type="submit">POTWIERDŹ PRZEDŁUŻENIE</button>
        </form>
      </section>
    """), headers={"Cache-Control":"private, no-store"})


@router.post("/multiguard/panel/license/installation/{installation_id}/extend",
             response_class=HTMLResponse)
def panel_direct_extension_post(
    installation_id: uuid.UUID,
    operation_id: uuid.UUID = Form(...),
    months: int = Form(...),
    csrf_token: str = Form(...),
    payment_confirmed: str = Form(""),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Wygasły formularz.")
    _ensure_schema()
    with engine.connect() as con:
        sale = con.execute(text("""
            SELECT sale_kind FROM guard.license_links
            WHERE installation_id=:id LIMIT 1
        """), {"id":installation_id}).mappings().first()
    if not sale or sale["sale_kind"] != "DIRECT":
        raise HTTPException(404,"Nie znaleziono licencji bezpośredniej.")
    result = _extend_active_license(
        installation_id, months, operation_id, source="WEB",
        payment_confirmed=(payment_confirmed=="yes"),by_installation=True,
    )
    new_date = _panel_escape(result["newValidUntil"][:10])
    return HTMLResponse(_panel_html(f"""
      <section class="card">
        <h1>Przedłużenie zapisane</h1>
        <p>Nowa ważność licencji: <strong>{new_date}</strong></p>
        <p>Wersja {result["edition"]} · +{result["months"]} miesięcy.
           Komputer pobierze zmieniony termin podczas kolejnego połączenia.</p>
        <a class="button-link" href="/multiguard/panel/pending/{installation_id}">
        WRÓĆ DO KOMPUTERA</a>
      </section>
    """), headers={"Cache-Control":"private, no-store"})


@router.get(
    "/multiguard/panel/license/{reception_id}/extend",
    response_class=HTMLResponse,
)
def panel_extend_license(
    reception_id: uuid.UUID,
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _csrf_token
    import time

    _ensure_schema()
    link = _link_by_reception_id(reception_id)
    if not link:
        raise HTTPException(404, "Nie znaleziono licencji dla tego zlecenia.")
    link = _normalize_link(link)
    if link["lifecycle"] != "ACTIVE" or not link.get("valid_until"):
        raise HTTPException(409, "Licencja nie jest aktualnie aktywna.")
    with engine.connect() as connection:
        history = connection.execute(text("""
            SELECT months,previous_valid_until,new_valid_until,created_at
            FROM guard.license_extensions WHERE license_link_id=:id
            ORDER BY created_at DESC LIMIT 30
        """), {"id": link["id"]}).mappings().all()
    history_html = "".join(
        f'<tr><td>{_panel_escape(h["created_at"].strftime("%d.%m.%Y"))}</td>'
        f'<td>+{int(h["months"])} mies.</td>'
        f'<td>{_panel_escape(h["previous_valid_until"].strftime("%d.%m.%Y"))}</td>'
        f'<td>{_panel_escape(h["new_valid_until"].strftime("%d.%m.%Y"))}</td></tr>'
        for h in history
    )
    token = _csrf_token(int(time.time() // 3600))
    operation = uuid.uuid4()
    name = _panel_escape(link["reception_number"])
    date_txt = _panel_escape(link["valid_until"].strftime("%d.%m.%Y"))
    edition = "Pro" if link["plan_code"] == "multi_guard_pro" else "Standard"
    return HTMLResponse(_panel_html(f"""
        <section class="card">
          <div class="eyebrow">MULTI-GUARD / PRZEDŁUŻENIE UPRAWNIEŃ KLIENTA</div>
          <h1>Przedłuż licencję</h1>
          <p><strong>{name}</strong> · Multi-Guard {edition}</p>
          <p>Aktualna data wygaśnięcia: <strong>{date_txt}</strong>.</p>
          <p>Nowy okres zostanie dodany do obecnej daty końcowej,
             nie do dnia płatności. Nie wymaga ponownej instalacji
             ani ponownej akceptacji niezmienionych dokumentów.</p>
          <form method="post" action="/multiguard/panel/license/{reception_id}/extend">
            <input type="hidden" name="csrf_token" value="{token}">
            <input type="hidden" name="operation_id" value="{operation}">
            <label>Dolicz okres
              <select name="months" required>
                <option value="3">3 miesiące</option>
                <option value="6">6 miesięcy</option>
                <option value="12" selected>12 miesięcy</option>
              </select>
            </label>
            <label><input type="checkbox" name="payment_confirmed" value="yes" required>
              Potwierdzam otrzymanie płatności i przedłużenie licencji</label>
            <button type="submit">POTWIERDŹ PRZEDŁUŻENIE</button>
          </form>
        </section>
        <section class="card">
          <h2>Historia przedłużeń</h2>
          <div class="table-wrap"><table>
            <thead><tr><th>Data operacji</th><th>Okres</th><th>Było ważne do</th>
            <th>Nowa data końcowa</th></tr></thead>
            <tbody>{history_html or '<tr><td colspan="4">Brak przedłużeń.</td></tr>'}</tbody>
          </table></div>
        </section>
    """), headers={"Cache-Control": "private, no-store"})


@router.post(
    "/multiguard/panel/license/{reception_id}/extend",
    response_class=HTMLResponse,
)
def panel_extend_license_post(
    reception_id: uuid.UUID,
    operation_id: uuid.UUID = Form(...),
    months: int = Form(...),
    csrf_token: str = Form(...),
    payment_confirmed: str = Form(""),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid

    if not _token_valid(csrf_token):
        raise HTTPException(403, "Nieprawidłowy formularz.")
    result = _extend_active_license(
        reception_id, months, operation_id,
        source="WEB", payment_confirmed=(payment_confirmed == "yes"),
    )
    return HTMLResponse(_panel_html(f"""
      <section class="card"><h1>Licencja przedłużona</h1>
        <p>Nowa data ważności: <strong>{_panel_escape(result["newValidUntil"][:10])}</strong></p>
        <p>{_panel_escape(result["edition"])} · +{int(result["months"])} miesięcy</p>
        <p>Multi-Guard pobierze nową datę po kolejnym połączeniu z serwerem.</p>
        <a class="button-link" href="/multiguard/panel/license/{reception_id}/extend">
          HISTORIA LICENCJI</a></section>
    """), headers={"Cache-Control": "private, no-store"})
