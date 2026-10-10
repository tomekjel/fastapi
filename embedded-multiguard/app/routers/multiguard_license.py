from __future__ import annotations

import base64
import calendar
import hashlib
import html
import json
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

    Workshop permission is open-ended on the server, but each client lease
    is only trusted for a short offline grace period and must be refreshed.
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
            WHERE installation_id=:id FOR UPDATE
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
        created = _keygate_create_license(
            reception_number=reference, edition=edition, months=months,
        )
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
        con.execute(text("""
            UPDATE guard.pending_installations SET
                status='ASSIGNED',assigned_reception_id=NULL,
                assigned_license_id=:license_id,
                assigned_at=now(),updated_at=now()
            WHERE installation_id=:id
        """), {"license_id":lic["keygate_license_id"],"id":installation_id})
        con.execute(text("""
            UPDATE guard.workshop_grants SET enabled=FALSE,updated_at=now()
            WHERE installation_id=:id AND enabled=TRUE
        """), {"id":installation_id})
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
        <img alt="" width="42" height="42" style="display:block;object-fit:contain" src="data:image/webp;base64,UklGRpAMAABXRUJQVlA4TIMMAAAvKUAKAA0wbNs2Um2nxafuP/A9M0T0fwL05PexjU0Au6Z3coGqaeitcWfNI8kAnjqHjz5tWkvW6rNKUpLHGJITer05DNzGtq0q67tEP9QS6L8i5oe4cwdtwo1t22qycakoKTP/0eDu7poEZ8GOJMlRVWj8twwPLgOt4YnPi4v+J/5CNqxmVkdwBVC7toR9mLi2AICTV2vLzJ8/ZjtHALleep30+f3SuvnnWehWPN7KTzHvyX9msjdJbfL8+r5f5vF0yt+ECbObhHvyfLhwkdrfnpbZ0uZgk0PCHaXFInkHY1zGSF/58k/rylWYXhpZ7UkwzMHAwJNeeoUdRhySblMiYANY4dnLLMxtZoz9mzd2IJjg3ZHaP8x6AIKCtm0Yhz/sHQwRMQFmaEIflOdrr4cR2ctdba1aqF3bXki2d/S+b5JqjW0t7HVs27Zt27ZtfbW9bdu2xuzu6amurqok7xFlybZN21brY6591jkb1/c+2yjbr/RK5n/4lfyK5l+oZtu27XO5tdacs/utbVu1bdu2Uiql1tbGCIuZNdpkwJa3J9uEbdU2Ym91y7xFZppMva/eWs2RsmPbVq1ozn3RT0KzPAjVSYN2fe+e2ZIExEiSHClZs2sc0hg8wGsNI6GRJEmSLHKOP8eXxWx5qG3bhtldU55o0ZdECVoiMSQtacGQDEkLpmRIStASFUNQAgWFdqtssStH+j3yD71404x2kxx/lIoJ3T/qeEYB3Hmrd9y3ervWfA0nUYIhKcGQtKQFU9KSJjZJK1pQknZo6RZqSRGunWSdN5i3Qy549OL9NbKr7v6d3ti/2HHbK2rp+/Phy0chJyG7dhbL3vIxIChJCZoYiqFoYlO0oCVDMhRD0MrT0XCQGJKS2H6WSP0Mex52ygXWR+WB3fnvv0d9O0EFeMjp97Of/PfofI8GOvxkgSkmgpa0oAQtmYJWTIeWDGIqpmIqT4fpaDgM8nBUkj6ZTmf4+Wk+y5/FGWAy4a4nMtAdUfAWypFEBNDYAR5ggQBwaCxl4wZARAmIFVTHUxwwmVGS5HC5mXLr23JktVAC7tuxjKHAokZLUkJYwgMIwMNEh4FOIwIUYUytavqy27yCwYOyIx80HfW84UAqJ6/1ji4Hj2SBYgcBACAAYRQdDoNAGGBjkI1Cp5cBHa1E6R0N2/Wg9Yzfnnflb4644FHpfsDf78D0HVgCABAIgAUlACLIkE4U7bRB+x8WNEwAw/AwXYxOa64aPjjklF/cc+MvW457Cj9+CbsB7gAAwIAAcFCECAhgoW6Lrt8JSqYAJzkFGQCm+w8duzx6D33D7MgJ49eOXQI/fB9409Br6EVvjrWfdM9vlf0P2VG2gzEnnEedszgEAAMwkvP8ST9/45Kf6dHHhntGi4YVJROsHaa0EN3Z9fipeEMOzsgyADz3b8yv+/Y9IhvNW6vSjeaNDHq6/lkrv2TV6+mgE2gDAG6X+/lx5ef7Vxf9tHy4GQaDITQAwKZJiMqd3h4+dvf6uzILALBknNfqjCRLlmOP/7p6bQiGRQOWk1nI0e8F3Z6xFgDCfHiV8Kfe6/lV1l+UBLRIK4IQoFhkZ+e9fbp++H//xoDFpeMsH6cwu++vr6k8Ryb4vZqbIQyGMCc2K9ktbI5H2hdFEEDjjtfXXPiPRe3hTzcuhst25yVZdFkA5CGiBJBVmemsnaVYmGrnr7r9ViRqB0V1V2wyyig2MMIKiKUH6di+jp49+4AbSO0ioSjbxt/YMpem5CC75HB3IQREkbcEiIAIae1kbilIEEY1WkolsYp1V1FAUWC1LGUFNKSGZMbXR2ZPrglg5zvr8ni0uEdua7GCxq6PsnofoNx2mTU7s+mgMFJCiIjK9uy3/lwOAJR7CCQGNWhQKZgghZMarMKNXVDPk4/rS5BQ3/nQd7/nBYNzHVfXsIDErob8Lz8rUQno2WE/IgsvpUBJ1qY1OH7RIZgcmajuMloSgmZ5JYPcj0BOMCkRPnY3XnHqD56V8FdWl+3xssHKWbib2r8JVgSqhlYEYOZTHPTv19pdsu2FHWUgnkdEAgrS2bdl3R0HTDH4HpNaStO3DhGhG/XGf46dOnbqy//a/MvY4+frx7vDAPDR6/ufn0c13fgU8icMTarYzXfz7hRuKzCde9L5UI7SQ8bi8b6tAggClFxaBf31rNGAno2M9bJqvR0iEJwdf6cjZGD4s459+teWd2FY1/vYGZsgFYtqSytkSppooKLd9FbtwRoJ8uu7OfnnG0Kx2L1GZCiBVmrSh/eHlUZOi6bW5v9FBkWBWTip9ZQ2AW6olfFi+HjW1f2IDmbbPLlUmYhSsxoFANZ2lt1JxtyiGjD1nei71n48pEp2o9mcvLhQyx3mtAh0ATKPEbc2IZLYKJIrtv1oEzKEYMzGLmcyyG9X/XO2JwYG6BSTFqhYYYkKgIDk5qOBHHZ6714/xl6Ti8rLgKKNAc7kpPy2qSJK/PbRzaUu5kxT98XW275ZsgvJJiEUri7WAAiYW+dDF08nqrWLl+rLj84O3kGhkg4pRCy17H25Wrpp0jEO8YZuZiztmTHH6np8OrVBZAWSxqGQUOYWFZRAMQlJsbCAkNYSum83A7SNtfKbPLwlDAcESCnY/bf+gmgyekAnmaJ2HB3d3m+vexAfBSAAkoMBwP8LjAEAx8i+A0OpdWQH30iADTmgyCGVtzTIICWH8ej4TKcxSKzxPJG4DiGDUAQBYJQoFAxJiMbsjAAYAFiiIZWNZQHfLHA5yUaIINFEWinUGb1UM/OmHWFxMTFO06HogiCe1svBWawO1w11ZEC6uMCol0Y30iuEAWAQJEwwcIQFAiCrBvj/BbqhntMBT7hTZNni7M7g24gMwdNGLKrRzYs362DIJwNyczqc7jWMRsoCcAvAIoBv/cmRv4gJLACLoxHRpcNAWCEw4QENghoRmf/K6aeizVrIkCSJgKmI17a5Q0yIAx3SOxW7oAqqbCUgVhqZw8Y4i7rbX4dSMK38Dh89rtIzytTphgyJweg8B7cau7uifywypCRHARRAiCrixLKvqriQgCNjWYNFVKMAYomx1rimSfzGy5nleG7VVZMZ0frylb9+/Jgrfp5X5/ofJhQmhzkuzhwVyMW7Kfz3LW/0ZiTOdSMFm6ahS9jUYh28gwBPiFU1P3KD0ImmESvEYvFjma+VyaDls2Xe3cEw2RWf3QdNTISFrRbv69krdzNdGlpPfr5p/Q+CD3tIDUb4phCDI0rhyMpRuhaAGrxicBnYdnh2bLTdDZeKOraK5Qawb96/L8M3DEOG4YGO3bzBzbJCarHyV24IYouWj/546+9FsaeK9WHGX1AsgkMa0d7W3dfWELrVO5qjdf7ynQ48/9zYz20NOWjUKto7ZH4DcKzLx26q3w5DyVGk2CEAapM6q7jyGLLyyp8k4su+OAp4TcVdwGvRjAAZpB1XP7ev6oxAovpu+/LH9XO25s7dUJ3ppgjj2dq/zJu9dWY3eqm+aqY6WrE49uWn/bmBi1zBr1ilKHfjgQ8y/38t0p42lfqwx3eJJIUYxU4f3fb+q7B6EqcHKtJV1aksQMRIdKEFBMen1EblsItFtWjgPEXlN0+fKLfGOBICAKnqw7qb3+egl0P6tX344SgVVSWGE6XptDOXXT1anHriA1oH8nIy45TuhkqxCy2gIVmbA78tkw7gKk2RxhcOuhDCcthCwJMMZJQhaNVXyLtSL4X2FFSIEX0AdUOlkQAQQmu4fzrnsUWWs3D3Ui5UWcqClTYSJrIreGvXtroNUCEZqrXra5i3A+thEor8XoR3rGFUqmhVFDG4aWjRABp0UUkPW1WT4JvsykVl2h0QKAZDsU6nu+zLjVIdW8ZIWIKnDh9kSSACJwCDkl2zwFiUqjZGqgDDgL1h00bMaz+lngQgsRX3C/a8c23nTBobFgQNiT20DjNfoAuCGCN8bkIlAAb4+OAbOSUZhVoVzRjQJts6IRgkxRkljaREmhBs+S2S5IABBKMHJfL9KAAtDehUw/6zjm2L3ve42JdqYUISCnoCFJLRaCJrUSG1wY4+yYBcUUpIJYUBYGHBxbT8uCkHrLEK1flbZT27r/8SN7BQVtNQIQmARpSwKXKDVVWRTY6zgbWILFJq6AIQmJVD0Im7wpHVma8yhh107/K/SQ8ti1mBaBaGJSoRTccuUCQQgw1RRqI0MjJ5HNgJIZQQI0FAtVEaKUGxO8BgScJjKYEgFUMAISvLW34MQQYFAMoYTS+yYGLAKh5HlhqCOHZVNI3CIhNFWKywAAA=">
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
                  AND reported_at < now() - interval '30 days'
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
    if received != expected:
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
                    ("OFF","Wyłączone"),("STANDARD","Standardowy"),
                    ("OBSERVATION","Obserwacja"),("INTENSIVE","Intensywny"),
                )
            )
            controls = f"""
              <div class="owner-service-controls">
                <form method="post" action="/multiguard/panel/workshop/{iid}/monitoring">
                  <input type="hidden" name="csrf_token" value="{token}">
                  <label>Monitorowanie rozszerzone
                    <select name="profile" aria-label="Poziom monitorowania dla {display}">
                      {options}
                    </select>
                  </label>
                  <button type="submit">ZAPISZ MONITOROWANIE</button>
                </form>
                <a class="button-link compact" href="/multiguard/panel/workshop/{iid}/reports">
                  HISTORIA RAPORTÓW
                </a>
                <button type="button" class="pending-archive-trigger"
                  onclick="document.getElementById('disable-workshop-{iid}').showModal()">
                  WYŁĄCZ TRYB SERWISOWY
                </button>
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
            + link + "</td><td>" + edition + "</td><td>" + status
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
          <thead><tr><th>Komputer / zlecenie</th><th>Edycja</th>
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
        summary=row["summary"] or {}
        sample_list=summary.get("samples",[])
        if not isinstance(sample_list,list):
            sample_list=[]
        if not isinstance(summary,dict):
            summary={}
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
    profile: str = Form(...),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403, "Wygasły lub nieprawidłowy formularz.")
    if profile not in {"OFF","STANDARD","OBSERVATION","INTENSIVE"}:
        raise HTTPException(400, "Nieznany poziom monitorowania.")
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


@router.get("/multiguard/panel", response_class=HTMLResponse)
def multiguard_panel(
    _: None = Depends(_panel_auth),
):
    return _panel_html(
        f"""
        {_owner_workshop_manager_panel()}
        <section class="card">
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
