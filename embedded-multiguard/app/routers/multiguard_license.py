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


class AssignPendingInstallationRequest(BaseModel):
    reception_id: str = Field(alias="receptionId")
    edition: str
    months: int
    release_channel: str = Field(default="STABLE", alias="releaseChannel")

    model_config = {"populate_by_name": True}


_LICENSE_SOURCES = {"CLIENT", "WORKSHOP", "GROUP"}


def _normalize_license_source(value: str | None, *, default: str = "CLIENT") -> str:
    source = str(value or default).strip().upper()
    if source not in _LICENSE_SOURCES:
        raise HTTPException(400, "Źródło licencji musi być CLIENT, WORKSHOP albo GROUP.")
    return source


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
        "serviceDeviceId": str(link["service_device_id"]),
        "installationId": str(link["installation_id"] or ""),
        "deviceId": link.get("device_id") or "",
        "planCode": link["plan_code"],
        "releaseChannel": link.get("release_channel") or "STABLE",
        "licenseSource": str(link.get("license_source") or "CLIENT"),
        "sourceNote": str(link.get("source_note") or ""),
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
    reception_id UUID NOT NULL UNIQUE REFERENCES service.service_orders(id) ON DELETE CASCADE,
    reception_number TEXT NOT NULL UNIQUE,
    service_device_id UUID NOT NULL REFERENCES core.devices(id) ON DELETE RESTRICT,
    keygate_license_id TEXT NOT NULL UNIQUE,
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
        CHECK (status IN ('WAITING','ASSIGNED','PROVISIONED','IGNORED')),
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

CREATE TABLE IF NOT EXISTS guard.installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_device_id UUID NOT NULL REFERENCES core.devices(id) ON DELETE CASCADE,
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
    reception_id UUID NOT NULL REFERENCES service.service_orders(id) ON DELETE CASCADE,
    reception_number TEXT NOT NULL,
    keygate_license_id TEXT NOT NULL UNIQUE,
    edition TEXT NOT NULL CHECK (edition IN ('STANDARD','PRO')),
    duration_months INTEGER NOT NULL CHECK (duration_months IN (3,6,12)),
    valid_until TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_guard_activation_events_created
    ON guard.activation_events(id DESC);

ALTER TABLE guard.license_links
    ADD COLUMN IF NOT EXISTS release_channel TEXT NOT NULL DEFAULT 'STABLE';
ALTER TABLE guard.license_links
    ADD COLUMN IF NOT EXISTS license_source TEXT;
ALTER TABLE guard.license_links
    ADD COLUMN IF NOT EXISTS source_note TEXT;
ALTER TABLE guard.pending_installations
    ADD COLUMN IF NOT EXISTS license_source TEXT;
ALTER TABLE guard.pending_installations
    ADD COLUMN IF NOT EXISTS source_note TEXT;
ALTER TABLE guard.installations
    ADD COLUMN IF NOT EXISTS release_channel TEXT NOT NULL DEFAULT 'STABLE';
ALTER TABLE guard.installations
    ADD COLUMN IF NOT EXISTS license_source TEXT;
ALTER TABLE guard.installations
    ADD COLUMN IF NOT EXISTS source_note TEXT;
UPDATE guard.license_links
SET license_source='CLIENT'
WHERE license_source IS NULL AND reception_id IS NOT NULL;
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
        "licenseSource": str(row.get("license_source") or ""),
        "sourceNote": str(row.get("source_note") or ""),
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
    return f"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Multi-Servis — Multi-Guard</title>
<style>
:root{{font-family:Segoe UI,Arial,sans-serif;color:#eef7ff;background:#06101f}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;background:#06101f}}
main{{width:min(1480px,96vw);margin:28px auto 64px}}
nav{{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 16px}}
nav a,.button-link{{display:inline-block;padding:10px 14px;border:1px solid #2d5677;border-radius:9px;background:#0a192b;color:#d8efff;text-decoration:none;font-weight:700}}
nav a:hover,.button-link:hover{{background:#12304d}}
.card{{background:#0a192b;border:1px solid #23425f;border-radius:18px;padding:22px;margin-bottom:16px;box-shadow:0 20px 60px #0007}}
h1,h2{{margin:0 0 8px}}p{{color:#9fb4c8;line-height:1.5;margin:6px 0 14px}}
form{{display:grid;gap:14px}}label{{display:grid;gap:6px;font-size:13px;color:#c8d9e8}}
input,select{{width:100%;padding:12px;border:1px solid #2d5677;border-radius:9px;background:#07182a;color:#eef7ff}}
button{{border:0;border-radius:9px;padding:12px 16px;background:#139ce7;color:#fff;font-weight:700;cursor:pointer}}
.grid{{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin-top:16px}}
.metric{{padding:14px;border:1px solid #23425f;border-radius:12px;background:#07182a}}
.metric b{{display:block;color:#9fb4c8;font-size:12px;margin-bottom:5px}}
.metric strong{{font-size:26px}}
.section-head{{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;flex-wrap:wrap}}
.table-wrap{{overflow:auto;border:1px solid #1d3b57;border-radius:12px}}
table{{width:100%;border-collapse:collapse;min-width:900px}}
th,td{{padding:11px 12px;text-align:left;border-bottom:1px solid #17334d;vertical-align:top}}
th{{position:sticky;top:0;background:#0d2138;color:#b8d2e8;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
tr:hover td{{background:#0c1f34}}
.badge{{display:inline-block;padding:3px 7px;border-radius:999px;background:#163451;border:1px solid #2d5677;font-size:12px;font-weight:700}}
.good{{color:#61e7a2;border-color:#267f5b}}.warn{{color:#ffd27a;border-color:#84641e}}.bad{{color:#ffad72;border-color:#9a4f24}}.critical{{color:#ff7c7c;border-color:#a63131}}
.muted{{color:#7892a9;font-size:12px}}
.mono{{font-family:Consolas,ui-monospace,monospace}}
.numbers{{white-space:nowrap}}
.detail-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:14px}}
.detail-grid>div{{padding:12px;border:1px solid #23425f;border-radius:10px;background:#07182a}}
.detail-grid b,.detail-grid span{{display:block}}.detail-grid span{{margin-top:5px;color:#cce0ef}}
.key{{display:block;padding:15px;margin:14px 0;background:#03101c;border:1px solid #24618c;border-radius:10px;color:#67e5ff;font:700 15px Consolas,monospace;word-break:break-all}}
a{{color:#67c8ff}}.ok{{color:#48d99a}}
.eyebrow{{font-size:11px;font-weight:800;letter-spacing:.14em;color:#64cfff;margin-bottom:6px}}
.telemetry-hero{{background:linear-gradient(135deg,#0a192b 0%,#0b2035 55%,#071421 100%);border-color:#2b5b7e}}
.telemetry-status{{display:flex;flex-direction:column;align-items:flex-end;gap:7px}}
.filter-bar{{display:flex;grid-template-columns:none;flex-wrap:wrap;align-items:end;gap:10px}}
.filter-bar label{{min-width:150px}}.filter-bar .filter-grow{{flex:1 1 320px}}
.problem-title{{font-size:14px;color:#f2f8ff}}
.button-link.compact{{padding:7px 10px;font-size:12px;white-space:nowrap}}
.telemetry-table td{{vertical-align:middle}}
@media(max-width:720px){{.telemetry-status{{align-items:flex-start}}.filter-bar{{display:grid;grid-template-columns:1fr}}}}
@media(max-width:720px){{main{{width:96vw;margin-top:14px}}.grid{{grid-template-columns:1fr}}.card{{padding:15px}}}}
</style>
</head>
<body>
<main>
<nav>
  <a href="/multiguard/panel/dashboard">PULPIT</a>
  <a href="/multiguard/panel/dashboard#devices">URZĄDZENIA</a>
  <a href="/multiguard/panel/telemetry">TELEMETRIA / ROZWÓJ</a>
  <a href="/multiguard/panel/licenses">LICENCJE</a>
  <a href="/multiguard/panel">NOWA LICENCJA</a>
</nav>
{body}
</main>
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
        "serviceDeviceId": str(link["service_device_id"]),
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


@router.post("/v1/multi-guard/discovery/assignment")
def discovery_assignment(req: DiscoveryAssignmentRequest):
    pending = _authenticate_pending(
        req.installation_id,
        req.device_id,
        req.discovery_credential,
    )

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE guard.pending_installations
                SET last_seen_at=now(),updated_at=now()
                WHERE installation_id=:installation_id
                """
            ),
            {"installation_id": pending["installation_id"]},
        )

    reception_id = pending.get("assigned_reception_id")
    if not reception_id or pending["status"] == "WAITING":
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
    lifecycle = (
        link["lifecycle"]
        if link.get("rebind_pending") and link["lifecycle"] != "UNASSIGNED"
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
        "requiredDocuments": [],
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
    device = " ".join(
        part for part in [
            public["manufacturer"].strip(),
            public["model"].strip(),
        ] if part
    ) or public["hostname"] or "Nieznany komputer"

    return _panel_html(
        f"""
        <section class="card">
          <a href="/multiguard/panel/dashboard">← Wróć do pulpitu</a>
          <h1>Przypisz {_panel_escape(public['shortId'])}</h1>
          <p>
            <b>{_panel_escape(device)}</b>
            • wersja {_panel_escape(public['appVersion'] or '—')}
            • {'ONLINE' if public['online'] else 'offline'}
          </p>
          <p>
            Serial: {_panel_escape(public['serialNumber'] or '—')}
            • host: {_panel_escape(public['hostname'] or '—')}
          </p>
          <form method="post" action="/multiguard/panel/pending/{installation_id}/assign">
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
            </div>
            <button type="submit">PRZYPISZ I PRZYGOTUJ LICENCJĘ</button>
          </form>
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
    months: int = Form(...),
    release_channel: str = Form("STABLE"),
    _: None = Depends(_panel_auth),
):
    try:
        iid = uuid.UUID(installation_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe ID instalacji.") from exc

    reception = _reception_by_number(reception_number)
    link = _assign_pending_to_reception(
        iid,
        reception["id"],
        edition,
        months,
        release_channel,
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


@router.get("/multiguard/panel", response_class=HTMLResponse)
def multiguard_panel(
    _: None = Depends(_panel_auth),
):
    return _panel_html(
        """
        <section class="card">
          <h1>Multi-Servis — Multi-Guard</h1>
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
          <p class="warn">Po wpisaniu klucza w Multi-Guard uruchomi się SERVICE_TEST. Czas licencji jeszcze nie biegnie.</p>
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
