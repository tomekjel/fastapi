from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import settings


def _key() -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(settings.signing_seed_b64, validate=True)
    except Exception as exc:
        raise RuntimeError("BRIDGE_SIGNING_SEED_B64 must be valid Base64") from exc
    if len(raw) != 32:
        raise RuntimeError("BRIDGE_SIGNING_SEED_B64 must decode to 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def validate_signing_key() -> None:
    _key()


def public_key_b64() -> str:
    raw = _key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def license_payload(link: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "licenseId": link["keygate_license_id"],
        "serviceDeviceId": link["reception_number"],
        "installationId": link["installation_id"],
        "deviceId": link["device_id"],
        "planCode": link["plan_code"],
        "lifecycle": link["lifecycle"],
        "validFrom": _iso(link.get("valid_from")),
        "validUntil": _iso(link.get("valid_until")),
        "acceptedAt": _iso(link.get("accepted_at")),
        "acceptedDocuments": link.get("accepted_documents") or [],
        "serverTime": _iso(datetime.now(timezone.utc)),
    }


def signed_envelope(link: dict[str, Any]) -> dict[str, str]:
    payload = json.dumps(
        license_payload(link),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    signature = _key().sign(payload.encode("utf-8"))
    return {
        "payload": payload,
        "signatureB64": base64.b64encode(signature).decode("ascii"),
    }
