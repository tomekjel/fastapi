"""MASTER 1.5 / 3-of-6 — signed OWNER profile-transition grant codec.

Pure contract shared with MultiGuardProfileManager; this module does NOT
expose an HTTP route, choose an edition, or perform a profile transition.
The OWNER-authorization endpoint must independently check current edition,
device identity, and active customer/workshop sessions before calling it.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from typing import Callable

PURPOSE = "MULTIGUARD_OWNER_PROFILE_TRANSITION_V1"
TARGETS = frozenset({"STANDARD", "PRO", "SERVICE"})
MAX_GRANT_SECONDS = 120


def create_profile_transition_grant(
    *,
    installation_id: UUID,
    device_id: str,
    target: str,
    signing_key,
    issued_at: datetime | None = None,
    request_id: UUID | None = None,
) -> dict[str, str]:
    """Sign exact compact JSON bytes using the already configured Ed25519 key.

    Caller MUST authenticate the installation and OWNER's selected edition;
    mere possession of a discovery credential is not OWNER authorization.
    This function cannot be invoked directly by an external request.
    """
    if target not in TARGETS:
        raise ValueError("UNSUPPORTED_OWNER_PROFILE")
    if installation_id.int == 0 or not device_id.strip() or len(device_id) > 128:
        raise ValueError("INVALID_INSTALLATION_IDENTITY")
    issued = issued_at or datetime.now(timezone.utc)
    if issued.tzinfo is None or issued.utcoffset() is None:
        raise ValueError("UNTRUSTED_CLOCK")
    issued = issued.astimezone(timezone.utc)
    uid = request_id or uuid4()
    if uid.int == 0:
        raise ValueError("INVALID_REQUEST_ID")
    def iso(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    payload = json.dumps({
        "schemaVersion": 1,
        "purpose": PURPOSE,
        "installationId": str(installation_id),
        "deviceId": device_id,
        "requestId": str(uid),
        "target": target,
        "issuedAt": iso(issued),
        "expiresAt": iso(issued + timedelta(seconds=MAX_GRANT_SECONDS)),
    }, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    signature = signing_key.sign(payload.encode("utf-8"))
    return {"payload": payload, "signatureB64": base64.b64encode(signature).decode("ascii")}
