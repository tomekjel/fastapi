"""Pure fail-closed entitlement selection policy for Multi-Guard OWNER.

Customer Standard/Pro KeyGate licences are *not* revoked when OWNER selects
a separate, perpetual service grant.  Only the selected mode may be used
by discovery, signed refresh, paid remote and workshop remote entrypoints.

This module intentionally does not write SQL or call KeyGate/MeshCentral.
It is shared by the future route wiring and can be tested in isolation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

Mode = Literal["CLIENT", "SERVICE", "NONE"]
_ALLOWED_MODES = frozenset(("CLIENT", "SERVICE", "NONE"))
_PENDING_ALLOWED = frozenset(("WAITING", "ASSIGNED", "PROVISIONED"))


def resolve_mode(
    explicit_mode: str | None,
    *,
    has_customer_link: bool,
    has_service_grant: bool,
) -> Mode:
    """Legacy paid installation always wins, including an expired/revoked link.

    A service grant is selected only when explicitly requested by OWNER or
    when there is no customer link at all. Invalid stored values fail closed.
    """
    if explicit_mode is not None:
        value = explicit_mode.strip().upper()
        if value not in _ALLOWED_MODES:
            raise ValueError("Unknown OWNER entitlement mode")
        return value  # type: ignore[return-value]
    if has_customer_link:
        return "CLIENT"
    if has_service_grant:
        return "SERVICE"
    return "NONE"


def _utc_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc)


def paid_pro_authorized(
    mode: Mode,
    *,
    edition: str,
    lifecycle: str,
    valid_until: datetime | None,
    now: datetime,
) -> bool:
    """Paid Pro remote support ALWAYS requires a separate per-session consent."""
    current = _utc_aware(now)
    end = _utc_aware(valid_until)
    return bool(
        mode == "CLIENT"
        and edition == "PRO"
        and lifecycle == "ACTIVE"
        and current is not None
        and end is not None
        and current < end
    )


def service_grant_authorized(
    mode: Mode,
    *,
    enabled: bool,
    edition: str,
    pending_status: str,
    valid_until: datetime | None,
    now: datetime,
    require_pro: bool = False,
) -> bool:
    """A disabled, expired, unknown or unselected service grant never authorizes."""
    current = _utc_aware(now)
    end = _utc_aware(valid_until)
    if current is None or mode != "SERVICE" or not enabled:
        return False
    if edition not in ("STANDARD", "PRO"):
        return False
    if require_pro and edition != "PRO":
        return False
    if pending_status not in _PENDING_ALLOWED:
        return False
    if valid_until is not None and (end is None or current >= end):
        return False
    return True


def unattended_service_authorized(
    mode: Mode,
    *,
    enabled: bool,
    edition: str,
    pending_status: str,
    valid_until: datetime | None,
    now: datetime,
    standing_authorization_valid: bool,
) -> bool:
    """Permanent OWNER authorization and local opt-in are additionally required.

    The caller MUST verify the stored Mesh node identity, standing authorization,
    revocation flag and local attestation; this flag is never supplied by agent
    input alone. A paid PRO licence must not bypass the client prompt.
    """
    return bool(
        standing_authorization_valid
        and service_grant_authorized(
            mode,
            enabled=enabled,
            edition=edition,
            pending_status=pending_status,
            valid_until=valid_until,
            now=now,
            require_pro=True,
        )
    )
