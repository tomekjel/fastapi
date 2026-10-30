"""Pure fail-closed entitlement selection policy for Multi-Guard OWNER.

Standard, Pro and Service are three independent editions. Every edition may
have a fixed term or be perpetual. Switching effective rights never revokes an
independent stored KeyGate licence.  Only the selected mode may be used
by discovery, signed refresh, paid remote and workshop remote entrypoints.

This module intentionally does not write SQL or call KeyGate/MeshCentral.
It is shared by the future route wiring and can be tested in isolation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

LicenseEdition = Literal["STANDARD", "PRO", "SERVICE"]
LicensePeriod = Literal["TIMED", "PERPETUAL"]
_ALLOWED_EDITIONS = frozenset(("STANDARD", "PRO", "SERVICE"))
_ALLOWED_PERIODS = frozenset(("TIMED", "PERPETUAL"))
_ALLOWED_MONTHS = frozenset((3, 6, 12))


def validate_license_variant(
    edition: str,
    period: str,
    months: int | None,
) -> tuple[LicenseEdition, LicensePeriod, int | None]:
    """Validate all six combinations. Time period is NOT implied by edition.

    A timed licence must declare its term. A perpetual one cannot silently
    inherit a previous customer's expiration or a service lease.
    """
    normalized_edition = edition.strip().upper()
    normalized_period = period.strip().upper()
    if normalized_edition not in _ALLOWED_EDITIONS:
        raise ValueError("Unknown license edition")
    if normalized_period not in _ALLOWED_PERIODS:
        raise ValueError("Unknown license period")
    if normalized_period == "TIMED":
        if type(months) is not int or months not in _ALLOWED_MONTHS:
            raise ValueError("Timed licence requires 3, 6 or 12 months")
    elif months is not None:
        raise ValueError("Perpetual licence cannot have a duration in months")
    return normalized_edition, normalized_period, months  # type: ignore[return-value]


def license_within_period(
    period: str, valid_until: datetime | None, now: datetime,
) -> bool:
    """Do not infer perpetual rights from a missing legacy paid end date."""
    current = _utc_aware(now)
    if current is None:
        return False
    if period == "PERPETUAL":
        return valid_until is None
    if period == "TIMED":
        end = _utc_aware(valid_until)
        return end is not None and current < end
    return False


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
