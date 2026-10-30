"""Pure fail-closed entitlement selection policy for Multi-Guard OWNER.

Standard, Pro and Service are three independent editions. Every edition may
have a fixed term or be perpetual. Switching effective rights never revokes an
independent stored KeyGate licence.  Only the selected mode may be used
by discovery, signed refresh, paid remote and workshop remote entrypoints.

This module intentionally does not write SQL or call KeyGate/MeshCentral.
It is shared by the future route wiring and can be tested in isolation.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

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


def license_term_selection(
    edition: str,
    period: str,
    *,
    preset_months: int | None = None,
    calendar_date: date | None = None,
) -> tuple[LicenseEdition, LicensePeriod, int | None, date | None]:
    """The UI has three presets AND an arbitrary day picker, independent of edition.

    Perpetual is an explicit selection, never inferred from a missing date.
    A timed licence requires exactly one of the preset or calendar date.
    """
    edition = edition.strip().upper()
    period = period.strip().upper()
    if edition not in _ALLOWED_EDITIONS:
        raise ValueError("Unknown license edition")
    if period not in _ALLOWED_PERIODS:
        raise ValueError("Unknown license period")
    if period == "PERPETUAL":
        if preset_months is not None or calendar_date is not None:
            raise ValueError("Perpetual licence has no expiration selection")
    else:
        has_preset = preset_months is not None
        has_calendar = calendar_date is not None
        if has_preset == has_calendar:
            raise ValueError("Choose 3/6/12 months OR an expiration date")
        if has_preset and (type(preset_months) is not int or preset_months not in _ALLOWED_MONTHS):
            raise ValueError("Only preset 3/6/12 months is supported")
        if has_calendar and type(calendar_date) is not date:
            raise ValueError("Calendar expiration must be a calendar date")
    return edition, period, preset_months, calendar_date  # type: ignore[return-value]


def calendar_valid_until(
    chosen_day: date,
    *,
    now: datetime,
    tz_name: str = "Europe/Warsaw",
) -> datetime:
    """Inclusive local calendar day -> exclusive start of the next local day (UTC).

    Allows one or two weeks, or any chosen future day. Using local midnight
    avoids DST errors and avoids expiring at the START of the chosen day.
    """
    if type(chosen_day) is not date:
        raise ValueError("Incorrect calendar date")
    if now.tzinfo is None:
        raise ValueError("Current time must have a timezone")
    tz = ZoneInfo(tz_name)
    if chosen_day < now.astimezone(tz).date():
        raise ValueError("The chosen day has already passed")
    next_midnight_local = datetime.combine(chosen_day + timedelta(days=1), time.min, tzinfo=tz)
    end_utc = next_midnight_local.astimezone(timezone.utc)
    if end_utc <= now.astimezone(timezone.utc):
        raise ValueError("The license end date must be in the future")
    return end_utc


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



def owner_valid_until(
    edition: str,
    choice: str,
    calendar_day: str,
    *,
    now: datetime,
    existing_end: datetime | None = None,
    extend: bool = False,
) -> datetime | None:
    """Term policy for all three editions, with a single explicit expiry choice.

    3/6/12 add *calendar months*. An extension preserves unused paid time:
    remaining 2 months plus 12 months ends 14 months from now. No existing
    KeyGate fields, record or licence state are changed by this pure function.
    A calendar end covers the entire chosen Warsaw day, inclusive.
    'PERPETUAL' is a separate, intentional selection, not missing data.
    """
    edition = edition.strip().upper()
    if edition not in _ALLOWED_EDITIONS:
        raise ValueError("Unknown license edition")
    current = _utc_aware(now)
    if current is None:
        raise ValueError("Current UTC time is required")
    current_end = _utc_aware(existing_end)
    if existing_end is not None and current_end is None:
        raise ValueError("Existing expiry requires a timezone")
    selected = choice.strip().upper()
    raw_day = calendar_day.strip()

    if selected == "PERPETUAL":
        if raw_day:
            raise ValueError("Perpetual licence cannot retain a calendar date")
        return None

    if selected == "CALENDAR":
        if not raw_day:
            raise ValueError("A calendar day is required")
        try:
            chosen = date.fromisoformat(raw_day)
        except ValueError as exc:
            raise ValueError("Invalid calendar day") from exc
        if chosen.isoformat() != raw_day:
            raise ValueError("Calendar day must be ISO YYYY-MM-DD")
        target = calendar_valid_until(chosen, now=current)
        if extend and current_end and target <= current_end:
            raise ValueError("Extension cannot shorten the existing paid term")
        return target

    if selected in ("3", "6", "12"):
        if raw_day:
            raise ValueError("Preset months cannot include a calendar day")
        import calendar
        base = max(current, current_end) if extend and current_end else current
        months = int(selected)
        month_index = base.month - 1 + months
        year = base.year + month_index // 12
        month = month_index % 12 + 1
        day = min(base.day, calendar.monthrange(year, month)[1])
        return base.replace(year=year, month=month, day=day)

    raise ValueError("An explicit licence term is required")


def service_valid_until(
    choice: str, calendar_day: str, *, now: datetime,
) -> datetime | None:
    """Service expiry; legacy caller compatibility, no implicit extension."""
    return owner_valid_until("SERVICE", choice, calendar_day, now=now)



def plan_grid_license_change(
    *,
    current_mode: str,
    current_edition: str,
    target_edition: str,
    term_choice: str,
    term_date: str,
    now: datetime,
    paid_valid_until: datetime | None,
    service_valid_until_current: datetime | None = None,
    paid_edition: str | None = None,
    explicit_paid_perpetual_supported: bool = False,
) -> dict[str, object]:
    """Plan OWNER grid Save without writes to KeyGate, SQL or MeshCentral.

    Keeps customer KeyGate terms and OWNER service permissions separate.
    The known KeyGate adapter supports 3/6/12 month extension and a fixed
    expiration date; it does NOT prove support for perpetual paid contracts.
    Such a selection must fail closed instead of storing a NULL paid expiry.
    Caller must validate authenticated OWNER, CSRF, stale version, live Mesh
    sessions and explicit payment before executing any returned action.

    A service grant's expiry is independent of the customer's paid expiry.
    A return to CLIENT must retain the original paid term and key.
    """
    selected_mode = current_mode.strip().upper()
    old = current_edition.strip().upper()
    new = target_edition.strip().upper()
    choice = term_choice.strip().upper()
    if selected_mode not in ("CLIENT", "SERVICE"):
        raise ValueError("Missing or invalid OWNER selected mode")
    if old not in ("STANDARD", "PRO", "SERVICE"):
        raise ValueError("Invalid existing license edition")
    if new not in _ALLOWED_EDITIONS:
        raise ValueError("Invalid target license edition")
    if old == "SERVICE" and selected_mode != "SERVICE":
        raise ValueError("Service edition and selected mode conflict")
    if old != "SERVICE" and selected_mode != "CLIENT":
        raise ValueError("Paid edition and selected mode conflict")

    if new == "SERVICE":
        if choice == "KEEP":
            if selected_mode != "SERVICE":
                raise ValueError("Service entry requires an explicit term")
            if term_date.strip():
                raise ValueError("KEEP cannot contain a calendar date")
            return {
                "action": "NONE",
                "mode": "SERVICE",
                "edition": "SERVICE",
                "valid_until": service_valid_until_current,
            }
        expires = owner_valid_until("SERVICE", choice, term_date, now=now)
        return {
            "action": "SERVICE_TERM" if selected_mode == "SERVICE" else "ENTER_SERVICE",
            "mode": "SERVICE",
            "edition": "SERVICE",
            "valid_until": expires,
        }

    # Select CLIENT from SERVICE. The prior KeyGate license remains untouched
    # and must be checked for ACTIVE status independently during execution.
    if selected_mode == "SERVICE":
        if choice != "KEEP" or term_date.strip():
            raise ValueError("Return to paid mode requires KEEP; modify paid term separately")
        if paid_edition is None or paid_edition.strip().upper() != new:
            raise ValueError("Restored edition must match the original paid license")
        return {
            "action": "RESTORE_PAID",
            "mode": "CLIENT",
            "edition": new,
            "valid_until": paid_valid_until,
        }

    if choice == "KEEP":
        if term_date.strip():
            raise ValueError("KEEP cannot contain an unsubmitted calendar date")
        return {
            "action": "PAID_EDITION" if old != new else "NONE",
            "mode": "CLIENT",
            "edition": new,
            "valid_until": paid_valid_until,
        }

    # Deliberately separate plan/term mutations, otherwise a partial KeyGate
    # request can apply one modification while silently losing the other.
    if old != new:
        raise ValueError("Save the paid edition and its term in separate operations")
    if choice == "PERPETUAL" and not explicit_paid_perpetual_supported:
        raise ValueError("Paid perpetual terms are unsupported by the current KeyGate adapter")

    expires = owner_valid_until(
        new, choice, term_date, now=now,
        existing_end=paid_valid_until, extend=choice in ("3", "6", "12"),
    )
    if choice in ("3", "6", "12"):
        if paid_valid_until is None or paid_valid_until <= now:
            raise ValueError("Paid extension requires an unexpired paid term")
        action = "PAID_EXTEND"
    elif choice == "CALENDAR":
        if paid_valid_until is None:
            raise ValueError("Paid calendar changes require an existing expiry")
        action = "PAID_CALENDAR"
    else:
        action = "PAID_PERPETUAL"

    return {
        "action": action,
        "mode": "CLIENT",
        "edition": new,
        "valid_until": expires,
    }


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
    period: str = "TIMED",
) -> bool:
    """Pro remote requires verified current CLIENT rights AND per-session consent.

    Perpetual rights are explicit (period=PERPETUAL). A legacy missing expiry
    never converts a paid timed licence into a perpetual one.
    """
    return bool(
        mode == "CLIENT"
        and edition == "PRO"
        and lifecycle == "ACTIVE"
        and license_within_period(period, valid_until, now)
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
