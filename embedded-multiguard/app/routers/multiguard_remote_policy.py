"""Server-side policy for Multi-Servis remote connection modes.

Pure decision engine. No API route or unattended access is enabled by
importing this module. All booleans passed to authorize_share MUST be
derived from server-side DB records, authenticated OWNER identity and live
MeshCentral group verification, NEVER from a request body or an app label.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RemoteMode(str, Enum):
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    OWNER_UNATTENDED = "OWNER_UNATTENDED"


class DeviceScope(str, Enum):
    OWNED_WORKSHOP_PRO = "OWNED_WORKSHOP_PRO"
    CLIENT_WORKSHOP_PRO = "CLIENT_WORKSHOP_PRO"
    PAID_PRO = "PAID_PRO"
    UNLICENSED = "UNLICENSED"


class MeshGroupClass(str, Enum):
    CONSENT = "CONSENT"
    OWNER_OWNED = "OWNER_OWNED"
    # Separate group for diagnostic service devices whose owners have
    # given durable, individually recorded and revocable prior consent.
    SERVICE_DIAGNOSTICS = "SERVICE_DIAGNOSTICS"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ServerEvidence:
    # All evidence must be verified or read on the server.
    scope: DeviceScope
    enabled: bool
    owner_authenticated: bool
    current_installation: bool
    mesh_node_verified_live: bool
    mesh_group: MeshGroupClass
    # Set by a trusted OWNER approval record and by a distinct local
    # attestation bound to the SAME installation; neither is a UI checkbox.
    owner_approved_unattended: bool = False
    local_opt_in_attested: bool = False
    # Tied to one short-lived support session, not a global acceptance.
    session_desktop_consent_confirmed: bool = False
    license_revoked: bool = False


@dataclass(frozen=True)
class ShareDecision:
    mesh_consent: str
    desktop_only: bool
    audited_mode: RemoteMode


def authorize_share(mode: RemoteMode, evidence: ServerEvidence) -> ShareDecision:
    """Reject unless all independent policy checks have succeeded.

    OWNER_UNATTENDED never gives file/terminal rights or disables the
    MeshCentral privacy bar; there is no fallback from denied mode to
    an alternative group or lesser-verified session.
    """
    if (
        not evidence.owner_authenticated
        or not evidence.enabled
        or evidence.license_revoked
        or not evidence.current_installation
        or not evidence.mesh_node_verified_live
        or evidence.scope == DeviceScope.UNLICENSED
    ):
        raise PermissionError("REMOTE_ACCESS_NOT_AUTHORIZED")

    if mode == RemoteMode.CONSENT_REQUIRED:
        if evidence.mesh_group not in (MeshGroupClass.CONSENT, MeshGroupClass.OWNER_OWNED):
            raise PermissionError("MESH_GROUP_NOT_VERIFIED")
        if not evidence.session_desktop_consent_confirmed:
            raise PermissionError("PER_SESSION_DESKTOP_CONSENT_REQUIRED")
        return ShareDecision("prompt,bar", False, RemoteMode.CONSENT_REQUIRED)

    if mode == RemoteMode.OWNER_UNATTENDED:
        # The indefinite SERVICE PRO mode is independent of where the device
        # physically resides. A workshop-owned PC and a customer diagnostic
        # PC are BOTH eligible only with distinct server-side prior-consent
        # evidence; ordinary time-limited PAID_PRO can NEVER use this mode.
        expected_group = {
            DeviceScope.OWNED_WORKSHOP_PRO: MeshGroupClass.OWNER_OWNED,
            DeviceScope.CLIENT_WORKSHOP_PRO: MeshGroupClass.SERVICE_DIAGNOSTICS,
        }.get(evidence.scope)
        if expected_group is None:
            raise PermissionError("UNATTENDED_REQUIRES_SERVICE_PRO")
        if not evidence.owner_approved_unattended:
            raise PermissionError("STANDING_OWNER_APPROVAL_REQUIRED")
        if not evidence.local_opt_in_attested:
            raise PermissionError("DEVICE_OWNER_PRIOR_CONSENT_NOT_ATTESTED")
        if evidence.mesh_group != expected_group:
            raise PermissionError("UNATTENDED_MESH_GROUP_REQUIRED")
        # No interactive prompt after recorded standing authorization, but
        # MeshCentral privacy notification/bar must remain visible.
        return ShareDecision("notify,bar", True, RemoteMode.OWNER_UNATTENDED)

    raise PermissionError("UNRECOGNIZED_REMOTE_MODE")
