"""Offline fail-closed tests: no database, MeshCentral or real session."""
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers.multiguard_remote_policy import (
    DeviceScope, MeshGroupClass, RemoteMode, ServerEvidence, authorize_share,
)


def evidence(**changes):
    initial = ServerEvidence(
        scope=DeviceScope.OWNED_WORKSHOP_PRO,
        enabled=True,
        owner_authenticated=True,
        current_installation=True,
        mesh_node_verified_live=True,
        mesh_group=MeshGroupClass.OWNER_OWNED,
        owner_approved_unattended=True,
        local_opt_in_attested=True,
    )
    return replace(initial, **changes)


class RemoteConsentPolicy(unittest.TestCase):
    def assert_denied(self, mode, **updates):
        with self.assertRaises(PermissionError):
            authorize_share(mode, evidence(**updates))

    def test_owned_device_can_connect_without_dialog_only_after_3_checks(self):
        decision = authorize_share(RemoteMode.OWNER_UNATTENDED, evidence())
        self.assertEqual(decision.mesh_consent, "notify,bar")
        self.assertTrue(decision.desktop_only)
        for missing in (
            {"owner_approved_unattended": False},
            {"local_opt_in_attested": False},
            {"mesh_group": MeshGroupClass.CONSENT},
            {"mesh_group": MeshGroupClass.UNKNOWN},
            {"mesh_node_verified_live": False},
        ):
            self.assert_denied(RemoteMode.OWNER_UNATTENDED, **missing)

    def test_customer_diagnostic_service_pro_requires_standing_prior_opt_in(self):
        # A customer can explicitly pre-authorize diagnostic access before
        # leaving the PC running at home; no fresh popup is needed then.
        allowed = evidence(
            scope=DeviceScope.CLIENT_WORKSHOP_PRO,
            mesh_group=MeshGroupClass.SERVICE_DIAGNOSTICS,
        )
        result = authorize_share(RemoteMode.OWNER_UNATTENDED, allowed)
        self.assertEqual(result.mesh_consent, "notify,bar")
        self.assertTrue(result.desktop_only)
        for missing in (
            {"owner_approved_unattended": False},
            {"local_opt_in_attested": False},
            {"mesh_group": MeshGroupClass.CONSENT},
            {"mesh_group": MeshGroupClass.OWNER_OWNED},
            {"mesh_node_verified_live": False},
            {"current_installation": False},
            {"license_revoked": True},
            {"enabled": False},
        ):
            with self.subTest(missing=missing):
                with self.assertRaises(PermissionError):
                    authorize_share(RemoteMode.OWNER_UNATTENDED,
                                    replace(allowed, **missing))

    def test_paid_pro_standard_and_unlicensed_never_get_unattended(self):
        for scope in (DeviceScope.PAID_PRO, DeviceScope.UNLICENSED):
            for group in (MeshGroupClass.SERVICE_DIAGNOSTICS, MeshGroupClass.OWNER_OWNED):
                self.assert_denied(RemoteMode.OWNER_UNATTENDED,
                                   scope=scope,mesh_group=group)
        # Service STANDARD is not modeled as PRO and fails server entitlement.
        self.assert_denied(RemoteMode.OWNER_UNATTENDED, enabled=False)


    def test_owner_device_can_still_ask_session_consent(self):
        consented = evidence(
            session_desktop_consent_confirmed=True,
            owner_approved_unattended=False,
            local_opt_in_attested=False,
            mesh_group=MeshGroupClass.OWNER_OWNED,
        )
        decision = authorize_share(RemoteMode.CONSENT_REQUIRED, consented)
        self.assertEqual(decision.mesh_consent, "prompt,bar")
        self.assertFalse(decision.desktop_only)

    def test_paid_pro_requires_explicit_per_session_consent(self):
        self.assert_denied(
            RemoteMode.CONSENT_REQUIRED,
            scope=DeviceScope.PAID_PRO, mesh_group=MeshGroupClass.CONSENT,
            session_desktop_consent_confirmed=False)
        decision = authorize_share(RemoteMode.CONSENT_REQUIRED, evidence(
            scope=DeviceScope.PAID_PRO,
            mesh_group=MeshGroupClass.CONSENT,
            session_desktop_consent_confirmed=True,
            local_opt_in_attested=False,
            owner_approved_unattended=False,
        ))
        self.assertEqual(decision.mesh_consent, "prompt,bar")

    def test_client_workshop_requires_explicit_per_session_consent(self):
        self.assert_denied(
            RemoteMode.CONSENT_REQUIRED,
            scope=DeviceScope.CLIENT_WORKSHOP_PRO, mesh_group=MeshGroupClass.CONSENT)
        self.assertEqual(authorize_share(RemoteMode.CONSENT_REQUIRED, evidence(
            scope=DeviceScope.CLIENT_WORKSHOP_PRO,
            mesh_group=MeshGroupClass.CONSENT,
            session_desktop_consent_confirmed=True,
        )).mesh_consent, "prompt,bar")

    def test_a_revoked_unverified_or_unknown_device_is_never_connectable(self):
        for change in (
            {"enabled": False},
            {"license_revoked": True},
            {"owner_authenticated": False},
            {"current_installation": False},
            {"mesh_node_verified_live": False},
            {"scope": DeviceScope.UNLICENSED},
        ):
            for mode in (RemoteMode.OWNER_UNATTENDED, RemoteMode.CONSENT_REQUIRED):
                self.assert_denied(mode, **change)

    def test_no_unknown_group_or_mode_is_allowed(self):
        self.assert_denied(
            RemoteMode.CONSENT_REQUIRED,
            mesh_group=MeshGroupClass.UNKNOWN,
            session_desktop_consent_confirmed=True)
        self.assert_denied("NO_CONSENT_BECAUSE_I_SAID_SO")


if __name__ == "__main__":
    unittest.main()
