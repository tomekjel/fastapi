"""Offline contract tests for the backend-to-Windows OWNER grant.
No database, deployment, license modification, or network access.
Run: python -m unittest discover -s scripts/tests -p 'test_multiguard_owner_grant.py'
"""
import base64
import importlib.util
import json
import pathlib
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SOURCE = pathlib.Path(__file__).resolve().parents[2] / "embedded-multiguard" / "app" / "routers" / "multiguard_owner_profile_grant.py"
SPEC = importlib.util.spec_from_file_location("owner_grant_contract", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OwnerGrantContractTest(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.installation = uuid4()
        self.device = "a" * 64

    def grant(self, target):
        return MODULE.create_profile_transition_grant(
            installation_id=self.installation,
            device_id=self.device,
            target=target,
            signing_key=self.key,
            issued_at=datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc),
        )

    def test_all_editions_have_exact_signed_fields(self):
        for edition in ("STANDARD", "PRO", "SERVICE"):
            with self.subTest(edition=edition):
                signed = self.grant(edition)
                payload = json.loads(signed["payload"])
                self.key.public_key().verify(
                    base64.b64decode(signed["signatureB64"]),
                    signed["payload"].encode("utf-8"),
                )
                self.assertEqual(payload["schemaVersion"], 1)
                self.assertEqual(payload["purpose"], MODULE.PURPOSE)
                self.assertEqual(payload["installationId"], str(self.installation))
                self.assertEqual(payload["deviceId"], self.device)
                self.assertEqual(payload["target"], edition)
                self.assertEqual(payload["issuedAt"], "2026-11-08T12:00:00Z")
                self.assertEqual(payload["expiresAt"], "2026-11-08T12:02:00Z")

    def test_signed_ticket_is_bound_to_reservation_and_report_keeps_lock(self):
        base = pathlib.Path(__file__).resolve().parents[2] / "embedded-multiguard" / "app" / "routers"
        src = (base / "multiguard_license.py").read_text(encoding="utf-8")
        grant = src.split('@router.post("/v1/multi-guard/owner-profile-grant")',1)[1].split(
            '@router.post("/v1/multi-guard/owner-profile-report")',1
        )[0]
        report = src.split('@router.post("/v1/multi-guard/owner-profile-report")',1)[1].split(
            '@router.post("/v1/multi-guard/acceptance")',1
        )[0]
        self.assertIn("request_id=reservation_id", grant)
        self.assertIn('"reservationId": str(reservation_id)', grant)
        self.assertIn("WHERE installation_external_id=:iid AND is_current=TRUE FOR UPDATE", report)
        self.assertIn("reservation_id=:rid AND state='RESERVED'", report)
        self.assertIn('"admissionBlocked": True', report)
        self.assertIn('"ownerVerificationRequired": True', report)
        self.assertNotIn("state='COMPLETED'", report)
        self.assertNotIn("state='ABORTED'", report)

    def test_session_admission_and_grant_use_same_installation_lock(self):
        base = pathlib.Path(__file__).resolve().parents[2] / "embedded-multiguard" / "app" / "routers"
        license_source = (base / "multiguard_license.py").read_text(encoding="utf-8")
        remote_source = (base / "multiguard_remote.py").read_text(encoding="utf-8")
        grant = license_source.split(
            '@router.post("/v1/multi-guard/owner-profile-grant")', 1
        )[1].split('@router.post("/v1/multi-guard/acceptance")', 1)[0]
        create = remote_source.split(
            '@router.post("/remote-sessions")', 1
        )[1].split('return {', 1)[0]
        self.assertIn("WHERE installation_external_id=:iid FOR UPDATE", grant)
        self.assertIn("FOR UPDATE OF gi", create)
        self.assertIn("guard.workshop_profile_transitions", grant)
        self.assertIn("guard.workshop_profile_transitions", create)
        self.assertIn("state='RESERVED'", grant)
        self.assertIn("t.state='RESERVED'", create)
        self.assertLess(grant.index("FOR UPDATE"), grant.index("INSERT INTO guard.workshop_profile_transitions"))
        self.assertLess(create.index("FOR UPDATE OF gi"), create.index("INSERT INTO guard.remote_sessions"))
        self.assertIn("reservationId", grant)

    def test_heartbeat_cannot_overwrite_entitlement_fields(self):
        source = (
            pathlib.Path(__file__).resolve().parents[2]
            / "embedded-multiguard" / "app" / "routers"
            / "multiguard_runtime.py"
        ).read_text(encoding="utf-8")
        heartbeat = source.split('def heartbeat(body: HeartbeatBody):', 1)[1].split(
            '@router.post("/agent/event")', 1
        )[0]
        # This SQL was previously client-controlled and must not return.
        update = heartbeat.split("UPDATE guard.installations", 1)[1].split(
            'WHERE id=:id', 1
        )[0]
        for forbidden in (
            "plan_code=:plan_code", "license_id=COALESCE",
            "lifecycle=:lifecycle", "accepted_at=COALESCE",
            "valid_until=:valid_until",
        ):
            self.assertNotIn(forbidden, update)

    def test_owner_edition_is_resolved_from_verified_state(self):
        base = dict(
            owner_mode="CLIENT", plan_code="multi_guard_pro", lifecycle="ACTIVE",
            license_valid=True, installation_active=True,
            customer_session_active=False, workshop_session_active=False,
            transition_reserved=False,
        )
        self.assertEqual(MODULE.resolve_owner_target(**base), "PRO")
        self.assertEqual(MODULE.resolve_owner_target(**{**base, "plan_code":"multi_guard"}), "STANDARD")
        self.assertEqual(MODULE.resolve_owner_target(**{
            **base, "owner_mode":"SERVICE", "lifecycle":"WORKSHOP"
        }), "SERVICE")

    def test_owner_resolution_denies_mismatches_sessions_and_expiry(self):
        base = dict(
            owner_mode="CLIENT", plan_code="PRO", lifecycle="ACTIVE",
            license_valid=True, installation_active=True,
            customer_session_active=False, workshop_session_active=False,
            transition_reserved=False,
        )
        for changed in [
            {"customer_session_active":True},
            {"workshop_session_active":True},
            {"transition_reserved":True},
            {"license_valid":False},
            {"installation_active":False},
            {"owner_mode":"SERVICE"},
            {"lifecycle":"EXPIRED"},
            {"plan_code":"unknown"},
        ]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                MODULE.resolve_owner_target(**{**base, **changed})

    def test_tampering_breaks_signature(self):
        signed = self.grant("STANDARD")
        with self.assertRaises(Exception):
            self.key.public_key().verify(
                base64.b64decode(signed["signatureB64"]),
                signed["payload"].replace('"STANDARD"', '"SERVICE"').encode("utf-8"),
            )

    def test_unsupported_mode_and_empty_identity_fail(self):
        with self.assertRaises(ValueError):
            self.grant("ADMIN")
        with self.assertRaises(ValueError):
            MODULE.create_profile_transition_grant(
                installation_id=self.installation,
                device_id="",
                target="PRO",
                signing_key=self.key,
            )


if __name__ == "__main__":
    unittest.main()
