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
