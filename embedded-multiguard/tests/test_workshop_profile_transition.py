"""Offline regression tests for the authenticated Windows profile transition guard.

No database, MeshCentral, Windows SCM, or production service is accessed.
Run from repository root with the backend's normal Python dependencies:
    python -m unittest discover -s embedded-multiguard/tests -p 'test_workshop_profile_transition.py'
"""
import json
import sys
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import HTTPException
from app.routers import multiguard_workshop_remote as api


class FakeCursor:
    def __init__(self, result=None):
        self.result = result

    def first(self):
        return self.result


class FakeDatabase:
    def __init__(self, *, workshop_open=False, paid_open=False):
        self.workshop_open = workshop_open
        self.paid_open = paid_open
        self.queries = []

    def execute(self, sql, params=None):
        query = str(sql)
        self.queries.append(query)
        if "SELECT 1 FROM guard.workshop_remote_sessions" in query:
            return FakeCursor((1,) if self.workshop_open else None)
        if "SELECT 1 FROM guard.remote_sessions" in query:
            return FakeCursor((1,) if self.paid_open else None)
        return FakeCursor(None)


class FakeEngine:
    def __init__(self, db):
        self.db = db

    @contextmanager
    def begin(self):
        yield self.db


def request(target):
    return api.WorkshopProfileTransitionCheck(
        requestId=str(uuid.uuid4()),
        nonce=str(uuid.uuid4()),
        sentAt=datetime.now(timezone.utc),
        installationId=uuid.uuid4(),
        deviceId="device-identity-0001",
        discoveryCredential="discovery-secret-for-offline-test-not-real",
        targetMode=target,
    )


class ProfileTransitionTests(unittest.TestCase):
    def verify(self, target, *, workshop=False, paid=False, revoked=False, enabled=True):
        db = FakeDatabase(workshop_open=workshop, paid_open=paid)
        grant = {
            "status": "DISCOVERED",
            "edition": "PRO",
            "enabled": enabled,
        }
        standing = {
            "owner_approved_at": datetime.now(timezone.utc),
            "revoked_at": datetime.now(timezone.utc) if revoked else None,
        }
        payload = request(target)
        with patch.object(api, "_schema"), \
             patch.object(api, "_authenticate", return_value={"status": "DISCOVERED"}), \
             patch.object(api, "engine", FakeEngine(db)), \
             patch.object(api, "_grant", return_value=grant), \
             patch.object(api, "standing_authorization_record", return_value=standing):
            try:
                response = api.workshop_profile_transition_check(payload)
                return response.status_code, json.loads(response.body), db.queries
            except HTTPException as exc:
                return exc.status_code, str(exc.detail), db.queries

    def test_service_staging_checks_both_tables_and_allows_empty(self):
        code, body, queries = self.verify("SERVICE_PRO")
        self.assertEqual(code, 200)
        self.assertTrue(body["allowed"])
        self.assertEqual(body["targetMode"], "SERVICE_PRO")
        self.assertTrue(any("FROM guard.remote_sessions" in q for q in queries))
        self.assertTrue(any("FROM guard.workshop_remote_sessions" in q for q in queries))

    def test_refuses_pending_commercial_session(self):
        code, _, _ = self.verify("SERVICE_PRO", paid=True)
        self.assertEqual(code, 409)

    def test_refuses_pending_workshop_session(self):
        code, _, _ = self.verify("SERVICE_PRO", workshop=True)
        self.assertEqual(code, 409)

    def test_restoring_client_requires_owner_revoke(self):
        code, _, _ = self.verify("CLIENT", revoked=False)
        self.assertEqual(code, 409)

    def test_restoring_client_allows_revoked_permission_and_no_sessions(self):
        code, body, queries = self.verify("CLIENT", revoked=True)
        self.assertEqual(code, 200)
        self.assertTrue(body["allowed"])
        self.assertTrue(any("FROM guard.remote_sessions" in q for q in queries))

    def test_disabled_workshop_license_denies_any_transition(self):
        code, _, _ = self.verify("SERVICE_PRO", enabled=False)
        self.assertEqual(code, 403)


if __name__ == "__main__":
    unittest.main()
