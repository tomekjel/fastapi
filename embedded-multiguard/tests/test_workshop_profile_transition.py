"""Offline regression tests for the authenticated Windows profile transition guard.

No database, MeshCentral, Windows SCM, or production service is accessed.
Run from repository root with the backend's normal Python dependencies:
    python -m unittest discover -s embedded-multiguard/tests -p 'test_workshop_profile_transition.py'
"""
import json
import inspect
import re
import sys
import types
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

# This suite deliberately imports the REAL workshop router with ONLY its
# external infrastructure modules replaced by in-memory stubs. It runs in a
# dedicated Python process, so no test can initialize live DB/API/MeshCentral.
# The router's pure policy and transition functions are not mocked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app.routers  # namespace package, no service startup

for name in (
    "app.database",
    "app.security",
    "app.routers.multiguard_license",
    "app.routers.multiguard_meshcentral",
    "app.routers.multiguard_remote",
):
    sys.modules[name] = types.ModuleType(name)
sys.modules["app.database"].engine = None
sys.modules["app.security"].CurrentUser = type("CurrentUser", (), {})
sys.modules["app.security"].require_owner = lambda: None

from fastapi import HTTPException
from app.routers import multiguard_workshop_remote as api


class FakeCursor:
    def __init__(self, result=None):
        self.result = result

    def first(self):
        return self.result

    def mappings(self):
        return self


class FakeDatabase:
    def __init__(self, *, workshop_open=False, paid_open=False):
        self.workshop_open = workshop_open
        self.paid_open = paid_open
        self.queries = []
        self.reservation = None

    def execute(self, sql, params=None):
        query = str(sql)
        self.queries.append(query)
        if "SELECT 1 FROM guard.workshop_profile_transition_locks" in query:
            return FakeCursor((1,) if self.reservation and self.reservation["released_at"] is None else None)
        if "SELECT reservation_id" in query and "guard.workshop_profile_transition_locks" in query:
            return FakeCursor(self.reservation)
        if "INSERT INTO guard.workshop_profile_transition_locks" in query:
            self.reservation = {
                "reservation_id": params["reservation"],
                "target_mode": params["target"],
                "created_at": datetime.now(timezone.utc)-timedelta(minutes=3),
                "released_at": None,
                "recovery_owner_approved_at": None,
                "recovery_owner_reservation_id": None,
            }
            return FakeCursor()
        if "UPDATE guard.workshop_profile_transition_locks" in query:
            if "SET recovery_owner_approved_at" in query:
                self.reservation["recovery_owner_approved_at"] = params["now"]
                self.reservation["recovery_owner_reservation_id"] = params["rid"]
            else:
                self.reservation["released_at"] = datetime.now(timezone.utc)
            return FakeCursor()
        if "INSERT INTO guard.workshop_profile_transition_audit" in query:
            return FakeCursor()
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


class TransitionReservationTests(unittest.TestCase):
    def setUp(self):
        self.db = FakeDatabase()
        self.grant = {"status": "DISCOVERED", "edition": "PRO", "enabled": True}
        self.record = {
            "owner_approved_at": datetime.now(timezone.utc),
            "revoked_at": datetime.now(timezone.utc),
        }

    def auth(self):
        return (
            patch.object(api, "_schema"),
            patch.object(api, "_authenticate", return_value={"status": "DISCOVERED"}),
            patch.object(api, "engine", FakeEngine(self.db)),
            patch.object(api, "_grant", return_value=self.grant),
            patch.object(api, "standing_authorization_record", return_value=self.record),
        )

    def test_begin_blocks_new_sessions_and_duplicate_begin(self):
        req = request("SERVICE_PRO")
        from contextlib import ExitStack
        with ExitStack() as stack:
            for mocked in self.auth():
                stack.enter_context(mocked)
            first = api.workshop_profile_transition_begin(req)
            content = json.loads(first.body)
            self.assertTrue(content["allowed"])
            self.assertEqual(uuid.UUID(content["reservationId"]), self.db.reservation["reservation_id"])
            with self.assertRaises(HTTPException) as error:
                api._assert_no_profile_transition(self.db, req.installationId)
            self.assertEqual(error.exception.status_code, 409)
            with self.assertRaises(HTTPException) as error:
                api.workshop_profile_transition_begin(req)
            self.assertEqual(error.exception.status_code, 409)

    def test_finishing_exact_reservation_unblocks_sessions(self):
        req = request("CLIENT")
        from contextlib import ExitStack
        with ExitStack() as stack:
            for mocked in self.auth():
                stack.enter_context(mocked)
            received = json.loads(api.workshop_profile_transition_begin(req).body)
            done = api.WorkshopProfileTransitionFinish(
                requestId=req.requestId, nonce=req.nonce,
                sentAt=req.sentAt, installationId=req.installationId,
                deviceId=req.deviceId, discoveryCredential=req.discoveryCredential,
                targetMode="CLIENT",
                reservationId=uuid.UUID(received["reservationId"]), succeeded=True,
            )
            reply = json.loads(api.workshop_profile_transition_finish(done).body)
            self.assertTrue(reply["released"])
            self.assertIsNotNone(self.db.reservation["released_at"])
            api._assert_no_profile_transition(self.db, req.installationId)
            self.assertTrue(json.loads(api.workshop_profile_transition_begin(req).body)["allowed"])

    def test_wrong_reservation_must_not_release(self):
        req = request("SERVICE_PRO")
        from contextlib import ExitStack
        with ExitStack() as stack:
            for mocked in self.auth():
                stack.enter_context(mocked)
            api.workshop_profile_transition_begin(req)
            wrong = api.WorkshopProfileTransitionFinish(
                requestId=req.requestId, nonce=req.nonce,
                sentAt=req.sentAt, installationId=req.installationId,
                deviceId=req.deviceId, discoveryCredential=req.discoveryCredential,
                targetMode="SERVICE_PRO",
                reservationId=uuid.uuid4(), succeeded=False,
            )
            with self.assertRaises(HTTPException) as error:
                api.workshop_profile_transition_finish(wrong)
            self.assertEqual(error.exception.status_code, 409)
            self.assertIsNone(self.db.reservation["released_at"])



class TransitionRecoveryTests(TransitionReservationTests):
    """Independent mock DB verifies the real recovery policy, not a fake route."""

    def make(self, target="SERVICE_PRO"):
        from contextlib import ExitStack
        req = request(target)
        stack = ExitStack()
        for mocked in self.auth():
            stack.enter_context(mocked)
        api.workshop_profile_transition_begin(req)
        return req, stack

    def recovery(self, req, *, identifier=None, profile="SERVICE_PRO_DORMANT"):
        return api.WorkshopProfileTransitionRecovery(
            requestId=req.requestId, nonce=req.nonce, sentAt=req.sentAt,
            installationId=req.installationId, deviceId=req.deviceId,
            discoveryCredential=req.discoveryCredential,
            targetMode=req.targetMode,
            reservationId=identifier or self.db.reservation["reservation_id"],
            verifiedProfile=profile, localConfirmation=True,
        )

    def test_owner_approval_alone_does_not_unlock(self):
        req, stack = self.make()
        with stack:
            api.approve_transition_recovery_for_owner(req.installationId)
            self.assertIsNone(self.db.reservation["released_at"])
            api._assert_no_profile_transition(self.db, req.installationId)

    def test_no_owner_approval_keeps_lock(self):
        req, stack = self.make()
        with stack:
            with self.assertRaises(HTTPException) as error:
                api.workshop_profile_transition_recover(self.recovery(req))
            self.assertEqual(error.exception.status_code, 409)
            self.assertIsNone(self.db.reservation["released_at"])

    def test_too_recent_reservation_cannot_be_approved(self):
        req, stack = self.make()
        with stack:
            self.db.reservation["created_at"] = datetime.now(timezone.utc)
            with self.assertRaises(HTTPException) as error:
                api.approve_transition_recovery_for_owner(req.installationId)
            self.assertEqual(error.exception.status_code, 409)

    def test_approval_expires_without_unlocking(self):
        req, stack = self.make()
        with stack:
            api.approve_transition_recovery_for_owner(req.installationId)
            self.db.reservation["recovery_owner_approved_at"] -= timedelta(minutes=6)
            with self.assertRaises(HTTPException) as error:
                api.workshop_profile_transition_recover(self.recovery(req))
            self.assertEqual(error.exception.status_code, 409)

    def test_wrong_reservation_cannot_recover(self):
        req, stack = self.make()
        with stack:
            api.approve_transition_recovery_for_owner(req.installationId)
            with self.assertRaises(HTTPException) as error:
                api.workshop_profile_transition_recover(
                    self.recovery(req, identifier=uuid.uuid4()))
            self.assertEqual(error.exception.status_code, 409)

    def test_local_inspection_deny_running_service_pro(self):
        self.assertFalse(api._verified_recovery_profile("CLIENT", "SERVICE_PRO_RUNNING"))
        self.assertFalse(api._verified_recovery_profile("SERVICE_PRO", "SERVICE_PRO_RUNNING"))
        self.assertFalse(api._verified_recovery_profile("CLIENT", "CLIENT_RUNNING"))
        self.assertTrue(api._verified_recovery_profile("SERVICE_PRO", "CLIENT_RUNNING"))
        self.assertTrue(api._verified_recovery_profile("CLIENT", "SERVICE_PRO_DORMANT"))

    def test_verified_recovery_requires_owner_then_releases(self):
        req, stack = self.make()
        with stack:
            api.approve_transition_recovery_for_owner(req.installationId)
            result = api.workshop_profile_transition_recover(self.recovery(req))
            self.assertTrue(json.loads(result.body)["released"])
            self.assertIsNotNone(self.db.reservation["released_at"])
            api._assert_no_profile_transition(self.db, req.installationId)

    def test_recovery_status_shows_id_only_after_owner_approval(self):
        req, stack = self.make()
        with stack:
            status = json.loads(api.workshop_profile_transition_recovery_status(req).body)
            self.assertTrue(status["pending"])
            self.assertFalse(status["ownerRecoveryApproved"])
            self.assertIsNone(status["reservationId"])
            api.approve_transition_recovery_for_owner(req.installationId)
            status = json.loads(api.workshop_profile_transition_recovery_status(req).body)
            self.assertTrue(status["ownerRecoveryApproved"])
            self.assertEqual(uuid.UUID(status["reservationId"]),
                             self.db.reservation["reservation_id"])



class PaidInstallationMappingTests(unittest.TestCase):
    def test_every_paid_session_guard_resolves_external_installation_id(self):
        # Commercial guard.remote_sessions.installation_id is an INTERNAL
        # guard.installations.id. Workshop uses the EXTERNAL installation UUID.
        # Never compare them directly, even when a fake database returns empty.
        source = inspect.getsource(api)
        selects = re.findall(
            r"SELECT 1 FROM guard[.]remote_sessions\b(.*?)LIMIT 1",
            source, re.DOTALL,
        )
        self.assertEqual(len(selects), 6)
        for selection in selects:
            self.assertIn(
                "JOIN guard.installations gi ON gi.id=rs.installation_id",
                selection,
            )
            self.assertIn("gi.installation_external_id=:iid", selection)

    def test_commercial_requests_guard_against_open_workshop_session(self):
        source = (Path(__file__).resolve().parents[1] / "app" / "routers" /
                  "multiguard_remote.py").read_text(encoding="utf-8")
        start = source.index("def create_remote_session(")
        end = source.index('@router.get("/remote-sessions/{session_id}")', start)
        block = source[start:end]
        self.assertIn("FROM guard.workshop_remote_sessions", block)
        self.assertIn("installation_id=:iid", block)
        self.assertIn("external_iid = support[\"installation_external_id\"]", block)
        self.assertIn("FOR UPDATE", block)

    def test_workshop_requests_check_paid_pending_before_creation(self):
        for fn in (api.request_consent_for_owner, api.request_for_owner):
            source = inspect.getsource(fn)
            self.assertIn("JOIN guard.installations gi ON gi.id=rs.installation_id", source)
            self.assertIn("gi.installation_external_id=:iid", source)
            self.assertIn("'REQUESTED','CONSENTED','CONNECT_READY','ACTIVE'", source)





class MeshGroupAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.grant = {
            "status": "DISCOVERED", "edition": "PRO",
            "enabled": True, "mesh_node_id": None,
        }
        self.record = {
            "owner_approved_at": datetime.now(timezone.utc),
            "local_opt_in_attested_at": datetime.now(timezone.utc),
            "revoked_at": None, "device_scope": "OWNED_WORKSHOP",
            "prior_consent_sha256": "a" * 64,
            "approved_mesh_node_id": None,
        }
        self.group = "mesh//" + "A" * 64

    def check(self, record=None, *, owner_group=None, diagnostic_group=None):
        setting = {
            "MESH_CENTRAL_OWNER_OWNED_MESH_ID": owner_group or "",
            "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID": diagnostic_group or "",
        }
        with patch.object(api, "expected_remote_mesh_group", return_value=self.group), \
             patch.dict(api.os.environ, setting):
            return api.authorized_standing_mesh_group(self.grant, record or self.record)

    def test_owner_device_accepts_only_owner_group(self):
        self.assertEqual(self.check(owner_group=self.group), self.group)
        with self.assertRaises(HTTPException) as error:
            self.check(diagnostic_group=self.group)
        self.assertEqual(error.exception.status_code, 503)

    def test_client_diagnostic_requires_distinct_scope_selection(self):
        self.record["device_scope"] = "CLIENT_DIAGNOSTIC"
        self.assertEqual(self.check(diagnostic_group=self.group), self.group)
        with self.assertRaises(HTTPException) as error:
            self.check(owner_group=self.group)
        self.assertEqual(error.exception.status_code, 503)

    def test_revoked_or_unattested_is_denied(self):
        self.record["revoked_at"] = datetime.now(timezone.utc)
        with self.assertRaises(HTTPException) as error:
            self.check(owner_group=self.group)
        self.assertEqual(error.exception.status_code, 403)
        self.record["revoked_at"] = None
        self.record["local_opt_in_attested_at"] = None
        with self.assertRaises(HTTPException) as error:
            self.check(owner_group=self.group)
        self.assertEqual(error.exception.status_code, 403)

    def test_other_node_requires_reauthorization(self):
        self.grant["mesh_node_id"] = "node//" + "B" * 64
        self.record["approved_mesh_node_id"] = "node//" + "C" * 64
        with self.assertRaises(HTTPException) as error:
            self.check(owner_group=self.group)
        self.assertEqual(error.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
