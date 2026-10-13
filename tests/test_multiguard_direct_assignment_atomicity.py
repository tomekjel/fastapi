"""Regression tests for assigning a DIRECT Multi-Guard licence.

Run in the backend test environment (with app import path configured):
    python -m unittest discover -s tests -p test_multiguard_direct_assignment_atomicity.py
No network access or production database is used. The real production function is loaded via AST.
Run only on the owner's verified MultiGuard-Dev runner.
"""
import ast
import types
import unittest
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from pathlib import Path
from typing import Any


class FakeHTTPException(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# Compile the unmodified production function from its AST. These isolated
# transaction tests do not import the entire FastAPI production backend,
# connect to KeyGate, or require production-only Python dependencies.
source_file = (
    Path(__file__).resolve().parents[1]
    / "embedded-multiguard"
    / "app"
    / "routers"
    / "multiguard_license.py"
)
source = source_file.read_text(encoding="utf-8")
parsed = ast.parse(source, filename=str(source_file))
function = next(
    node for node in parsed.body
    if isinstance(node, ast.FunctionDef) and node.name == "_assign_direct_customer_license"
)
mg = types.ModuleType("isolated_multiguard_licence")
mg.__dict__.update({
    "uuid": uuid,
    "Any": Any,
    "HTTPException": FakeHTTPException,
    "text": lambda sql: sql,
    "_ensure_schema": lambda: None,
    "engine": None,
    "_keygate_create_license": lambda **kwargs: None,
    "_normalize_link": lambda row: row,
    "_hash": lambda key: "HASH",
    "logger": types.SimpleNamespace(exception=lambda *args, **kwargs: None),
})
isolated = ast.Module(body=[function], type_ignores=[])
ast.fix_missing_locations(isolated)
exec(compile(isolated, str(source_file), "exec"), mg.__dict__)



class SimulatedDatabase:
    """Transaction simulator: changes persist only if the block exits normally."""

    def __init__(self, fail_workshop_update=False):
        self.fail_workshop_update = fail_workshop_update
        self.state = {"status": "WAITING", "license": None, "grant": True}
        self.attempts = {}
        self.queries = []

    @contextmanager
    def begin(self):
        working = self.state.copy()
        db = self

        class Connection:
            def execute(self, sql, params=None):
                query = str(sql)
                db.queries.append(query)
                if "INSERT INTO guard.direct_keygate_attempts" in query:
                    iid = str(params["installation_id"])
                    if iid in db.attempts:
                        return Result(None)
                    db.attempts[iid] = {"state": "STARTED", "keygate_license_id": None}
                    return Result(iid)
                if "UPDATE guard.direct_keygate_attempts" in query:
                    iid = str(params["id"])
                    if iid in db.attempts:
                        db.attempts[iid]["state"] = (
                            "RECONCILIATION_REQUIRED" if "RECONCILIATION_REQUIRED" in query
                            else "CREATED"
                        )
                        if params.get("license_id"):
                            db.attempts[iid]["keygate_license_id"] = params["license_id"]
                    return Result(None)
                if "FROM guard.pending_installations" in query:
                    return Result({"status": working["status"], "assigned_license_id": working["license"]})
                if "SELECT id FROM guard.license_links" in query:
                    return Result(None)
                if "INSERT INTO guard.license_links" in query:
                    return Result({"keygate_license_id": "FAKE-LICENSE", "plan_code": "multi_guard_pro"})
                if "UPDATE guard.pending_installations" in query:
                    working["status"] = "ASSIGNED"
                    working["license"] = "FAKE-LICENSE"
                if "UPDATE guard.workshop_grants" in query:
                    if db.fail_workshop_update:
                        raise RuntimeError("synthetic SQL error during grant revocation")
                    working["grant"] = False
                return Result(None)

        try:
            yield Connection()
        except Exception:
            raise
        else:
            self.state = working


class Result:
    def __init__(self, value):
        self.value = value

    def first(self):
        return self.value

    def one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def mappings(self):
        return self


class DirectAssignmentAtomicityTests(unittest.TestCase):
    def run_assignment(self, database):
        with (
            patch.object(mg, "engine", database),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", return_value={
                "id": "FAKE-LICENSE", "_plan_id": "FAKE-PLAN", "_license_key": "FAKE-KEY"
            }),
            patch.object(mg, "_normalize_link", side_effect=lambda link: link),
        ):
            return mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")

    def test_assigns_paid_rights_and_revokes_service_grant_together(self):
        db = SimulatedDatabase()
        result = self.run_assignment(db)
        self.assertEqual(result["keygate_license_id"], "FAKE-LICENSE")
        self.assertEqual(
            next(iter(db.attempts.values()))["state"], "CREATED"
        )
        self.assertEqual(db.state, {"status": "ASSIGNED", "license": "FAKE-LICENSE", "grant": False})

    def test_keygate_failure_does_not_assign_local_rights(self):
        db = SimulatedDatabase()
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", side_effect=RuntimeError("synthetic KeyGate outage")),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic KeyGate outage"):
                mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")
        self.assertEqual(db.state, {"status": "WAITING", "license": None, "grant": True})
        self.assertFalse(any("INSERT INTO guard.license_links" in q for q in db.queries))
        self.assertEqual(
            next(iter(db.attempts.values()))["state"], "RECONCILIATION_REQUIRED"
        )

    def test_sql_failure_after_external_creation_requires_reconciliation(self):
        """Document cross-system failure: SQL rollback cannot undo KeyGate."""
        db = SimulatedDatabase(fail_workshop_update=True)
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", return_value={
                "id": "EXTERNAL-ORPHAN", "_plan_id": "FAKE-PLAN", "_license_key": "FAKE-KEY"
            }) as keygate,
        ):
            with self.assertRaises(mg.HTTPException) as failure:
                mg._assign_direct_customer_license(uuid.uuid4(), "PRO", 3, "STABLE")
        self.assertEqual(failure.exception.status_code, 503)
        self.assertIn("KeyGate", failure.exception.detail)
        keygate.assert_called_once()
        self.assertEqual(
            next(iter(db.attempts.values()))["state"], "RECONCILIATION_REQUIRED"
        )
        self.assertEqual(db.state["status"], "WAITING")
        self.assertIsNone(db.state["license"])
        # External licence exists in this scenario despite SQL rollback.
        # This is a documented release blocker until reconciliation is implemented.

    def test_retry_after_external_creation_is_blocked(self):
        db = SimulatedDatabase(fail_workshop_update=True)
        installation_id = uuid.uuid4()
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license", return_value={
                "id": "EXTERNAL-ORPHAN",
                "_plan_id": "FAKE-PLAN",
                "_license_key": "FAKE-KEY",
            }) as keygate,
        ):
            with self.assertRaises(mg.HTTPException) as first:
                mg._assign_direct_customer_license(installation_id, "PRO", 3, "STABLE")
            self.assertEqual(first.exception.status_code, 503)
            with self.assertRaises(mg.HTTPException) as repeated:
                mg._assign_direct_customer_license(installation_id, "PRO", 3, "STABLE")
            self.assertEqual(repeated.exception.status_code, 409)
            keygate.assert_called_once()
        self.assertEqual(db.attempts[str(installation_id)]["state"], "RECONCILIATION_REQUIRED")

    def test_retry_after_uncertain_keygate_network_result_is_blocked(self):
        db = SimulatedDatabase()
        installation_id = uuid.uuid4()
        with (
            patch.object(mg, "engine", db),
            patch.object(mg, "_ensure_schema"),
            patch.object(mg, "_keygate_create_license",
                         side_effect=RuntimeError("KeyGate response lost")) as keygate,
        ):
            with self.assertRaisesRegex(RuntimeError, "KeyGate response lost"):
                mg._assign_direct_customer_license(installation_id, "PRO", 3, "STABLE")
            with self.assertRaises(mg.HTTPException) as retry:
                mg._assign_direct_customer_license(installation_id, "PRO", 3, "STABLE")
            self.assertEqual(retry.exception.status_code, 409)
            keygate.assert_called_once()
        self.assertEqual(db.attempts[str(installation_id)]["state"], "RECONCILIATION_REQUIRED")
        self.assertEqual(db.state["status"], "WAITING")

    def test_sql_failure_rolls_back_pending_assignment(self):
        db = SimulatedDatabase(fail_workshop_update=True)
        with self.assertRaises(mg.HTTPException) as failure:
            self.run_assignment(db)
        self.assertEqual(failure.exception.status_code, 503)
        self.assertEqual(db.state, {"status": "WAITING", "license": None, "grant": True})
        self.assertTrue(any("UPDATE guard.workshop_grants" in q for q in db.queries))
        self.assertTrue(any("UPDATE guard.direct_keygate_attempts" in q for q in db.queries))
        self.assertEqual(
            next(iter(db.attempts.values()))["state"], "RECONCILIATION_REQUIRED"
        )



class KeyGateApiContractTests(unittest.TestCase):
    def test_direct_creation_sends_stable_workspace_reference_without_auto_retry(self):
        original = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "_keygate_create_license"
        )
        original.decorator_list = []
        module = ast.Module(body=[original], type_ignores=[])
        ast.fix_missing_locations(module)
        calls = []
        def request(method, path, **kwargs):
            calls.append((method, path, kwargs))
            return {"id": "KEYGATE-ID", "license_key": "KG-TEST"}
        env = {
            "Any": Any,
            "_required_env": lambda name: "TEST-PRODUCT",
            "_find_plan_id": lambda edition, months: "TEST-PLAN",
            "_keygate_request": request,
            "_setting": lambda key, default: default,
            "HTTPException": FakeHTTPException,
        }
        exec(compile(module, str(source_file), "exec"), env)
        created = env["_keygate_create_license"](
            reception_number="MG-DIRECT-123", edition="PRO", months=3
        )
        self.assertEqual(created["_plan_id"], "TEST-PLAN")
        self.assertEqual(len(calls), 1)
        method, path, params = calls[0]
        self.assertEqual((method, path), ("POST", "/api/v1/admin/licenses"))
        self.assertTrue(params["admin"])
        self.assertEqual(params["body"]["external_workspace_id"], "MG-DIRECT-123")
        self.assertEqual(params["body"]["plan_id"], "TEST-PLAN")
        self.assertNotIn("valid_until", params["body"])


class AcceptanceGateTests(unittest.TestCase):
    def test_duplicate_document_cannot_activate_keygate(self):
        from types import SimpleNamespace
        original = next(node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "acceptance")
        original.decorator_list = []
        module = ast.Module(body=[original], type_ignores=[])
        ast.fix_missing_locations(module)
        kinds = ["licence", "privacy", "terms"]
        required = [
            {"kind": kind, "version": "1", "sha256": "ab" * 32}
            for kind in kinds
        ]
        keygate_calls = []
        env = {
            "AcceptanceRequest": object,
            "HTTPException": FakeHTTPException,
            "_authenticate_installation": lambda req: {"lifecycle": "PENDING_ACCEPTANCE"},
            "_required_documents": lambda: required,
            "_keygate_set_valid_until": lambda *args: keygate_calls.append(args),
        }
        exec(compile(module, str(source_file), "exec"), env)
        accepted = [SimpleNamespace(**item) for item in required]
        invalid_sets = {
            "duplicate": accepted + [accepted[0]],
            "missing": accepted[:2],
            "wrong_hash": accepted[:2] + [
                SimpleNamespace(kind="terms", version="1", sha256="00" * 32)
            ],
        }
        for scenario, documents in invalid_sets.items():
            with self.subTest(scenario=scenario):
                req = SimpleNamespace(documents=documents)
                with self.assertRaises(FakeHTTPException) as error:
                    env["acceptance"](req)
                self.assertEqual(error.exception.status_code, 400)
                self.assertEqual(keygate_calls, [])


class OwnerQueueVisibilityTests(unittest.TestCase):
    def test_owner_pending_list_returns_unlicensed_asus_without_assignment(self):
        from contextlib import nullcontext
        original = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "pending_installations"
        )
        original.decorator_list = []
        module = ast.Module(body=[original], type_ignores=[])
        ast.fix_missing_locations(module)
        iid = uuid.uuid4()
        queries = []
        class QueryResult:
            def mappings(self):
                return self
            def all(self):
                return [{
                    "installation_id": iid,
                    "device_id": "asus-test",
                    "hostname": "ASUS",
                    "status": "WAITING",
                    "app_version": "0.3.42",
                    "last_seen_at": None,
                    "assigned_reception_id": None,
                    "assigned_license_id": None,
                }]
        class Connection:
            def execute(self, query):
                queries.append(str(query))
                return QueryResult()
        class Engine:
            def connect(self):
                return nullcontext(Connection())
        env = {
            "CurrentUser": object,
            "Depends": lambda x: None,
            "require_owner": lambda: None,
            "_ensure_schema": lambda: None,
            "engine": Engine(),
            "text": lambda s: s,
            "_pending_public": lambda row, match_score=0: {
                "installationId": str(row["installation_id"]),
                "status": row["status"],
                "hostname": row["hostname"],
                "appVersion": row["app_version"],
                "online": False,
                "matchScore": match_score,
                "lastSeenAt": None,
            },
        }
        exec(compile(module, str(source_file), "exec"), env)
        result = env["pending_installations"](reception_id="", include_assigned=False)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["hostname"], "ASUS")
        self.assertEqual(result[0]["status"], "WAITING")
        self.assertEqual(result[0]["appVersion"], "0.3.42")
        self.assertTrue(any("status='WAITING'" in q for q in queries))


class OwnerReconciliationPanelTests(unittest.TestCase):
    def test_owner_sees_interrupted_and_orphaned_keygate_creations(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        fn = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_owner_keygate_reconciliation_panel"
        )
        ast.fix_missing_locations(fn)
        module = ast.Module(body=[fn], type_ignores=[])
        ast.fix_missing_locations(module)
        seen = []
        class DbResult:
            def mappings(self):
                return self
            def all(self):
                return [
                    dict(installation_id=uuid.uuid4(),
                         workspace_reference="MG-DIRECT-test",
                         state="CREATED", keygate_license_id="KG-123")
                ]
        class Db:
            def execute(self, query):
                seen.append(str(query))
                return DbResult()
        env = dict(
            _ensure_schema=lambda: None,
            engine=SimpleNamespace(connect=lambda: nullcontext(Db())),
            text=lambda query: query,
            _panel_escape=lambda value: str(value),
        )
        exec(compile(module, str(source_file), "exec"), env)
        rendered = env["_owner_keygate_reconciliation_panel"]()
        self.assertIn("KG-123", rendered)
        self.assertIn("Wymagana weryfikacja KeyGate", rendered)
        self.assertIn("CREATED", rendered)
        self.assertIn("/multiguard/panel/pending/", rendered)
        self.assertIn("Szczegóły komputera", rendered)
        sql = seen[0]
        self.assertIn("RECONCILIATION_REQUIRED", sql)
        self.assertIn("STARTED", sql)
        self.assertIn("state='CREATED'", sql)
        self.assertIn("NOT EXISTS", sql)
        self.assertIn("guard.license_links", sql)


class OwnerPanelContractTests(unittest.TestCase):
    def test_owner_panel_has_both_license_routes_and_indefinite_service(self):
        # AST verifies the actual OWNER-rendering endpoint independently of FastAPI.
        panel = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "multiguard_panel_pending"
        )
        literals = [
            node.value for node in ast.walk(panel)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        markup = "\\n".join(literals)
        self.assertIn("/direct", markup)
        self.assertIn("/assign", markup)
        self.assertIn('value="STANDARD"', markup)
        self.assertIn('value="PRO"', markup)
        self.assertEqual(markup.count('value="SERVICE"'), 2)
        self.assertIn("Tryb serwisowy (bezterminowy)", markup)
        self.assertIn("PRZEKAŻ KLIENTOWI", markup)
        self.assertIn("csrf_token", markup)


class DiscoveryRegistrationSecurityTests(unittest.TestCase):
    def test_existing_asus_identity_rejects_foreign_device_or_credential(self):
        # Production endpoint, fake SQL transaction, no secrets or network.
        from types import SimpleNamespace
        from contextlib import nullcontext
        original = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "discovery_register"
        )
        original.decorator_list = []
        module = ast.Module(body=[original], type_ignores=[])
        ast.fix_missing_locations(module)
        updates = []
        class Result:
            def __init__(self, row):
                self.row = row
            def mappings(self):
                return self
            def first(self):
                return self.row
        class Connection:
            def __init__(self, existing):
                self.existing = existing
            def execute(self, query, params):
                if "SELECT *" in str(query):
                    return Result(self.existing)
                updates.append(str(query))
                raise AssertionError("Security check must block database writes")
        class Engine:
            def __init__(self, existing):
                self.existing = existing
            def begin(self):
                return nullcontext(Connection(self.existing))
        installed_id = str(uuid.uuid4())
        req = SimpleNamespace(
            installation_id=installed_id, device_id="asus-original",
            discovery_credential="secret-original",
        )
        env = {
            "DiscoveryRegisterRequest": object,
            "_ensure_schema": lambda: None,
            "uuid": uuid,
            "_hash": lambda value: "sha-" + value,
            "_utcnow": lambda: None,
            "engine": None,
            "text": lambda sql: sql,
            "HTTPException": FakeHTTPException,
            "secrets": __import__("secrets"),
        }
        exec(compile(module, str(source_file), "exec"), env)
        registered = {
            "device_id": "asus-original",
            "discovery_credential_sha256": "sha-secret-original",
        }
        for label, data in [
            ("device changed", {**registered, "device_id": "other-device"}),
            ("credential changed", {**registered, "discovery_credential_sha256": "sha-other"}),
        ]:
            with self.subTest(label=label):
                env["engine"] = Engine(data)
                with self.assertRaises(FakeHTTPException) as failure:
                    env["discovery_register"](req)
                self.assertEqual(failure.exception.status_code, 409 if label == "device changed" else 401)
        self.assertEqual(updates, [])


class DiscoveryQueueContractTests(unittest.TestCase):
    def test_unlicensed_computer_is_waiting_and_service_grant_is_signed(self):
        # Execute the real discovery endpoint against an isolated in-memory DB.
        from types import SimpleNamespace
        from contextlib import nullcontext
        original = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "discovery_assignment"
        )
        original.decorator_list = []
        module = ast.Module(body=[original], type_ignores=[])
        ast.fix_missing_locations(module)
        iid = uuid.uuid4()
        pending = {
            "installation_id": iid, "device_id": "asus-test",
            "status": "WAITING", "assigned_reception_id": None,
            "assigned_license_id": None,
        }
        queries = []
        class Result:
            def scalar_one(self):
                return "WAITING"
        class Connection:
            def execute(self, query, params):
                queries.append(str(query))
                return Result()
        class Engine:
            def begin(self):
                return nullcontext(Connection())
        grant = None
        def find_grant(installation_id):
            self.assertEqual(installation_id, iid)
            return grant
        env = {
            "DiscoveryAssignmentRequest": object,
            "_authenticate_pending": lambda *args: pending.copy(),
            "engine": Engine(),
            "text": lambda sql: sql,
            "_workshop_grant": find_grant,
            "_signed_workshop_grant": lambda p, g: {"payload": "signed", "signatureB64": "test"},
            "_iso": lambda _: "2026-10-13T00:00:00Z",
            "_utcnow": lambda: None,
        }
        exec(compile(module, str(source_file), "exec"), env)
        req = SimpleNamespace(
            installation_id=iid, device_id="asus-test", discovery_credential="test"
        )
        waiting = env["discovery_assignment"](req)
        self.assertFalse(waiting["assigned"])
        self.assertEqual(waiting["status"], "WAITING")
        self.assertNotIn("provisioningToken", waiting)
        self.assertNotIn("workshopLease", waiting)
        grant = {"enabled": True, "release_channel": "STABLE", "monitoring_profile": "OFF"}
        service = env["discovery_assignment"](req)
        self.assertFalse(service["assigned"])
        self.assertEqual(service["status"], "WORKSHOP")
        self.assertEqual(service["workshopLease"]["payload"], "signed")
        self.assertEqual(service["workshopMonitoring"]["profile"], "OFF")
        grant["enabled"] = False
        revoked = env["discovery_assignment"](req)
        self.assertFalse(revoked["assigned"])
        self.assertEqual(revoked["status"], "WAITING")
        self.assertIn("workshopLease", revoked)
        self.assertFalse(revoked["workshopMonitoring"]["enabled"])
        self.assertTrue(any("UPDATE guard.pending_installations" in sql for sql in queries))


class BackendWindowsContractTests(unittest.TestCase):
    def test_workshop_lease_contains_windows_required_fields(self):
        # Verify the real backend JSON builder rather than a hand-written fixture.
        import json
        import base64
        from datetime import datetime, timezone

        builder = next(
            node for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "_signed_workshop_grant"
        )
        class FakeSigner:
            def sign(self, data):
                return b"test-signature"
        env = {
            "Any": Any,
            "json": json,
            "base64": base64,
            "_signing_key": lambda: FakeSigner(),
            "_iso": lambda dt: dt.isoformat(),
            "_utcnow": lambda: datetime.now(timezone.utc),
        }
        module = ast.Module(body=[builder], type_ignores=[])
        ast.fix_missing_locations(module)
        exec(compile(module, str(source_file), "exec"), env)
        installation_id = uuid.uuid4()
        device_id = "device-test"
        pending = {"installation_id": installation_id, "device_id": device_id}
        grant = {"edition": "PRO", "release_channel": "STABLE", "enabled": True}
        envelope = env["_signed_workshop_grant"](pending, grant)
        payload = json.loads(envelope["payload"])
        required = {
            "schemaVersion", "licenseId", "serviceDeviceId", "installationId",
            "deviceId", "planCode", "lifecycle", "validFrom", "validUntil",
            "acceptedAt", "acceptedDocuments", "serverTime",
        }
        self.assertTrue(required <= payload.keys())
        self.assertEqual(payload["lifecycle"], "WORKSHOP")
        self.assertEqual(payload["planCode"], "multi_guard_pro")
        self.assertEqual(payload["installationId"], str(installation_id))
        self.assertEqual(payload["deviceId"], device_id)
        self.assertEqual(base64.b64decode(envelope["signatureB64"]), b"test-signature")
        grant["enabled"] = False
        revoked = json.loads(env["_signed_workshop_grant"](pending, grant)["payload"])
        self.assertEqual(revoked["lifecycle"], "UNKNOWN")
        self.assertEqual(revoked["installationId"], str(installation_id))
        self.assertEqual(revoked["deviceId"], device_id)
        self.assertEqual(revoked["acceptedDocuments"], [])
        self.assertIsNone(revoked["validUntil"])
        # STANDARD service mode must never inherit PRO plan rights.
        grant["enabled"] = True
        grant["edition"] = "STANDARD"
        standard = json.loads(env["_signed_workshop_grant"](pending, grant)["payload"])
        self.assertEqual(standard["lifecycle"], "WORKSHOP")
        self.assertEqual(standard["planCode"], "multi_guard")
        self.assertEqual(standard["installationId"], str(installation_id))
        self.assertEqual(standard["deviceId"], device_id)
        self.assertIsNone(standard["validUntil"])



if __name__ == "__main__":
    unittest.main()
