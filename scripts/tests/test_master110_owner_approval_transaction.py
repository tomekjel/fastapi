"""MASTER110: execute actual OWNER approval function with transactional fake DB.

No real database or KeyGate or MeshCentral is accessed. Test captures SQL
operations and rolls back pending status on errors, preserving license term.
"""
import ast
import contextlib
import copy
from datetime import datetime, timezone, timedelta
from pathlib import Path
import secrets
import types
import unittest
import uuid

CODE = Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
TREE = ast.parse(CODE)
SOURCE = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "approve_pending_recovery")
# Strip the FastAPI decorator; exercise body as authored.
STUB = ast.FunctionDef(name="approve", args=SOURCE.args, body=SOURCE.body,
                       decorator_list=[], returns=None, type_comment=None)
FUTURE = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
COMPILED = compile(ast.fix_missing_locations(ast.Module(body=[FUTURE, STUB], type_ignores=[])), "<actual-owner-approve>", "exec")
NOW = datetime.now(timezone.utc)
RID = uuid.uuid4()
IID = uuid.uuid4()

class HTTPException(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code

class Result:
    def __init__(self, row=None): self.row = row
    def mappings(self): return self
    def first(self): return self.row

class FakeConn:
    def __init__(self, data): self.data = data
    def execute(self, sql, params):
        statement = str(sql)
        self.data["queries"].append(statement)
        if "SELECT * FROM guard.pending_installations" in statement:
            return Result(self.data["pending"])
        if "SELECT * FROM guard.license_links" in statement:
            return Result(self.data["link"])
        if "FROM guard.installations" in statement:
            return Result({"installation_external_id": IID} if self.data["old_active"] else None)
        if "SELECT id FROM guard.license_links" in statement:
            return Result({"id": uuid.uuid4()} if self.data["other_claim"] else None)
        if "UPDATE guard.pending_installations" in statement:
            self.data["pending"]["status"] = "ASSIGNED"
            self.data["pending"]["assigned_reception_id"] = params["rid"]
            self.data["pending"]["assigned_license_id"] = params["keygate_id"]
            return Result({"installation_id": IID})
        raise AssertionError("Unexpected SQL operation: " + statement)

class FakeEngine:
    def __init__(self, data): self.data = data
    @contextlib.contextmanager
    def begin(self):
        snapshot = copy.deepcopy(self.data)
        try:
            yield FakeConn(self.data)
        except BaseException:
            self.data.clear()
            self.data.update(snapshot)
            raise

class Tests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "queries": [],
            "pending": {
                "status": "WAITING",
                "discovery_credential_sha256": "a"*64,
                "last_seen_at": NOW,
                "assigned_reception_id": None,
                "device_id": "device-hash",
            },
            "link": {
                "id": uuid.uuid4(), "keygate_license_id": "LIC-OLD",
                "rebind_pending": True, "installation_id": None,
                "lifecycle": "ACTIVE", "valid_until": NOW + timedelta(days=60),
                "reception_id": RID,
            },
            "old_active": False,
            "other_claim": False,
        }
        env = {
            "uuid": uuid, "HTTPException": HTTPException, "secrets": secrets,
            "Depends": lambda x: None, "require_owner": object(),
            "engine": FakeEngine(self.data), "text": lambda sql: sql,
            "_ensure_schema": lambda: None, "_utcnow": lambda: NOW,
        }
        exec(COMPILED, env)
        self.approve = env["approve"]
        self.body = types.SimpleNamespace(reception_id=str(RID),expected_license_id="LIC-OLD")
    def call(self):
        return self.approve(str(IID), self.body, user=object())
    def reject(self, code):
        with self.assertRaises(HTTPException) as cm: self.call()
        self.assertEqual(code, cm.exception.status_code)
        self.assertEqual("WAITING", self.data["pending"]["status"])
        self.assertEqual(NOW + timedelta(days=60), self.data["link"]["valid_until"])
        self.assertFalse(any("UPDATE guard.license_links" in q for q in self.data["queries"]))
    def test_approved_recovery_keeps_paid_date(self):
        result = self.call()
        self.assertEqual("ASSIGNED", result["status"])
        self.assertFalse(result["createdNewLicense"])
        self.assertFalse(result["changedLicenseValidity"])
        self.assertFalse(result["meshChanged"])
        self.assertEqual(NOW + timedelta(days=60), self.data["link"]["valid_until"])
        self.assertEqual(RID, self.data["pending"]["assigned_reception_id"])
        self.assertFalse(any("UPDATE guard.license_links" in q for q in self.data["queries"]))
    def test_denied_when_device_offline(self):
        self.data["pending"]["last_seen_at"] = NOW - timedelta(minutes=6)
        self.reject(409)
    def test_denied_when_rebind_not_enabled(self):
        self.data["link"]["rebind_pending"] = False
        self.reject(409)
    def test_denied_when_prior_install_current(self):
        self.data["old_active"] = True
        self.reject(409)
    def test_denied_when_old_license_revoked(self):
        self.data["link"]["lifecycle"] = "REVOKED"
        self.reject(409)
    def test_denied_when_licence_expired(self):
        self.data["link"]["valid_until"] = NOW - timedelta(seconds=1)
        with self.assertRaises(HTTPException) as cm: self.call()
        self.assertEqual(409, cm.exception.status_code)
        self.assertEqual("WAITING", self.data["pending"]["status"])
    def test_denied_when_license_changed_since_owner_review(self):
        self.body.expected_license_id = "LIC-CHANGED"
        self.reject(409)
    def test_denied_when_other_license_claims_device(self):
        self.data["other_claim"] = True
        self.reject(409)
    def test_denied_when_install_already_assigned(self):
        self.data["pending"]["assigned_reception_id"] = uuid.uuid4()
        self.reject(409)

if __name__ == "__main__":
    unittest.main()
