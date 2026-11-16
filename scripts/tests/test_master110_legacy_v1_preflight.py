"""MASTER 1.10: execute the real OWNER legacy-v1 preflight with a fake DB.

No network, KeyGate or production PostgreSQL side effects.
"""
import ast
import copy
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
import uuid

SOURCE = Path(__file__).resolve().parents[2] / "embedded-multiguard/app/routers/multiguard_license.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCTION = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "owner_legacy_v1_preflight")
FUNCTION = copy.deepcopy(FUNCTION)
FUNCTION.decorator_list = []
FUNCTION.args.defaults = [ast.Constant(value=None)]
CODE = compile(ast.fix_missing_locations(ast.Module(
    body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), FUNCTION],
    type_ignores=[]
)), "<real-owner-legacy-v1-preflight>", "exec")

class HTTPException(Exception):
    def __init__(self, code, detail):
        self.status_code = code
        super().__init__(detail)

class Rows:
    def __init__(self, row):
        self.row = row
    def mappings(self):
        return self
    def first(self):
        return self.row

class Database:
    def __init__(self, state):
        self.state = state
        self.writes = 0
    def connect(self):
        return self
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def execute(self, query, params):
        sql = str(query).upper()
        if "UPDATE " in sql or "DELETE " in sql or "INSERT " in sql:
            self.writes += 1
            raise AssertionError("Preflight must be read-only")
        if "FROM GUARD.LICENSE_LINKS" in sql and "RECEPTION_ID" in sql:
            return Rows(self.state["link"])
        if "FROM GUARD.LICENSE_LINKS" in sql and "ID<>" in sql:
            return Rows(self.state.get("conflict"))
        if "FROM GUARD.INSTALLATIONS" in sql:
            return Rows((self.state["mirror"],) if self.state.get("mirror") else None)
        raise AssertionError("Unexpected query " + sql[:140])

class TestLegacyV1Preflight(unittest.TestCase):
    def setUp(self):
        self.rid = uuid.uuid4()
        self.iid = uuid.uuid4()
        self.valid = datetime.now(timezone.utc) + timedelta(days=45)
        self.state = {
            "link": {
                "id": uuid.uuid4(),
                "reception_id": self.rid,
                "installation_id": self.iid,
                "keygate_license_id": "paid-existing-license",
                "lifecycle": "ACTIVE",
                "valid_until": self.valid,
                "rebind_pending": False,
            },
            "mirror": self.iid,
            "conflict": None,
        }
        self.db = Database(self.state)
        env = {
            "uuid": uuid,
            "HTTPException": HTTPException,
            "Depends": lambda x: None,
            "require_owner": object(),
            "CurrentUser": object,
            "_ensure_schema": lambda: None,
            "engine": self.db,
            "text": lambda x: x,
            "_utcnow": lambda: datetime.now(timezone.utc),
            "_iso": lambda x: x.isoformat() if x else None,
        }
        exec(CODE, env)
        self.preflight = env["owner_legacy_v1_preflight"]

    def test_matching_paid_v1_is_reviewable_but_not_authorized(self):
        result = self.preflight(str(self.rid), str(self.iid))
        self.assertTrue(result["eligibleForOwnerReview"])
        self.assertTrue(result["requiresOwnerApproval"])
        self.assertFalse(result["authorizesMigration"])
        self.assertFalse(result["mutated"])
        self.assertEqual(self.db.writes, 0)
        self.assertEqual(self.state["link"]["valid_until"], self.valid)

    def test_cloned_or_unbound_installation_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            self.preflight(str(self.rid), str(uuid.uuid4()))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.db.writes, 0)

    def test_conflicting_claim_cannot_be_reviewed(self):
        self.state["conflict"] = ("other-license",)
        self.assertFalse(self.preflight(str(self.rid), str(self.iid))["eligibleForOwnerReview"])

    def test_expired_or_rebinding_license_cannot_be_reviewed(self):
        self.state["link"]["valid_until"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.assertFalse(self.preflight(str(self.rid), str(self.iid))["eligibleForOwnerReview"])
        self.state["link"]["valid_until"] = self.valid
        self.state["link"]["rebind_pending"] = True
        self.assertFalse(self.preflight(str(self.rid), str(self.iid))["eligibleForOwnerReview"])

    def test_missing_mirror_cannot_be_reviewed(self):
        self.state["mirror"] = None
        self.assertFalse(self.preflight(str(self.rid), str(self.iid))["eligibleForOwnerReview"])

if __name__ == "__main__":
    unittest.main()
