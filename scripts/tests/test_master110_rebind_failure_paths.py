"""MASTER 1.10: execute the real OWNER rebind function with fake transactional DB.

No credentials, network, PostgreSQL or KeyGate connection. Tests rollback and
journal transitions, including ambiguous external effects.
"""
import ast
import contextlib
import copy
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
import uuid

SRC = Path(__file__).resolve().parents[2] / "embedded-multiguard/app/routers/multiguard_license.py"
TREE = ast.parse(SRC.read_text(encoding="utf-8"))
FN = next(n for n in TREE.body if isinstance(n, ast.FunctionDef)
          and n.name == "rebind_reception_license")
FN = copy.deepcopy(FN)
FN.decorator_list = []
FN.args.defaults = [ast.Constant(value=None)]
CODE = compile(ast.fix_missing_locations(ast.Module(
    body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), FN],
    type_ignores=[])), "<actual-owner-rebind>", "exec")

class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        super().__init__(detail)

class Result:
    def __init__(self, value):
        self.value = value
    def first(self):
        return self.value
    def mappings(self):
        return self

class DB:
    def __init__(self, state, events, fail_stage=None):
        self.state = state
        self.events = events
        self.fail_stage = fail_stage
    @contextlib.contextmanager
    def begin(self):
        before = copy.deepcopy(self.state)
        try:
            yield self
        except Exception:
            self.state.clear()
            self.state.update(before)
            raise
    def execute(self, query, params):
        sql = str(query)
        if "SELECT * FROM guard.license_links" in sql:
            self.events.append("lock_license")
            return Result(copy.deepcopy(self.state))
        if "UPDATE guard.installations" in sql:
            self.events.append("update_installation")
            if self.fail_stage == "installation":
                raise RuntimeError("simulated PostgreSQL installation update failure")
            return Result(None)
        if "UPDATE guard.license_links" in sql:
            self.events.append("update_license")
            if self.fail_stage == "license":
                raise RuntimeError("simulated PostgreSQL license update failure")
            if self.state["installation_id"] != params["installation_id"]:
                return Result(None)
            self.state["installation_id"] = None
            self.state["device_id"] = None
            self.state["credential_sha256"] = None
            self.state["rebind_pending"] = True
            return Result(copy.deepcopy(self.state))
        raise AssertionError("Unexpected SQL: " + sql[:90])

class Tests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.iid = uuid.uuid4()
        self.rid = uuid.uuid4()
        self.state = {
            "id": uuid.uuid4(), "reception_id": self.rid,
            "keygate_license_id": "existing-paid",
            "installation_id": self.iid, "device_id": "device-old",
            "lifecycle": "ACTIVE", "valid_until": datetime.now(timezone.utc) + timedelta(days=40),
            "credential_sha256": "credential-old", "rebind_pending": False,
        }
        self.journal = []
        self.fail_deactivate = False
        self.db = DB(self.state, self.events)
        def begin(link):
            self.events.append("durable_intent")
            self.journal.append(["INTENT"])
            return uuid.uuid4()
        def finish(attempt, committed):
            self.events.append("finish_committed" if committed else "finish_review")
            self.journal[-1][0] = "COMMITTED" if committed else "NEEDS_REVIEW"
        def deactivate(key, device):
            self.events.append("keygate_deactivate")
            if self.fail_deactivate:
                raise RuntimeError("simulated ambiguous KeyGate failure")
        ns = {
            "uuid": uuid, "HTTPException": HTTPException, "Depends": lambda arg: None,
            "require_owner": object(), "CurrentUser": object, "engine": self.db,
            "text": lambda sql: sql, "_utcnow": lambda: datetime.now(timezone.utc),
            "_ensure_schema": lambda: None,
            "_link_by_reception_id": lambda rid: copy.deepcopy(self.state),
            "_normalize_link": lambda row: row,
            "_keygate_reveal": lambda lic: "KG-TEST-KEY",
            "_begin_keygate_rebind_attempt": begin,
            "_finish_keygate_rebind_attempt": finish,
            "_keygate_deactivate": deactivate,
            "_public_status": lambda row: {"lifecycle": row["lifecycle"]},
        }
        exec(CODE, ns)
        self.rebind = ns["rebind_reception_license"]

    def test_success_commits_after_external_deactivation_and_keeps_paid_term(self):
        old_end = self.state["valid_until"]
        self.rebind(str(self.rid))
        self.assertEqual(self.journal[-1][0], "COMMITTED")
        self.assertEqual(self.state["valid_until"], old_end)
        self.assertTrue(self.state["rebind_pending"])
        self.assertIsNone(self.state["installation_id"])
        self.assertLess(self.events.index("durable_intent"), self.events.index("keygate_deactivate"))
        self.assertLess(self.events.index("keygate_deactivate"), self.events.index("update_license"))
        self.assertLess(self.events.index("update_license"), self.events.index("finish_committed"))

    def test_ambiguous_keygate_failure_keeps_binding_and_blocks_retry(self):
        self.fail_deactivate = True
        with self.assertRaises(RuntimeError):
            self.rebind(str(self.rid))
        self.assertEqual(self.journal[-1][0], "NEEDS_REVIEW")
        self.assertEqual(self.state["installation_id"], self.iid)
        self.assertFalse(self.state["rebind_pending"])

    def test_postgresql_failure_after_deactivation_keeps_binding_and_requires_review(self):
        self.db.fail_stage = "license"
        with self.assertRaises(RuntimeError):
            self.rebind(str(self.rid))
        self.assertEqual(self.journal[-1][0], "NEEDS_REVIEW")
        self.assertEqual(self.state["installation_id"], self.iid)
        self.assertFalse(self.state["rebind_pending"])
        self.assertIn("keygate_deactivate", self.events)

    def test_expired_license_never_calls_keygate(self):
        self.state["valid_until"] = datetime.now(timezone.utc) - timedelta(days=1)
        with self.assertRaises(HTTPException):
            self.rebind(str(self.rid))
        self.assertEqual(self.journal, [])
        self.assertNotIn("keygate_deactivate", self.events)

    def test_rebind_pending_never_calls_keygate(self):
        self.state["rebind_pending"] = True
        with self.assertRaises(HTTPException):
            self.rebind(str(self.rid))
        self.assertEqual(self.journal, [])
        self.assertNotIn("keygate_deactivate", self.events)

if __name__ == "__main__":
    unittest.main()
