"""Run actual OWNER reconciliation diagnostics against fake database and KeyGate.

The handler is extracted from production AST, with NO real HTTP/DB connection.
"""
from __future__ import annotations
import ast
from datetime import datetime, timezone
from pathlib import Path
import types
import unittest
import uuid

SOURCE=Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
function=next(n for n in ast.parse(SOURCE).body if isinstance(n,ast.FunctionDef)
              and n.name=="owner_keygate_reconciliation_diagnostics")
unit=ast.Module(body=[ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0),function],type_ignores=[])
function.decorator_list=[]
script=compile(ast.fix_missing_locations(unit),"<real-owner-reconciliation>","exec")
ATTEMPT=uuid.uuid4()
INSTALL=uuid.uuid4()
NOW=datetime.now(timezone.utc)

class HTTPException(Exception):
    def __init__(self,status,detail):self.status_code=status;super().__init__(detail)
class Rows:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row
class Conn:
    def __init__(self,fixture):self.fixture=fixture
    def execute(self,query,params):
        query=str(query)
        if "FROM guard.keygate_provision_attempts" in query:
            return Rows(self.fixture["attempt"])
        if "FROM guard.license_links" in query:
            return Rows(self.fixture["link"])
        raise AssertionError("Unexpected or mutating query "+query)
class Engine:
    def __init__(self,fixture):self.fixture=fixture
    def connect(self):return self
    def __enter__(self):return Conn(self.fixture)
    def __exit__(self,*a):return False
class Cases(unittest.TestCase):
    def setUp(self):
        self.fixture={
            "attempt":{"id":ATTEMPT,"keygate_license_id":"LIC-ID","installation_id":INSTALL,
                       "device_id":"DEVICE-ID","state":"NEEDS_REVIEW",
                       "created_at":NOW,"updated_at":NOW},
            "link":{"installation_id":INSTALL,"device_id":"DEVICE-ID","rebind_pending":False,
                    "lifecycle":"ACTIVE","valid_until":NOW},
        }
        self.remote={"status":"active","license_key":"SECRET_MUST_NOT_LEAK"}
        env={"uuid":uuid,"HTTPException":HTTPException,"engine":Engine(self.fixture),
             "text":lambda s:s,"_ensure_schema":lambda:None,
             "_keygate_license":lambda license_id:self.remote,
             "_iso":lambda d:d.isoformat() if d else None,
             "Depends":lambda dep:None,"require_owner":object()}
        exec(script,env)
        self.run=env["owner_keygate_reconciliation_diagnostics"]
    def test_matching_systems_still_need_owner_review(self):
        out=self.run(str(ATTEMPT),user=object())
        self.assertTrue(out["databaseMatchesAttempt"])
        self.assertTrue(out["requiresOwnerReview"])
        self.assertFalse(out["safeToResolveAutomatically"])
        self.assertFalse(out["mayAutomaticallyRetry"])
        self.assertEqual("ACTIVE",out["keygateLicenseStatus"])
        self.assertNotIn("SECRET_MUST_NOT_LEAK",str(out))
    def test_missing_owner_license_does_not_recover(self):
        self.fixture["link"]=None
        out=self.run(str(ATTEMPT),user=object())
        self.assertFalse(out["licensePresentInOwner"])
        self.assertFalse(out["databaseMatchesAttempt"])
        self.assertTrue(out["requiresOwnerReview"])
    def test_keygate_failure_keeps_review_block(self):
        self.remote=None
        # Simulate KeyGate unavailable (raise from fake).
        env=self.run.__globals__
        env["_keygate_license"]=lambda license_id:(_ for _ in ()).throw(RuntimeError("offline"))
        out=self.run(str(ATTEMPT),user=object())
        self.assertFalse(out["keygateReachable"])
        self.assertEqual("UNKNOWN",out["keygateLicenseStatus"])
        self.assertFalse(out["safeToResolveAutomatically"])
    def test_invalid_id_does_not_query_services(self):
        with self.assertRaises(HTTPException) as error:self.run("INVALID",user=object())
        self.assertEqual(400,error.exception.status_code)

if __name__=="__main__":unittest.main()
