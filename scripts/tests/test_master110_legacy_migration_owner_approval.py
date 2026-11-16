"""OWNER legacy migration approval: isolated execution of production handler.

The approval transition must never transfer a paid licence or touch KeyGate.
"""
import ast
import copy
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

SOURCE=Path(__file__).resolve().parents[2]/"embedded-multiguard/app/routers/multiguard_license.py"
TREE=ast.parse(SOURCE.read_text(encoding="utf-8"))
fn=copy.deepcopy(next(n for n in TREE.body if isinstance(n,ast.FunctionDef)
  and n.name=="owner_approve_legacy_migration"))
fn.decorator_list=[]
fn.args.defaults=[ast.Constant(value=None)]
CODE=compile(ast.fix_missing_locations(ast.Module(body=[
 ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0),fn
],type_ignores=[])),"<owner-migration-approval>","exec")

class HTTPException(Exception):
    def __init__(self,code,detail):
        self.status_code=code
        super().__init__(detail)
class Rows:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row
class DB:
    def __init__(self,state):
        self.state=state
        self.writes=[]
    def begin(self):return self
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def execute(self,query,params):
        sql=str(query).upper()
        if "SELECT * FROM GUARD.LEGACY_MIGRATION_REQUESTS" in sql:
            return Rows(self.state["stage"])
        if "SELECT * FROM GUARD.LICENSE_LINKS" in sql:
            return Rows(self.state["license"])
        if "SELECT ID FROM GUARD.LICENSE_LINKS" in sql:
            return Rows(self.state.get("conflict"))
        if "UPDATE GUARD.LEGACY_MIGRATION_REQUESTS" in sql:
            self.writes.append("approval")
            self.state["stage"]["status"]="APPROVED"
            return Rows((params["mid"],))
        raise AssertionError("Unexpected SQL: "+sql[:110])
class Body:
    def __init__(self,lic,old,new):
        self.expected_license_id=lic
        self.old_installation_id=str(old)
        self.new_installation_id=str(new)

class Tests(unittest.TestCase):
    def setUp(self):
        self.mid,self.old,self.new=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
        self.until=datetime.now(timezone.utc)+timedelta(days=35)
        self.stage={
            "id":self.mid,"old_installation_id":self.old,
            "new_installation_id":self.new,"license_id":"paid-123",
            "device_id":"a"*64,
            "status":"WAITING_OWNER",
            "created_at":datetime.now(timezone.utc),
        }
        self.license={
            "keygate_license_id":"paid-123",
            "device_id":"a"*64,
            "credential_sha256":"b"*64,
            "rebind_pending":False,
            "lifecycle":"ACTIVE",
            "valid_until":self.until,
        }
        self.state={"stage":self.stage,"license":self.license}
        self.db=DB(self.state)
        env={
            "uuid":uuid,"HTTPException":HTTPException,
            "ApproveLegacyMigrationRequest":Body,
            "Depends":lambda x:None,"require_owner":object(),
            "CurrentUser":object,"engine":self.db,"text":str,
            "_ensure_schema":lambda:None,
            "_utcnow":lambda:datetime.now(timezone.utc),
        }
        exec(CODE,env)
        self.call=env["owner_approve_legacy_migration"]
        self.body=Body("paid-123",self.old,self.new)
    def test_approval_changes_only_stage_not_licence(self):
        before=dict(self.license)
        result=self.call(str(self.mid),self.body)
        self.assertEqual(result["status"],"APPROVED")
        self.assertTrue(result["requiresClientCommit"])
        for field in ("licenseChanged","credentialChanged","keygateChanged","meshChanged","validUntilChanged"):
            self.assertFalse(result[field])
        self.assertEqual(self.license,before)
        self.assertEqual(self.db.writes,["approval"])
    def test_second_approval_does_not_repeat(self):
        self.call(str(self.mid),self.body)
        with self.assertRaises(HTTPException) as err:self.call(str(self.mid),self.body)
        self.assertEqual(err.exception.status_code,409)
        self.assertEqual(self.db.writes,["approval"])
    def test_expired_stage_fails_closed(self):
        self.stage["created_at"]-=timedelta(minutes=16)
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.body)
        self.assertFalse(self.db.writes)
    def test_wrong_expected_licence_is_not_authorized(self):
        self.body.expected_license_id="paid-other"
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.body)
        self.assertFalse(self.db.writes)
    def test_revoked_or_expired_licence_cannot_be_approved(self):
        self.license["lifecycle"]="REVOKED"
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.body)
        self.license["lifecycle"]="ACTIVE"
        self.license["valid_until"]=datetime.now(timezone.utc)-timedelta(days=1)
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.body)
        self.assertFalse(self.db.writes)
    def test_conflicting_new_installation_blocked(self):
        self.state["conflict"]=("existing-link",)
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.body)
        self.assertFalse(self.db.writes)

if __name__=="__main__":unittest.main()
