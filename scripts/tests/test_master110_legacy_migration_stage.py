"""MASTER110 stage gate — real request handler with an isolated transactional fake.

No network, no real database and no license mutations.
"""
import ast
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import secrets
import unittest
import uuid

SOURCE=Path(__file__).resolve().parents[2]/"embedded-multiguard/app/routers/multiguard_license.py"
tree=ast.parse(SOURCE.read_text(encoding="utf-8"))
fn=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)
    and n.name=="request_legacy_migration"))
fn.decorator_list=[]
code=compile(ast.fix_missing_locations(ast.Module(body=[
    ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0),fn
],type_ignores=[])),"<legacy-stage>","exec")

class HTTPException(Exception):
    def __init__(self,status_code,detail):
        self.status_code=status_code
        super().__init__(detail)

class Result:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row

class Connection:
    def __init__(self,state):
        self.state=state
        self.writes=[]
    def execute(self,query,args):
        sql=str(query).upper()
        if "FROM GUARD.LICENSE_LINKS" in sql and "INSTALLATION_ID=:OLD_ID" in sql:
            return Result(self.state["link"])
        if "FROM GUARD.LICENSE_LINKS" in sql and "INSTALLATION_ID=:NEW_ID" in sql:
            return Result(self.state.get("claimed"))
        if "INSERT INTO GUARD.LEGACY_MIGRATION_REQUESTS" in sql:
            self.writes.append(("staged",dict(args)))
            if self.state.get("already_staged"):
                return Result(None)
            return Result((args["id"],))
        raise AssertionError("unexpected SQL: "+sql[:100])

class FakeEngine:
    def __init__(self,connection):self.conn=connection
    def begin(self):return self
    def __enter__(self):return self.conn
    def __exit__(self,*_):return False

class Request:
    def __init__(self,old,new,device,old_secret,new_secret):
        self.old_installation_id=str(old)
        self.new_installation_id=str(new)
        self.device_id=device
        self.old_installation_credential=old_secret
        self.new_discovery_credential=new_secret

class StageTests(unittest.TestCase):
    def setUp(self):
        self.old=uuid.uuid4()
        self.new=uuid.uuid4()
        self.device="a"*64
        self.secret="old-secret-"+"q"*45
        self.new_secret="new-secret-"+"r"*45
        self.valid=datetime.now(timezone.utc)+timedelta(days=70)
        self.link={
            "id":uuid.uuid4(),"keygate_license_id":"paid-license",
            "credential_sha256":hashlib.sha256(self.secret.encode()).hexdigest(),
            "device_id":self.device,
            "lifecycle":"ACTIVE",
            "rebind_pending":False,
            "valid_until":self.valid,
        }
        self.state={"link":self.link}
        self.conn=Connection(self.state)
        env={
            "uuid":uuid,"secrets":secrets,"HTTPException":HTTPException,
            "LegacyMigrationRequest":Request,
            "router":object(),"engine":FakeEngine(self.conn),"text":str,
            "_ensure_schema":lambda:None,
            "_utcnow":lambda:datetime.now(timezone.utc),
            "_hash":lambda x:hashlib.sha256(x.encode()).hexdigest(),
        }
        exec(code,env)
        self.call=env["request_legacy_migration"]
        self.req=Request(self.old,self.new,self.device,self.secret,self.new_secret)

    def test_valid_old_secret_stages_but_cannot_grant_license(self):
        before=dict(self.link)
        result=self.call(self.req)
        self.assertEqual(result["status"],"WAITING_OWNER")
        self.assertTrue(result["requiresOwnerApproval"])
        self.assertFalse(result["licenseChanged"])
        self.assertFalse(result["keygateChanged"])
        self.assertFalse(result["meshChanged"])
        self.assertEqual(self.link,before)
        self.assertEqual(len(self.conn.writes),1)
        self.assertEqual(self.conn.writes[0][1]["credential_hash"],
            hashlib.sha256(self.new_secret.encode()).hexdigest())
        self.assertNotIn(self.secret,str(self.conn.writes))
        self.assertNotIn(self.new_secret,str(self.conn.writes))

    def test_wrong_old_credential_fails_without_writes(self):
        self.req.old_installation_credential="invalid"+"x"*40
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,403)
        self.assertFalse(self.conn.writes)

    def test_new_secret_must_be_independent(self):
        self.req.new_discovery_credential=self.secret
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,400)
        self.assertFalse(self.conn.writes)

    def test_different_hardware_fails_closed(self):
        self.req.device_id="b"*64
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,409)
        self.assertFalse(self.conn.writes)

    def test_rebind_pending_and_expired_rejected(self):
        self.link["rebind_pending"]=True
        with self.assertRaises(HTTPException):self.call(self.req)
        self.link["rebind_pending"]=False
        self.link["valid_until"]=datetime.now(timezone.utc)-timedelta(days=1)
        with self.assertRaises(HTTPException):self.call(self.req)
        self.assertFalse(self.conn.writes)

    def test_concurrent_attempt_conflict_rejected(self):
        self.state["already_staged"]=True
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,409)

    def test_new_uuid_cannot_be_existing_license_or_old_uuid(self):
        self.state["claimed"]=("already-claimed",)
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,409)
        self.req.new_installation_id=str(self.old)
        with self.assertRaises(HTTPException) as e:self.call(self.req)
        self.assertEqual(e.exception.status_code,400)

if __name__=="__main__":
    unittest.main()
