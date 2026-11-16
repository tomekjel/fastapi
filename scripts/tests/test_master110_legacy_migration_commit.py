"""MASTER110 real commit handler: isolated transaction, rollback, idempotent replay."""
import ast
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
import unittest
import uuid

SRC=Path(__file__).resolve().parents[2]/"embedded-multiguard/app/routers/multiguard_license.py"
TREE=ast.parse(SRC.read_text(encoding="utf-8"))
FN=copy.deepcopy(next(n for n in TREE.body if isinstance(n,ast.FunctionDef) and n.name=="commit_legacy_migration"))
FN.decorator_list=[]
CODE=compile(ast.fix_missing_locations(ast.Module(body=[
    ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0),FN
],type_ignores=[])),"<owner-migration-commit>","exec")

class HTTPException(Exception):
    def __init__(self,code,detail):self.status_code=code;super().__init__(detail)
class Rows:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row
class Transaction:
    def __init__(self,state):self.state=state;self.events=[];self.fail=False
    def begin(self):return self
    def __enter__(self):
        import copy
        self.snapshot=copy.deepcopy(self.state)
        return self
    def __exit__(self,exc_type,*_):
        if exc_type:
            self.state.clear()
            self.state.update(self.snapshot)
        return False
    def execute(self,query,args):
        sql=str(query).upper()
        if "SELECT * FROM GUARD.LEGACY_MIGRATION_REQUESTS" in sql:return Rows(self.state["stage"])
        if "SELECT * FROM GUARD.LICENSE_LINKS" in sql and "INSTALLATION_ID=:OLD_ID" in sql:
            return Rows(self.state["link"] if self.state["link"]["installation_id"]==args["old_id"] else None)
        if "SELECT * FROM GUARD.LICENSE_LINKS" in sql and "INSTALLATION_ID=:NEW_ID" in sql:
            if self.state["link"]["installation_id"]==args["new_id"]:
                return Rows(self.state["link"])
            return Rows(self.state.get("conflict"))
        if "SELECT ID FROM GUARD.LICENSE_LINKS" in sql:return Rows(self.state.get("conflict"))
        if "UPDATE GUARD.LICENSE_LINKS" in sql:
            if self.fail:raise RuntimeError("simulated database failure")
            self.events.append("rotate")
            link=self.state["link"]
            link["installation_id"]=args["new_id"]
            link["credential_sha256"]=args["new_hash"]
            return Rows(dict(link))
        if "UPDATE GUARD.LEGACY_MIGRATION_REQUESTS" in sql:
            self.events.append("complete")
            self.state["stage"]["status"]="COMPLETED"
            return Rows((args["mid"],))
        raise AssertionError("Unexpected SQL "+sql[:120])

class Request:
    def __init__(self,old,new,old_secret,new_secret,discover):
        self.old_installation_id=str(old)
        self.new_installation_id=str(new)
        self.old_installation_credential=old_secret
        self.new_installation_credential=new_secret
        self.new_discovery_credential=discover

class Tests(unittest.TestCase):
    def setUp(self):
        self.mid,self.old,self.new=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
        self.old_secret="old-"+"x"*45
        self.new_secret="new-"+"y"*45
        self.discover="disc-"+"z"*45
        self.until=datetime.now(timezone.utc)+timedelta(days=40)
        self.state={
            "stage":{
                "old_installation_id":self.old,
                "new_installation_id":self.new,
                "license_id":"same-paid-license",
                "new_discovery_sha256":hashlib.sha256(self.discover.encode()).hexdigest(),
                "device_id":"a"*64,
                "status":"APPROVED",
                "created_at":datetime.now(timezone.utc),
            },
            "link":{
                "id":uuid.uuid4(),
                "keygate_license_id":"same-paid-license",
                "installation_id":self.old,
                "credential_sha256":hashlib.sha256(self.old_secret.encode()).hexdigest(),
                "device_id":"a"*64,
                "rebind_pending":False,
                "lifecycle":"ACTIVE",
                "valid_until":self.until,
            },
        }
        self.db=Transaction(self.state)
        self.req=Request(self.old,self.new,self.old_secret,self.new_secret,self.discover)
        env={
            "uuid":uuid,"secrets":secrets,"HTTPException":HTTPException,
            "CommitLegacyMigrationRequest":Request,
            "engine":self.db,"text":str,"_ensure_schema":lambda:None,
            "_utcnow":lambda:datetime.now(timezone.utc),
            "_hash":lambda x:hashlib.sha256(x.encode()).hexdigest(),
            "_normalize_link":dict,
            "_update_installation_mirror":lambda connection,row: connection.events.append("mirror"),
            "_signed_envelope":lambda row,recovery_approved=False:{"payload":str(row["installation_id"]),
                "recoveryApproved":recovery_approved},
        }
        exec(CODE,env)
        self.call=env["commit_legacy_migration"]
    def test_atomic_commit_preserves_expiry_and_does_not_contact_keygate(self):
        result=self.call(str(self.mid),self.req)
        self.assertEqual(result["status"],"COMPLETED")
        self.assertFalse(result["keygateChanged"])
        self.assertFalse(result["validUntilChanged"])
        self.assertTrue(result["meshReenrollmentRequired"])
        self.assertEqual(self.state["link"]["valid_until"],self.until)
        self.assertEqual(self.state["link"]["installation_id"],self.new)
        self.assertEqual(self.state["link"]["credential_sha256"],
            hashlib.sha256(self.new_secret.encode()).hexdigest())
        self.assertEqual(self.db.events,["rotate","mirror","complete"])
    def test_retry_after_lost_http_response_requires_exact_new_secret(self):
        self.call(str(self.mid),self.req)
        self.db.events.clear()
        result=self.call(str(self.mid),self.req)
        self.assertTrue(result["alreadyCommitted"])
        self.assertEqual(self.db.events,[])
        self.req.new_installation_credential="wrong-new-secret-"+"q"*40
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.req)
    def test_wrong_old_secret_is_not_accepted(self):
        self.req.old_installation_credential="other-"+"p"*50
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.req)
        self.assertEqual(self.state["link"]["installation_id"],self.old)
    def test_no_owner_approval_no_commit(self):
        self.state["stage"]["status"]="WAITING_OWNER"
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.req)
        self.assertEqual(self.db.events,[])
    def test_database_failure_rolls_back_licence_and_stage(self):
        self.db.fail=True
        with self.assertRaises(RuntimeError):self.call(str(self.mid),self.req)
        self.assertEqual(self.state["stage"]["status"],"APPROVED")
        self.assertEqual(self.state["link"]["installation_id"],self.old)
    def test_duplicate_new_identity_rejected(self):
        self.state["conflict"]=("other-license",)
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.req)
        self.assertEqual(self.db.events,[])
    def test_expired_paid_licence_rejected(self):
        self.state["link"]["valid_until"]=datetime.now(timezone.utc)-timedelta(days=1)
        with self.assertRaises(HTTPException):self.call(str(self.mid),self.req)
        self.assertEqual(self.db.events,[])

if __name__=="__main__":unittest.main()
