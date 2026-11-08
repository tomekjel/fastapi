"""Offline OWNER Service grant authorization tests, no DB or Mesh access."""
import ast
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

SRC=Path(__file__).with_name("master15_owner_profile_bridge.py")
NOW=datetime(2026,11,8,21,0,tzinfo=timezone.utc)

class HttpError(Exception):
    def __init__(self,status_code,detail):
        self.status_code=status_code
        self.detail=detail

class Result:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row

class DB:
    def __init__(self,grant):self.grant=grant;self.calls=0
    def execute(self,sql,args):
        assert "guard.workshop_grants" in str(sql)
        assert "installation_id" in args
        self.calls+=1
        return Result(self.grant)

class License:
    def __init__(self,mode):self.mode=mode
    def _owner_effective_entitlement_mode(self,db,iid):return self.mode

def load_target(mode):
    module=ast.parse(SRC.read_text(encoding="utf-8"))
    target=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=="_owner_target"]
    assert len(target)==1
    code=compile(ast.Module(body=target,type_ignores=[]),str(SRC),"exec")
    namespace={
        "license":License(mode),
        "text":lambda sql:sql,
        "HTTPException":HttpError,
        "_now":lambda:NOW,
    }
    exec(code,namespace)
    return namespace["_owner_target"]

class TestSignedServiceAuthorization(unittest.TestCase):
    def link(self):
        return {
            "lifecycle":"ACTIVE","rebind_pending":False,
            "valid_until":NOW+timedelta(days=30),
            "accepted_at":NOW-timedelta(days=1),
            "plan_code":"multi_guard",
        }
    def test_service_requires_active_workshop_grant(self):
        f=load_target("SERVICE")
        for grant in (None,{"enabled":False,"valid_until":NOW+timedelta(days=1)},
                      {"enabled":True,"valid_until":NOW-timedelta(seconds=1)},
                      {"enabled":True,"valid_until":None}):
            with self.assertRaises(HttpError) as caught:
                f(DB(grant),"asus-install",self.link())
            self.assertEqual(caught.exception.status_code,409)
        valid=DB({"enabled":True,"valid_until":NOW+timedelta(days=1)})
        self.assertEqual(f(valid,"asus-install",self.link()),"SERVICE")
        self.assertEqual(valid.calls,1)
    def test_service_rebind_denied(self):
        link=self.link();link["rebind_pending"]=True
        with self.assertRaises(HttpError):
            load_target("SERVICE")(DB({"enabled":True,"valid_until":NOW+timedelta(days=1)}),"asus",link)
    def test_client_standard_pro_unchanged(self):
        f=load_target("CLIENT")
        self.assertEqual(f(DB(None),"asus",self.link()),"STANDARD")
        pro=self.link();pro["plan_code"]="multi_guard_pro"
        self.assertEqual(f(DB(None),"asus",pro),"PRO")
        expired=self.link();expired["valid_until"]=NOW-timedelta(days=1)
        with self.assertRaises(HttpError):f(DB(None),"asus",expired)
    def test_unauthorized_owner_mode_rejected(self):
        with self.assertRaises(HttpError):
            load_target("UNKNOWN")(DB(None),"asus",self.link())
    def test_service_receipt_never_means_running(self):
        content=SRC.read_text(encoding="utf-8")
        self.assertIn('"SERVICE":"ServiceDormant"',content)
        self.assertNotIn('"SERVICE":"ServiceRunning"',content)
        self.assertIn("AND expires_at>now() FOR UPDATE",content)

if __name__=="__main__":unittest.main()
