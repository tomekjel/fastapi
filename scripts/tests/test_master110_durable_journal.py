"""MASTER110: execute the actual write-ahead journal functions against a fake DB."""
import ast
import copy
import contextlib
from pathlib import Path
import unittest
import uuid

src=Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
tree=ast.parse(src)
names={"_begin_keygate_provision_attempt","_finish_keygate_provision_attempt"}
actual=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
assert len(actual)==2
future=ast.ImportFrom(module="__future__",names=[ast.alias(name="annotations")],level=0)
code=compile(ast.fix_missing_locations(ast.Module(body=[future,*actual],type_ignores=[])),"<actual-durable-activation-journal>","exec")

class HTTPException(Exception):
    def __init__(self,status_code,detail):self.status_code=status_code;super().__init__(detail)
class Result:
    def __init__(self,data=None):self.data=data
    def first(self):return self.data
class Connection:
    def __init__(self,data):self.data=data
    def execute(self,sql,params):
        sql=str(sql)
        if "SELECT id FROM guard.keygate_provision_attempts" in sql:
            return Result(next(({"id":k} for k,v in self.data.items()
                if v["license"]==params["license_id"] and
                v["state"] in ("INTENT","NEEDS_REVIEW")),None))
        if "INSERT INTO guard.keygate_provision_attempts" in sql:
            if any(v["license"]==params["license_id"] and
                   v["state"] in ("INTENT","NEEDS_REVIEW") for v in self.data.values()):
                raise HTTPException(409,"conflicting unresolved keygate call")
            self.data[params["id"]]={"license":params["license_id"],
                "installation":params["installation_id"],
                "device":params["device_id"],"state":"INTENT"}
            return Result()
        if "UPDATE guard.keygate_provision_attempts" in sql:
            row=self.data.get(params["id"])
            if row and row["state"]=="INTENT":row["state"]=params["state"]
            return Result()
        raise AssertionError(sql)
class Engine:
    def __init__(self,data):self.data=data
    @contextlib.contextmanager
    def begin(self):
        previous=copy.deepcopy(self.data)
        try:yield Connection(self.data)
        except Exception:
            self.data.clear();self.data.update(previous)
            raise
class Tests(unittest.TestCase):
    def setUp(self):
        self.data={}
        env={"uuid":uuid,"HTTPException":HTTPException,"_ensure_schema":lambda:None,
             "engine":Engine(self.data),"text":lambda value:value}
        exec(code,env)
        self.begin=env["_begin_keygate_provision_attempt"]
        self.finish=env["_finish_keygate_provision_attempt"]
        self.link={"keygate_license_id":"licensed-existing-id"}
        self.install=uuid.uuid4()
    def test_intent_commits_before_external_activation(self):
        op=self.begin(self.link,self.install,"device-a")
        self.assertEqual(self.data[op]["state"],"INTENT")
        self.assertNotIn("license_key",self.data[op])
    def test_conflict_refuses_other_attempt_while_intent_unresolved(self):
        self.begin(self.link,self.install,"device-a")
        with self.assertRaises(HTTPException) as e:
            self.begin(self.link,uuid.uuid4(),"device-b")
        self.assertEqual(e.exception.status_code,409)
        self.assertEqual(len(self.data),1)
    def test_committed_frees_slot(self):
        op=self.begin(self.link,self.install,"device-a")
        self.finish(op,True)
        self.assertEqual(self.data[op]["state"],"COMMITTED")
        other=self.begin(self.link,uuid.uuid4(),"device-b")
        self.assertNotEqual(other,op)
    def test_unknown_outcome_blocks_automatic_retry(self):
        op=self.begin(self.link,self.install,"device-a")
        self.finish(op,False)
        self.assertEqual(self.data[op]["state"],"NEEDS_REVIEW")
        with self.assertRaises(HTTPException):
            self.begin(self.link,uuid.uuid4(),"device-b")
    def test_not_automatically_released_by_repeated_update(self):
        op=self.begin(self.link,self.install,"device-a")
        self.finish(op,False)
        self.finish(op,True)
        self.assertEqual(self.data[op]["state"],"NEEDS_REVIEW")

if __name__=="__main__":unittest.main()
