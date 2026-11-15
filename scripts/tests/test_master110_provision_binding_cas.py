"""MASTER110 compare-and-swap provision binding regression tests.

Runs the real SQL UPDATE portion of the backend provision handler against a
fake database cursor; no KeyGate, production DB, or MeshCentral requests.
"""
import ast
from pathlib import Path
import types
import unittest
import uuid

SOURCE = Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
AST = ast.parse(SOURCE)
PROVISION = next(n for n in AST.body if isinstance(n, ast.FunctionDef) and n.name=="provision")
TX = next(n for n in PROVISION.body if isinstance(n, ast.With) and
          any(isinstance(item.context_expr, ast.Call) and
              isinstance(item.context_expr.func, ast.Attribute) and
              item.context_expr.func.attr=="begin" for item in n.items))
UPDATE = next(
    n for n in ast.walk(TX) if isinstance(n, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == "row" for t in n.targets)
)
assert isinstance(UPDATE, ast.Assign)
# Execute exactly the real code assigning row from the SQL update.
FN = ast.FunctionDef(name="bind_once",args=ast.arguments(posonlyargs=[],args=[
    ast.arg(arg="connection"),ast.arg(arg="installation_id"),ast.arg(arg="req"),
    ast.arg(arg="credential_hash"),ast.arg(arg="lifecycle"),ast.arg(arg="link")
],vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),
    body=[UPDATE,ast.If(test=ast.Compare(left=ast.Name(id="row",ctx=ast.Load()),
          ops=[ast.Is()],comparators=[ast.Constant(None)]),
          body=[ast.Raise(exc=ast.Call(func=ast.Name(id="HTTPException",ctx=ast.Load()),
              args=[ast.Constant(409),ast.Constant("Binding changed")],keywords=[]),cause=None)],
          orelse=[]),
          ast.Return(value=ast.Name(id="row",ctx=ast.Load()))],
    decorator_list=[],returns=None,type_comment=None)
CODE=compile(ast.fix_missing_locations(ast.Module(body=[FN],type_ignores=[])),"<real-licence-cas>","exec")

class HTTPException(Exception):
    def __init__(self,code,message): super().__init__(message);self.code=code

class FakeCursor:
    def __init__(self,row):self.row=row
    def mappings(self):return self
    def first(self):return self.row

class FakeConnection:
    def __init__(self):self.stored_installation=None;self.stored_rebind=True
    def execute(self,sql,params):
        sql=str(sql)
        assert "installation_id IS NULL OR installation_id=:installation_id" in sql
        assert "rebind_pending=:expected_rebind_pending" in sql
        assert "lifecycle NOT IN ('EXPIRED','REVOKED')" in sql
        if (self.stored_installation is not None and
                self.stored_installation!=params["installation_id"]):
            return FakeCursor(None)
        if self.stored_rebind != params["expected_rebind_pending"]:
            return FakeCursor(None)
        self.stored_installation=params["installation_id"]
        self.stored_rebind=False
        return FakeCursor({"installation_id":self.stored_installation})

class Tests(unittest.TestCase):
    def setUp(self):
        env={"text":lambda sql:sql,"HTTPException":HTTPException}
        exec(CODE,env)
        self.run=env["bind_once"]
        self.connection=FakeConnection()
        self.link={"id":uuid.uuid4(),"rebind_pending":True}
        self.req=types.SimpleNamespace(device_id="device-a",app_version="test")
    def bind(self,iid):
        return self.run(self.connection,iid,self.req,"sha","ACTIVE",self.link)
    def test_first_wins(self):
        iid=uuid.uuid4()
        self.assertEqual(self.bind(iid)["installation_id"],iid)
        self.assertFalse(self.connection.stored_rebind)
    def test_second_separate_installation_cannot_replace_winner(self):
        first,second=uuid.uuid4(),uuid.uuid4()
        self.bind(first)
        with self.assertRaises(HTTPException) as ctx:self.bind(second)
        self.assertEqual(ctx.exception.code,409)
        self.assertEqual(self.connection.stored_installation,first)
    def test_replay_with_stale_rebind_state_rejected(self):
        iid=uuid.uuid4()
        self.bind(iid)
        with self.assertRaises(HTTPException):self.bind(iid)
        self.assertEqual(self.connection.stored_installation,iid)

if __name__=="__main__": unittest.main()
