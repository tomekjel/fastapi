"""Exercise the real KeyGate compensation except-handler without external calls."""
import ast
from pathlib import Path
import unittest

s=Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
p=next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef) and n.name=="provision")
tx=next(n for n in ast.walk(p) if isinstance(n,ast.With) and 'SELECT * FROM guard.license_links' in (ast.get_source_segment(s,n) or ''))
recovery=next(n for n in tx.body if isinstance(n,ast.Try) and n.handlers)
handler=recovery.handlers[0]
assert handler.name=="provision_error"
assert "_keygate_deactivate" in ast.get_source_segment(s,handler)
args=ast.arguments(posonlyargs=[],args=[ast.arg(arg="confirmed"),ast.arg(arg="deactivate")],vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[])
# Execute original except handler under an artificial SQL exception,
# binding only KeyGate deactivation to a captured callable.
throw=ast.Raise(exc=ast.Call(func=ast.Name(id="ValueError",ctx=ast.Load()),args=[ast.Constant("sql-failure")],keywords=[]))
test=ast.Try(body=[throw],handlers=[handler],orelse=[],finalbody=[])
f=ast.FunctionDef(name="simulate",args=args,body=[
    ast.Assign(targets=[ast.Name(id="activation_confirmed",ctx=ast.Store())],value=ast.Name(id="confirmed",ctx=ast.Load())),
    ast.Assign(targets=[ast.Name(id="_keygate_deactivate",ctx=ast.Store())],value=ast.Name(id="deactivate",ctx=ast.Load())),
    ast.Assign(targets=[ast.Name(id="license_key",ctx=ast.Store())],value=ast.Constant("TEST-KEY")),
    ast.Assign(targets=[ast.Name(id="req",ctx=ast.Store())],value=ast.Call(func=ast.Name(id="Request",ctx=ast.Load()),args=[],keywords=[])),
    test],decorator_list=[],returns=None,type_comment=None)
code=compile(ast.fix_missing_locations(ast.Module(body=[f],type_ignores=[])),"<original-compensation-handler>","exec")
class Request:device_id="computer-X"
class HTTPException(Exception):
    def __init__(self,code,message):self.status_code=code;super().__init__(message)
ns={"Request":Request,"HTTPException":HTTPException}
exec(code,ns)
class Cases(unittest.TestCase):
    def test_compensates_confirmed_activation_then_rethrows_sql_failure(self):
        calls=[]
        def deactivate(key,device):calls.append((key,device))
        with self.assertRaisesRegex(ValueError,"sql-failure"):
            ns["simulate"](True,deactivate)
        self.assertEqual(calls,[("TEST-KEY","computer-X")])
    def test_does_not_deactivate_unconfirmed_activation(self):
        calls=[]
        with self.assertRaises(ValueError):
            ns["simulate"](False,lambda *args:calls.append(args))
        self.assertEqual(calls,[])
    def test_compensation_failure_requires_owner_reconciliation(self):
        def fail(*args):raise RuntimeError("keygate-offline")
        with self.assertRaises(HTTPException) as caught:
            ns["simulate"](True,fail)
        self.assertEqual(caught.exception.status_code,503)
        self.assertIn("RECOVERY_RECONCILIATION_REQUIRED",str(caught.exception))
if __name__=="__main__":unittest.main()
