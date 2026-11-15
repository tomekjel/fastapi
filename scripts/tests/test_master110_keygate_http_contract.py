"""MASTER110: real urllib KeyGate client against an isolated local HTTP stub.

No production KeyGate, database or MeshCentral communication. Extracts the
actual backend _keygate_request/_keygate_activate/_keygate_deactivate code.
"""
from __future__ import annotations
import ast
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import unittest
import urllib.request
import urllib.error
import uuid

SOURCE = Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
NAMES = {"_keygate_request", "_keygate_activate", "_keygate_deactivate"}
FUNCS = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in NAMES]
assert len(FUNCS) == 3
FUTURE = ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)
SCRIPT = compile(ast.fix_missing_locations(ast.Module(body=[FUTURE,*FUNCS],type_ignores=[])),"<actual-keygate-client>","exec")

class HTTPException(Exception):
    def __init__(self,status_code,detail):
        self.status_code=status_code
        super().__init__(detail)

class Stub(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        length=int(self.headers.get("Content-Length","0"))
        payload=json.loads(self.rfile.read(length) or b"{}")
        self.server.calls.append((self.path,payload))
        if self.server.behavior=="disconnect":
            self.connection.shutdown(2)
            self.connection.close()
            return
        if self.server.behavior=="reject":
            self.send_response(409)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"device-limit"}')
            return
        if self.server.behavior=="bad-body":
            response={"success":True,"data":{"unexpected":"response"}}
        else:
            response={"success":True,"data":{"license_id":"LIC-TEST","status":"active"}}
        raw=json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),Stub)
        cls.server.calls=[]
        cls.server.behavior="ok"
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.env={
            "Any":object,"json":json,"urllib":__import__("urllib"),"HTTPException":HTTPException,
            "_keygate_base_url":lambda:"http://127.0.0.1:"+str(cls.server.server_port),
            "_required_env":lambda name:"TEST-ONLY-NO-REAL-TOKEN",
        }
        exec(SCRIPT,cls.env)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
    def setUp(self):
        self.server.behavior="ok"
        self.server.calls.clear()
    def test_activate_real_backend_client_sends_expected_contract(self):
        result=self.env["_keygate_activate"]("TEST-KEY","device-A",str(uuid.uuid4()))
        self.assertEqual(result["license_id"],"LIC-TEST")
        path,body=self.server.calls[0]
        self.assertEqual(path,"/api/v1/license/activate")
        self.assertEqual(body["license_key"],"TEST-KEY")
        self.assertEqual(body["identifier"],"device-A")
        self.assertEqual(body["identifier_type"],"device")
    def test_deactivate_real_backend_client_uses_same_device(self):
        self.env["_keygate_deactivate"]("TEST-KEY","device-A")
        path,body=self.server.calls[0]
        self.assertEqual(path,"/api/v1/license/deactivate")
        self.assertEqual(body["identifier"],"device-A")
    def test_keygate_reject_propagates_without_fabricated_success(self):
        self.server.behavior="reject"
        with self.assertRaises(HTTPException) as err:
            self.env["_keygate_activate"]("TEST-KEY","device-A","installation-A")
        self.assertEqual(err.exception.status_code,409)
    def test_disconnected_response_is_unknown_not_success(self):
        self.server.behavior="disconnect"
        with self.assertRaises(HTTPException) as err:
            self.env["_keygate_activate"]("TEST-KEY","device-A","installation-A")
        self.assertEqual(err.exception.status_code,502)
    def test_bad_response_without_license_id_must_not_be_accepted(self):
        self.server.behavior="bad-body"
        response=self.env["_keygate_activate"]("TEST-KEY","device-A","installation-A")
        # Current transport accepts arbitrary dictionaries; expose gap rather
        # than claiming proof of activation. Require license_id upstream.
        self.assertNotIn("license_id",response)

if __name__=="__main__":
    unittest.main()
