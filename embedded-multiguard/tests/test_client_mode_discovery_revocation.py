"""OWNER CLIENT discovery must never resurrect retained SERVICE grants.

Pure regression and AST tests: no API, KeyGate, MeshCentral or SQL mutations.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/
        "app/routers/multiguard_license.py").read_text()
TREE=ast.parse(SOURCE)

def function(name):
    matches=[n for n in TREE.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
             and n.name==name]
    if len(matches)!=1:
        raise AssertionError("Expected exactly one "+name)
    return matches[0]

def body(name):
    return ast.get_source_segment(SOURCE,function(name))

class Rejected(Exception):
    def __init__(self,code,detail):
        self.status_code=code
        self.detail=detail
        super().__init__(detail)

class ClientModeDiscoveryTests(unittest.TestCase):
    def make_pure(self, grant):
        captured=[]
        def signed(pending, state):
            captured.append((pending, dict(state)))
            return {"payload":{"lifecycle":"WORKSHOP" if state["enabled"] else "UNKNOWN",
                               "installationId":str(pending["installation_id"])},
                    "signatureB64":"SIGNATURE-STUB-NO-CRYPTO"}
        ns={
            "Any":Any,
            "HTTPException":Rejected,
            "_workshop_grant":lambda _iid: grant,
            "_signed_workshop_grant":signed,
        }
        module=ast.Module(body=[function("_client_mode_revocation_lease")],type_ignores=[])
        exec(compile(module,"<pure-client-lease>","exec"),ns)
        return ns["_client_mode_revocation_lease"],captured

    def test_old_enabled_service_grant_returns_only_signed_unknown(self):
        prior={"installation_id":"device-1","edition":"PRO",
               "enabled":True,"valid_until":None,
               "monitoring_profile":"INTENSIVE"}
        current=dict(prior)
        run,cap=self.make_pure(current)
        result=run({"installation_id":"device-1"},"CLIENT")
        self.assertEqual(result["workshopLease"]["payload"]["lifecycle"],"UNKNOWN")
        self.assertEqual(result["workshopMonitoring"],{"enabled":False,"profile":"OFF"})
        self.assertEqual(len(cap),1)
        self.assertFalse(cap[0][1]["enabled"])
        self.assertEqual(current,prior,"Original paid/service grants must remain unchanged")

    def test_clean_unlicensed_waiting_remains_allowed(self):
        run,cap=self.make_pure(None)
        for mode in ("NONE","CLIENT"):
            self.assertEqual(run({"installation_id":"clean-1"},mode),{})
        self.assertFalse(cap)

    def test_service_and_unknown_cannot_be_signed_as_client_revocation(self):
        run,_=self.make_pure({"enabled":True})
        for mode in ("SERVICE","NONE","UNRECOGNIZED"):
            with self.subTest(mode=mode),self.assertRaises(Rejected):
                run({"installation_id":"other"},mode)

    def test_selected_service_has_only_active_workshop_response(self):
        text=body("discovery_assignment")
        start=text.index('if selected_mode == "SERVICE":')
        fallback=text.index('if not reception_id or pending["status"] == "WAITING":')
        selected=text[start:fallback]
        self.assertIn('workshopLease": _signed_workshop_grant(pending, grant)',selected)
        self.assertIn('status": "WORKSHOP"',selected)
        tail=text[fallback:]
        self.assertIn('**_client_mode_revocation_lease(pending, selected_mode)',tail)
        self.assertNotIn('"WORKSHOP" if grant["enabled"]',tail)
        self.assertIn('"status": "WAITING"',tail)

    def test_direct_expired_assignment_also_clears_old_workshop(self):
        text=body("discovery_assignment")
        direct=text[text.index("if (not reception_id and pending"):text.index('if not reception_id or pending["status"]')]
        self.assertIn('if (link["lifecycle"] in {"REVOKED", "EXPIRED"}',direct)
        self.assertIn('**_client_mode_revocation_lease(pending, selected_mode)',direct)

    def test_signed_unknown_comes_from_normal_signing_key(self):
        text=body("_signed_workshop_grant")
        self.assertIn('"lifecycle": "WORKSHOP" if (',text)
        self.assertIn(') else "UNKNOWN"',text)
        self.assertIn('_signing_key().sign(payload.encode("utf-8"))',text)
        self.assertIn('"installationId": str(pending["installation_id"])',text)
        self.assertIn('"deviceId": str(pending["device_id"])',text)

if __name__=="__main__":
    unittest.main()
