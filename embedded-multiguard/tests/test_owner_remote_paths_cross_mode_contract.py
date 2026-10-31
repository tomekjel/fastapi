"""Fail-closed remote paths for selected OWNER licence edition.

Tests only real source / pure helpers; no MeshCentral, DB or key creation.
"""
from __future__ import annotations
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
PAID=(ROOT/"app/routers/multiguard_remote.py").read_text()
SERVICE=(ROOT/"app/routers/multiguard_workshop_remote.py").read_text()
OWNER=(ROOT/"app/routers/multiguard_license.py").read_text()

def function(source,name):
    tree=ast.parse(source)
    matches=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
    if len(matches)!=1:
        raise AssertionError("Missing or duplicate "+name)
    return ast.get_source_segment(source,matches[0])

class OwnerRemoteCrossModeContract(unittest.TestCase):
    def test_customer_remote_requires_actual_selected_client_mode(self):
        code=function(PAID,"_has_verified_remote_pro")
        self.assertIn("_owner_effective_entitlement_mode(",code)
        self.assertIn('!= "CLIENT"',code)
        self.assertIn('paid["plan_code"] == "multi_guard_pro"',code)
        self.assertIn('paid["valid_until"] > now',code)

    def test_customer_remote_never_uses_service_approval(self):
        code=function(PAID,"_has_verified_service_remote_pro")
        self.assertIn("return False",code)
        self.assertNotIn("meshcentral.",code)
        code=function(PAID,"remote_session_connect")
        self.assertIn("_has_verified_remote_pro(",code)
        self.assertIn("Zgoda klienta",code)

    def test_workshop_remote_requires_selected_service(self):
        code=function(SERVICE,"remote_entitlement_mode")
        self.assertIn('grant.get("owner_mode") != "SERVICE"',code)
        self.assertIn('return "CUSTOMER_LICENSE"',code)
        self.assertIn('return "SERVICE_PRO"',code)
        code=function(SERVICE,"_authenticate")
        self.assertIn('remote_entitlement_mode(selection) != "SERVICE_PRO"',code)

    def test_workshop_standing_consent_requires_both_approvals(self):
        code=function(SERVICE,"standing_authorization_record_valid")
        for guard in ("owner_approved_at","local_opt_in_attested_at",
                      "approved_mesh_node_id","revoked_at","prior_consent_sha256"):
            self.assertIn(guard,code)
        code=function(SERVICE,"connect_for_owner")
        self.assertIn("standing_authorization_record_valid(",code)
        self.assertIn("verify_service_pro_node(",code)
        self.assertIn("session_node_ready(",code)

    def test_owner_switch_blocks_live_mesh_and_revokes_standing_permission(self):
        code=function(OWNER,"_owner_select_effective_mode")
        for marker in ("guard.remote_sessions","guard.workshop_remote_sessions",
                       "mesh_public_id IS NOT NULL",
                       "invalidate_standing_authorization(",
                       "owner_entitlement_selections"):
            self.assertIn(marker,code)
        for forbidden in ("_keygate_revoke(", "_keygate_create_license("):
            self.assertNotIn(forbidden,code)

    def test_mesh_group_never_aliases_service_and_customer(self):
        code=function(SERVICE,"expected_remote_mesh_group")
        self.assertIn("MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID",code)
        self.assertIn("MESH_CENTRAL_CUSTOMER_MESH_ID",code)
        self.assertIn("MESH_CENTRAL_SINGLE_PROMPT_MESH_ID",code)
        self.assertIn("if group in customer_groups:",code)

if __name__=="__main__":
    unittest.main()
