"""Unattended service sessions require separate recorded OWNER + local consent.

Static AST and pure-function tests. No database, MeshCentral or licence writes.
"""
import ast
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "app" / "routers"
WORKSHOP = (ROOT / "multiguard_workshop_remote.py").read_text()
OWNER = (ROOT / "multiguard_license.py").read_text()
WORKSHOP_TREE = ast.parse(WORKSHOP)
OWNER_TREE = ast.parse(OWNER)

def source_for(tree, code, name):
    found = [x for x in tree.body
             if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))
             and x.name == name]
    if len(found) != 1:
        raise AssertionError(f"Expected exactly one {name}")
    return ast.get_source_segment(code, found[0])

class StandingAuthorizationGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fn = next(x for x in WORKSHOP_TREE.body
                  if isinstance(x, ast.FunctionDef)
                  and x.name == "standing_authorization_record_valid")
        ns = {"re": re, "_eligible": lambda g: bool(g and g.get("eligible"))}
        exec(compile(ast.Module(body=[fn], type_ignores=[]),
                     "<pure-consent-validation>", "exec"), ns)
        cls.check = staticmethod(ns["standing_authorization_record_valid"])

    def records(self):
        grant = {"eligible": True, "mesh_node_id": "node/example/" + "a" * 64}
        record = {
            "approved_mesh_node_id": grant["mesh_node_id"],
            "device_scope": "CLIENT_DIAGNOSTIC",
            "owner_approved_at": "recorded",
            "local_opt_in_attested_at": "recorded",
            "prior_consent_sha256": "0" * 64,
            "revoked_at": None,
        }
        return grant, record

    def test_both_approvals_required_for_same_bound_mesh_node(self):
        grant, record = self.records()
        self.assertTrue(self.check(grant, record))
        for key in ("owner_approved_at", "local_opt_in_attested_at",
                    "approved_mesh_node_id", "prior_consent_sha256",
                    "device_scope"):
            with self.subTest(key=key):
                altered = dict(record)
                altered[key] = None if key != "approved_mesh_node_id" else "node/foreign"
                self.assertFalse(self.check(grant, altered))

    def test_revoked_or_unlicensed_or_unbound_denied(self):
        grant, record = self.records()
        self.assertFalse(self.check({**grant, "eligible": False}, record))
        self.assertFalse(self.check({**grant, "mesh_node_id": ""}, record))
        self.assertFalse(self.check(grant, {**record, "revoked_at": "revoked"}))
        self.assertFalse(self.check(grant, {**record, "prior_consent_sha256": "bad"}))
        self.assertFalse(self.check(grant, None))

    def test_session_creation_requires_prior_consent_and_rechecks_under_lock(self):
        body = source_for(WORKSHOP_TREE, WORKSHOP, "request_for_owner")
        self.assertEqual(body.count("standing_authorization_record_valid("), 2)
        self.assertEqual(body.count("standing_authorization_record(db, iid)"), 2)
        self.assertLess(
            body.index("standing_authorization_record_valid("),
            body.index("meshcentral.verify_service_pro_node("),
        )
        self.assertLess(
            body.rindex("standing_authorization_record_valid("),
            body.index("INSERT INTO guard.workshop_remote_sessions"),
        )
        self.assertIn("SELECT installation_id FROM guard.workshop_grants", body)

    def test_share_creation_checks_exact_scope_and_consent_twice(self):
        body = source_for(WORKSHOP_TREE, WORKSHOP, "connect_for_owner")
        self.assertEqual(body.count("standing_authorization_record_valid("), 2)
        self.assertIn('scope = standing["device_scope"]', body)
        self.assertNotIn('scope = "CLIENT_DIAGNOSTIC"', body)
        self.assertIn('renewed["device_scope"] != scope', body)
        self.assertLess(body.index("standing_authorization_record_valid("),
                        body.index("meshcentral.create_standing_service_share("))
        self.assertIn("meshcentral.revoke_share(node,share.public_id)", body)
        self.assertIn("scope is not None", body)

    def test_owner_mode_change_invalidates_previous_consent_same_transaction(self):
        body = source_for(OWNER_TREE, OWNER, "_owner_select_effective_mode")
        self.assertIn('workshop_remote._schema()', body)
        self.assertIn('workshop_remote.invalidate_standing_authorization(', body)
        self.assertIn('"SERVICE_RIGHTS_CHANGED"', body)
        self.assertLess(
            body.index('workshop_remote.invalidate_standing_authorization('),
            body.index('INSERT INTO guard.owner_entitlement_selections'),
        )
        self.assertIn('with engine.begin() as con:', body)

if __name__ == "__main__":
    unittest.main()
