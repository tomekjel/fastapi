"""Pre-release cross-layer contract: only one mode, paid key preserved.

Read-only AST + pure policy tests: never invokes KeyGate, Mesh or production DB.
"""
from __future__ import annotations
import ast
import importlib.util
from datetime import datetime,timezone
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/"app/routers/multiguard_license.py").read_text()
tree=ast.parse(source)
functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
spec=importlib.util.spec_from_file_location(
    "mg_modes_contract",ROOT/"app/routers/multiguard_entitlement_modes.py"
)
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
now=datetime(2026,10,31,7,0,tzinfo=timezone.utc)
paid_end=datetime(2027,1,29,0,0,tzinfo=timezone.utc)

def body(name):
    return ast.get_source_segment(source,functions[name])

class ServiceTransitionContract(unittest.TestCase):
    def test_pro_service_perpetual_preserves_independent_paid_term(self):
        d=policy.plan_grid_license_change(
            current_mode="CLIENT",current_edition="PRO",
            target_edition="SERVICE",term_choice="PERPETUAL",term_date="",
            now=now,paid_valid_until=paid_end,paid_edition="PRO",
        )
        self.assertEqual((d["action"],d["mode"]),("ENTER_SERVICE","SERVICE"))
        self.assertIsNone(d["valid_until"])
        self.assertEqual(policy.resolve_mode("SERVICE",has_customer_link=True,
                                            has_service_grant=True),"SERVICE")
        self.assertEqual(policy.resolve_mode("CLIENT",has_customer_link=True,
                                            has_service_grant=True),"CLIENT")

    def test_service_return_restores_original_paid_edition_only(self):
        for target in ("PRO","STANDARD"):
            if target=="PRO":
                d=policy.plan_grid_license_change(
                    current_mode="SERVICE",current_edition="SERVICE",
                    target_edition=target,term_choice="KEEP",term_date="",
                    now=now,paid_valid_until=paid_end,paid_edition="PRO",
                )
                self.assertEqual(d["action"],"RESTORE_PAID")
                self.assertEqual(d["valid_until"],paid_end)
            else:
                with self.assertRaises(ValueError):
                    policy.plan_grid_license_change(
                        current_mode="SERVICE",current_edition="SERVICE",
                        target_edition=target,term_choice="KEEP",term_date="",
                        now=now,paid_valid_until=paid_end,paid_edition="PRO",
                    )

    def test_no_remote_without_selected_rights(self):
        mode=body("_owner_select_effective_mode")
        for x in (
            "guard.remote_sessions","guard.workshop_remote_sessions",
            "OR rs.mesh_public_id IS NOT NULL",
            "workshop_remote.invalidate_standing_authorization(",
            "FROM guard.pending_installations",
            "FOR UPDATE",
            "owner_entitlement_selections",
            "guard.owner_license_mode_transitions",
        ):
            self.assertIn(x,mode)
        self.assertNotIn("_keygate_revoke(",mode)
        self.assertNotIn("_keygate_create_license(",mode)
        self.assertNotIn("_keygate_activate(",mode)

    def test_service_cache_revoked_when_owner_returns_to_client(self):
        code=body("_client_mode_revocation_lease")
        self.assertIn('disabled["enabled"] = False',code)
        self.assertIn("_signed_workshop_grant(",code)
        self.assertIn('"profile": "OFF"',code)
        self.assertNotIn("_keygate_revoke(",code)

    def test_paid_without_valid_expiry_never_becomes_perpetual(self):
        self.assertFalse(policy.paid_pro_authorized(
            "CLIENT",edition="PRO",lifecycle="ACTIVE",
            valid_until=None,now=now,
        ))

if __name__=="__main__":
    unittest.main()
