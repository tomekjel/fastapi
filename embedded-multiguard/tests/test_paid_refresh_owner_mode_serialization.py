"""No database/KeyGate: detect stale paid refresh and activation race with OWNER.

Prove that the real FastAPI handlers lock the pending installation and
recheck selected OWNER mode inside the SAME SQL transaction before writing
the licence or making a KeyGate activation request.
"""
from __future__ import annotations
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"app/routers/multiguard_license.py").read_text()
TREE=ast.parse(SOURCE)

def source_for(name):
    node=next(n for n in TREE.body if isinstance(n,ast.FunctionDef)
              and n.name==name)
    return ast.get_source_segment(SOURCE,node)

class OwnerModeSerializationTests(unittest.TestCase):
    def test_paid_refresh_rechecks_under_pending_lock_before_paid_update(self):
        body=source_for("refresh")
        tx=body.index("with engine.begin() as connection:")
        transaction=body[tx:]
        self.assertIn("FROM guard.pending_installations",transaction)
        self.assertIn("WHERE installation_id=:iid FOR UPDATE",transaction)
        self.assertIn('_owner_effective_entitlement_mode(connection, link["installation_id"]) != "CLIENT"',transaction)
        self.assertIn('_owner_pending_plan_change(connection, link["id"])',transaction)
        self.assertLess(transaction.index("FOR UPDATE"),
                        transaction.index('_owner_effective_entitlement_mode('))
        self.assertLess(transaction.index('_owner_effective_entitlement_mode('),
                        transaction.index("UPDATE guard.license_links"))
        self.assertLess(transaction.index('_owner_pending_plan_change('),
                        transaction.index("UPDATE guard.license_links"))
        self.assertIn("signedLicense",body)
        self.assertNotIn("_keygate_create_license(",body)

    def test_acceptance_checks_owner_before_keygate_mutation(self):
        body=source_for("acceptance")
        transaction=body[body.index("with engine.begin() as connection:"):]
        self.assertIn("FROM guard.pending_installations",transaction)
        self.assertIn("WHERE installation_id=:iid FOR UPDATE",transaction)
        self.assertIn('_owner_effective_entitlement_mode(connection, link["installation_id"]) != "CLIENT"',transaction)
        self.assertIn('_owner_pending_plan_change(connection, link["id"])',transaction)
        self.assertLess(transaction.index("pending_installations"),
                        transaction.index("SELECT * FROM guard.license_links"))
        self.assertLess(transaction.index('_owner_effective_entitlement_mode('),
                        transaction.index("_keygate_set_valid_until("))
        self.assertLess(transaction.index('_owner_pending_plan_change('),
                        transaction.index("_keygate_set_valid_until("))
        self.assertIn('current["lifecycle"] != "PENDING_ACCEPTANCE"', transaction)

    def test_owner_switch_locks_same_rows_in_same_order(self):
        body=source_for("_owner_select_effective_mode")
        self.assertIn('FROM guard.pending_installations',body)
        self.assertIn('FROM guard.license_links WHERE id=:id FOR UPDATE',body)
        self.assertLess(body.index('FROM guard.pending_installations'),
                        body.index('FROM guard.license_links WHERE id=:id FOR UPDATE'))
        self.assertIn("guard.owner_entitlement_selections",body)
        self.assertIn('workshop_remote.invalidate_standing_authorization(',body)

    def test_workshop_signed_lease_bound_to_device_and_expiry(self):
        body=source_for("_signed_workshop_grant")
        for marker in (
            '"installationId": str(pending["installation_id"])',
            '"deviceId": str(pending["device_id"])',
            '"validUntil": _iso(grant.get("valid_until"))',
            '"lifecycle": "WORKSHOP" if (',
            '_signing_key().sign(payload.encode("utf-8"))',
        ):
            self.assertIn(marker,body)

if __name__=="__main__":
    unittest.main()
