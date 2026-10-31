"""Fail-closed regression contract for OWNER-paid terms and Service selection."""
from __future__ import annotations
import ast
import importlib.util
from datetime import datetime,timezone
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
OWNER=(ROOT/"scripts/compact_v44_owner_term.py").read_text()
POLICY=ROOT/"app/routers/multiguard_entitlement_modes.py"
spec=importlib.util.spec_from_file_location("mg_v44_entitlements", POLICY)
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
now=datetime(2026,10,31,7,0,tzinfo=timezone.utc)
expiry=datetime(2027,1,29,0,0,tzinfo=timezone.utc)

class OwnerV44TermContract(unittest.TestCase):
    def plan(self,edition="PRO",choice="KEEP",day=""):
        return policy.plan_grid_license_change(
            current_mode="CLIENT",current_edition="PRO",
            target_edition=edition,term_choice=choice,term_date=day,
            now=now,paid_valid_until=expiry,paid_edition="PRO",
            explicit_paid_perpetual_supported=False,
        )

    def test_paid_calendar_can_shorten_with_one_owner_save(self):
        x=self.plan(choice="CALENDAR",day="2026-12-10")
        self.assertEqual(x["action"],"PAID_CALENDAR")
        self.assertLess(x["valid_until"],expiry)

    def test_paid_calendar_can_extend_by_few_days(self):
        x=self.plan(choice="CALENDAR",day="2027-02-04")
        self.assertEqual(x["action"],"PAID_CALENDAR")
        self.assertGreater(x["valid_until"],expiry)

    def test_paid_presets_append_to_remaining_validity(self):
        for months in (3,6,12):
            with self.subTest(months=months):
                x=self.plan(choice=str(months))
                self.assertEqual(x["action"],"PAID_EXTEND")
                self.assertGreater(x["valid_until"],expiry)

    def test_pro_standard_perpetual_rejected(self):
        with self.assertRaises(ValueError):
            self.plan(choice="PERPETUAL")
        with self.assertRaises(ValueError):
            self.plan(edition="STANDARD",choice="PERPETUAL")

    def test_service_perpetual_is_independent_and_only_service(self):
        x=self.plan(edition="SERVICE",choice="PERPETUAL")
        self.assertEqual(x["action"],"ENTER_SERVICE")
        self.assertIsNone(x["valid_until"])
        self.assertEqual(x["mode"],"SERVICE")

    def test_paid_edition_and_term_do_not_change_together(self):
        with self.assertRaises(ValueError):
            self.plan(edition="STANDARD",choice="12")

    def test_backend_write_preserves_original_keygate_identity(self):
        src=OWNER
        tree=ast.parse(src)
        self.assertEqual(len(tree.body),1)
        for item in ("_keygate_set_valid_until", "owner_license_term_changes",
                     "expected_end", "FOR UPDATE", "if previous:"):
            self.assertIn(item,src)
        self.assertNotIn("_keygate_revoke",src)
        self.assertNotIn("_keygate_create",src)
        self.assertNotIn("payment_confirmed",src)

if __name__=="__main__":
    unittest.main()
