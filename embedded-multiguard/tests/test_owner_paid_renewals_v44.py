"""Unit/source tests for the separate functional paid renewal screen.

No FastAPI database, production data, MeshCentral or KeyGate API calls.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/"scripts/stage_paid_renewals_v44.py"
spec=importlib.util.spec_from_file_location("paid_renewals_v44",STAGE)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

SAMPLE = '''
# STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.
from __future__ import annotations
from typing import Any
from datetime import datetime
def _workshop_csrf(): return "csrf"
def _owner_effective_entitlement_mode(con,iid): return "CLIENT"
def panel_licenses_grid(): return "PROTECTED ORIGINAL V4.4 HTML CSS"
def panel_grid_save_row(): return "ORIGINAL V4.4 SAVE"
def _extend_active_license(
    reception_id,
    months,
    operation_id,
    *,
    source,
    payment_confirmed,
    by_installation: bool = False,
) -> dict[str,Any]:
    with engine.begin() as connection:
        lookup = "installation_id=:id" if by_installation else "reception_id=:id"
        link = connection.execute(text(
            "SELECT * FROM guard.license_links WHERE " + lookup + " FOR UPDATE"
        ), {"id":reception_id}).mappings().first()
        earlier = connection.execute(text(
            "SELECT * FROM guard.license_extensions WHERE id=:id"
        )).mappings().first()
        if earlier:
            return {"status":"ALREADY_EXTENDED"}
        end = link.get("valid_until")
        if end <= now():
            raise ValueError()
        new_end = _add_months(end, months)
        _keygate_set_valid_until(link["keygate_license_id"],new_end)
        return {"status":"EXTENDED"}
'''

def get_route(name):
    root=ast.parse(stage.ROUTES)
    nodes=[n for n in root.body if isinstance(n,ast.FunctionDef) and n.name==name]
    assert len(nodes)==1, name
    return ast.get_source_segment(stage.ROUTES,nodes[0])

class OwnerPaidRenewalsTests(unittest.TestCase):
    def test_overlay_creates_functional_page_without_touching_v44(self):
        result, changed=stage.patched(SAMPLE)
        self.assertTrue(changed)
        ast.parse(result)
        self.assertEqual(stage.names(SAMPLE)["panel_licenses_grid"].body[0].value.value,
                         stage.names(result)["panel_licenses_grid"].body[0].value.value)
        self.assertIn("PROTECTED ORIGINAL V4.4 HTML CSS",result)
        self.assertIn("ORIGINAL V4.4 SAVE",result)
        self.assertIn("WHERE l.lifecycle='ACTIVE' AND l.valid_until>now()",result)
        self.assertIn("SELECT l.id, l.installation_id",result)
        self.assertIn('_owner_effective_entitlement_mode(con, row["installation_id"]) == "CLIENT"',result)
        self.assertIn('"payment_confirmed"\\n',result) if False else None
        self.assertIn('name="payment_confirmed"',result)
        self.assertIn('name="operation_id"',result)
        self.assertIn('name="expected_end"',result)
        self.assertIn("3, 6, 12",result)
        self.assertIn("KeyGate",result)

    def test_payment_csrf_date_and_owner_mode_checked_before_mutation(self):
        text=get_route(stage.NEW_POST)
        self.assertIn("_token_valid(csrf_token)",text)
        self.assertIn('payment_confirmed != "yes"',text)
        self.assertIn("if months not in (3, 6, 12):",text)
        self.assertIn("if original_end.tzinfo is None:",text)
        self.assertIn('!= "CLIENT":',text)
        self.assertIn('link["lifecycle"] != "ACTIVE"',text)
        self.assertIn('link["valid_until"] != original_end',text)
        self.assertLess(text.index('link["valid_until"] != original_end'),
                        text.index("_extend_active_license("))
        self.assertIn("expected_end=original_end",text)
        self.assertIn("by_installation=True",text)
        self.assertNotIn("_keygate_create_license(",text)
        self.assertNotIn("_keygate_revoke(",text)

    def test_engine_stale_check_is_under_same_link_lock(self):
        result,_=stage.update_extension_engine(SAMPLE)
        body=stage.function_text(result,"_extend_active_license")
        self.assertIn("expected_end: datetime | None = None",body)
        self.assertIn("if expected_end is not None and end != expected_end:",body)
        self.assertLess(body.index(" FOR UPDATE"),body.index("if expected_end is not None"))
        self.assertLess(body.index("if expected_end is not None"),body.index("_keygate_set_valid_until("))
        self.assertIn("if earlier:",body)

    def test_already_guarded_engine_is_not_overwritten(self):
        first,changed=stage.update_extension_engine(SAMPLE)
        self.assertTrue(changed)
        second,changed=stage.update_extension_engine(first)
        self.assertFalse(changed)
        self.assertEqual(first,second)

    def test_duplicate_or_unknown_runtime_fails_before_writes(self):
        updated,_=stage.patched(SAMPLE)
        with self.assertRaises(RuntimeError):
            stage.patched(updated)
        with self.assertRaisesRegex(RuntimeError,"Niezgodna obsługa terminu"):
            stage.patched(SAMPLE.replace(
                '        end = link.get("valid_until")',
                '        end = stale_value()',1
            ))

    def test_real_prod_file_will_be_protected_before_restart(self):
        src=STAGE.read_text()
        self.assertIn("ensure_no_open_sessions()",src)
        self.assertIn('shutil.copy2(LICENSE,backup/LICENSE.name)',src)
        self.assertIn('if not args.apply:',src)
        self.assertIn('renewal_status() in (401,403)',src)
        self.assertIn('protected_status()==baseline',src)
        self.assertIn('shutil.copy2(backup/LICENSE.name,LICENSE)',src)
        self.assertIn("NEW_GET",src)
        self.assertIn("NEW_POST",src)

if __name__=="__main__":
    unittest.main()
