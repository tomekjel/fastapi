"""Synthetic regression of actual V4.4 Save field names and guarded extension.

Production patch verifies whole-file SHA256 and never trusts this synthetic
fixture as a substitute for the live 146-line function.
"""
from __future__ import annotations
import ast
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stage_owner_grid_save_v44_surgical.py"
spec = importlib.util.spec_from_file_location("v44_surgical", SCRIPT)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

FIXTURE = '''
# STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.
def protected_grid_and_sidebar():
    return "V4.4 preserved"

@router.post("/multiguard/panel/licenses-grid/{link_id}/save")
def panel_grid_save_row(
    link_id: uuid.UUID,
    operation_id: uuid.UUID = Form(...),
    friendly_name: str = Form(""),
    target_edition: str = Form(...),
    release_channel: str = Form(""),
    expected_plan: str = Form(...),
    expected_end: str = Form(""),
    expected_channel: str = Form(""),
    expected_name: str = Form(""),
    confirmed: str = Form(""),
    csrf_token: str = Form(...),
    _: None = Depends(_panel_auth),
):
    from app.routers.multiguard_panel_settings import _token_valid
    from fastapi.responses import RedirectResponse
    if not _token_valid(csrf_token):
        raise HTTPException(403,"Nieprawidłowy formularz.")
    if confirmed != "yes":
        raise HTTPException(400,"Potwierdź zapis zmian.")

    name=" ".join(friendly_name.strip().split())
    edition=target_edition.strip().upper()
    channel=release_channel.strip().upper()

    if len(name)>420 or any(ord(c)<32 for c in name):
        raise HTTPException(400,"Nieprawidłowa nazwa.")
    if edition not in {"STANDARD","PRO"}:
        raise HTTPException(400,"Nieprawidłowa edycja.")
    if channel not in {"","STABLE","PILOT"}:
        raise HTTPException(400,"Nieprawidłowy kanał.")
    _ensure_schema()

    def check_state(con,after_plan=False):
        return dict(plan_code="multi_guard_pro"), ""

    with engine.connect() as con:
        row,old_name=check_state(con)
        iid=row["installation_id"]
        plan_changed=("multi_guard_pro" if edition=="PRO" else "multi_guard")!=row["plan_code"]
        name_changed=name!=old_name
        channel_changed=channel!=str(row["release_channel"] or "").upper()

        if name_changed:
            pass
        if plan_changed:
            pass
        if channel_changed:
            pass

    if plan_changed:
        _owner_change_plan(link_id,operation_id,_license_operation_date(expected_end),edition,"")

    if name_changed or channel_changed:
        with engine.begin() as con:
            current,previous_name=check_state(con,after_plan=plan_changed)
            if channel_changed:
                pass
    return RedirectResponse("/multiguard/panel/licenses-grid", status_code=303)

def panel_licenses_grid():
    return "KNOWN V4.4 HTML CSS"
'''

class SurgicalProductionOverlayTests(unittest.TestCase):
    def test_only_save_and_new_guarded_handler_change(self):
        result = stage.patched(FIXTURE)
        ast.parse(result)
        self.assertEqual(
            ast.dump(stage.functions(FIXTURE)["panel_licenses_grid"], include_attributes=False),
            ast.dump(stage.functions(result)["panel_licenses_grid"], include_attributes=False),
        )
        for marker in (
            'name="expected_name"', 'expected_channel: str = Form',
            'release_channel: str = Form', 'term_choice: str = Form("KEEP")',
            "plan_grid_license_change(", "MULTIGUARD_OWNER_GRID_SERVICE_ENABLED",
            "MULTIGUARD_OWNER_GRID_PAID_TERM_ENABLED",
            "MULTIGUARD_MODE_SWITCH_ENABLED",
        ):
            # expected_name is a parameter, not an HTML form in the fixture.
            if marker == 'name="expected_name"':
                continue
            self.assertIn(marker, result)
        self.assertIn("def _owner_v44_grid_term_selection(", result)
        self.assertIn('if name_changed or channel_changed:', result)
        self.assertIn('def check_state(con,after_plan=False)', result)
        self.assertIn('_owner_change_plan(link_id,operation_id', result)
        self.assertIn('if owner_selected_mode == "SERVICE" and (plan_changed or channel_changed):', result)
        self.assertIn("if name_changed or channel_changed:", result)

    def test_no_double_patch_and_no_structural_guess(self):
        revised = stage.patched(FIXTURE)
        with self.assertRaises(RuntimeError):
            stage.patched(revised)
        with self.assertRaises(RuntimeError):
            stage.patched(FIXTURE.replace(
                'expected_channel: str = Form("")',
                'expected_config: str = Form("")',
            ))

    def test_original_ui_and_paid_mutation_endpoints_not_changed(self):
        revised = stage.patched(FIXTURE)
        self.assertIn('return "KNOWN V4.4 HTML CSS"', revised)
        helper = stage.function_text(revised, "_owner_v44_grid_term_selection")
        self.assertNotIn("_keygate_create_license(", helper)
        self.assertNotIn("_keygate_revoke(", helper)
        self.assertIn("expected_end=row[\"valid_until\"]", helper)
        self.assertIn('payment_confirmed != "yes"', helper)
        self.assertIn("explicit_paid_perpetual_supported=False", helper)

    def test_pinned_production_check_is_present(self):
        text = SCRIPT.read_text()
        self.assertIn("7086ed8317e4957d4e6b8958a2a3259eef3b56d6ec93aa18f5989c90d538e049", text)
        self.assertIn("DRY RUN", text)
        self.assertIn("no_open_sessions()", text)
        self.assertIn("if not args.apply:", text)

if __name__ == "__main__":
    unittest.main()
