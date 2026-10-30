"""V4.4 OWNER three-edition / calendar UI, source-only regression tests."""
from __future__ import annotations
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"stage_grid_v44_controls_20261030.py"
spec=importlib.util.spec_from_file_location("v44_controls",SCRIPT)
overlay=importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)
ns={}
exec(compile(overlay.HELPERS,"<pure-v44-grid-html>","exec"),ns)
transform=ns["_mg_v44_grid_transform"]

DOCUMENT = """
<!doctype html><html><body><table id="grid-licenses">
<thead><tr><th>Komputer</th><th>Edycja</th><th>Ważna do / kanał</th><th>Operacje</th></tr></thead>
<tbody>
<tr><td>Komputer</td><td>Standard</td><td>2027-01-29</td>
<td><form class="grid-row-form" id="row-a111" method="post"
 action="/multiguard/panel/licenses-grid/0f71bb3f-ffff-494d-a11d-222222222222/save">
<input type="hidden" name="csrf_token" value="stub">
<input type="hidden" name="expected_plan" value="multi_guard_pro">
<input type="hidden" name="expected_end" value="2027-01-29T00:00:00+00:00">
</form>
<select class="mg-grid-edition" name="target_edition" form="row-a111">
<option value="STANDARD">Standard</option>
<option value="PRO" selected>Pro</option>
</select>
<button class="grid-save" form="row-a111" disabled>Zapisz</button></td></tr>
</tbody></table></body></html>
"""

# Production markup normally places the edition select in the edition cell.
# Test both variants, since table V4.4 is live and differs from older Git.
DOCUMENT = DOCUMENT.replace(
    "<td>Standard</td><td>2027-01-29</td>",
    "<td>Standard</td><td>2027-01-29</td>"
)

class GridV44ControlsTests(unittest.TestCase):
    def test_exact_three_editions_and_calendar_inside_expiry_column(self):
        result=transform(DOCUMENT)
        for choice in (
            '<option value="PRO" selected>Pro</option>',
            '<option value="STANDARD">Standard</option>',
            '<option value="SERVICE">Service</option>',
            '<option value="CALENDAR">Wybierz datę…</option>',
            '<option value="PERPETUAL">Bezterminowa (Service)</option>',
        ):
            self.assertIn(choice,result)
        self.assertEqual(result.count('<option value="SERVICE"'),1)
        self.assertIn('name="term_date" form="row-a111"',result)
        self.assertIn('type="date"',result)
        self.assertIn('name="payment_confirmed" form="row-a111"',result)
        self.assertIn('name="term_choice" form="row-a111"',result)
        self.assertIn('data-mg-v44-term-version="1"',result)
        self.assertIn('<script data-mg-v44-term-version="1">',result)
        self.assertIn('var choice=term.value, isDate=choice==="CALENDAR"',result)
        self.assertIn('var changed=edition.value!==original || choice!=="KEEP"',result)
        self.assertIn("Ważna do / kanał",result)

    def test_second_render_is_idempotent(self):
        rendered=transform(DOCUMENT)
        self.assertEqual(transform(rendered),rendered)

    def test_missing_calendar_column_is_blocked(self):
        wrong=DOCUMENT.replace("Ważna do / kanał","Not a date")
        with self.assertRaisesRegex(RuntimeError,"kolumny"):
            transform(wrong)

    def test_grid_without_save_forms_is_blocked(self):
        wrong=DOCUMENT.replace("/save","/details")
        with self.assertRaisesRegex(RuntimeError,"Brak formularzy"):
            transform(wrong)

    def test_adapter_preserves_existing_v44_functions(self):
        source='''# STAGE2 HARD STOP: DO NOT ALLOW OWNER RIGHTS TRANSITIONS YET.
def _owner_v44_grid_term_selection(): return True
def panel_grid_save_row(): return True
def panel_licenses_grid():
    return HTMLResponse("grid")
def other_protected_route(): return 42
'''
        changed=overlay.add_adapter(source)
        ast.parse(changed)
        before=overlay.parse(source)
        after=overlay.parse(changed)
        self.assertIn('    HTMLResponse = _mg_v44_grid_response\n',changed)
        self.assertEqual(
            ast.dump(before["other_protected_route"],include_attributes=False),
            ast.dump(after["other_protected_route"],include_attributes=False),
        )
        self.assertIn("def _mg_v44_grid_transform(",changed)
        self.assertIn('def _mg_v44_grid_response(',changed)

    def test_deploy_does_not_enable_service_or_change_keygate(self):
        src=SCRIPT.read_text()
        self.assertIn('no_sessions()',src)
        self.assertIn('SERVICE MODE SWITCH: HARD-LOCKED',src)
        self.assertIn('shutil.copy2(SOURCE,backup/SOURCE.name)',src)
        self.assertIn('shutil.copy2(backup/SOURCE.name,SOURCE)',src)
        self.assertIn('if not args.apply:',src)

if __name__=="__main__":
    unittest.main()
