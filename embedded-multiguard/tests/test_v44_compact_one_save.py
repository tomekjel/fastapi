"""Pure tests for compact OWNER V4.4 UI, no production data or KeyGate."""
import ast
from pathlib import Path
import unittest

root=Path(__file__).resolve().parents[1]/"scripts"
ui=(root/"compact_v44_grid_renderer.py").read_text()
backend=(root/"compact_v44_owner_term.py").read_text()
deploy=(root/"deploy_compact_v44_one_save.py").read_text()
scope={}
exec(compile(ui,"<compact-grid>","exec"),scope)
render=scope["_mg_v44_grid_transform"]

sample='''<html><body><table id="grid-licenses"><thead><tr><th>Komputer</th><th>Edycja</th><th>Ważna do</th><th>Operacje</th></tr></thead>
<tbody><tr><td>Lenovo</td><td><select name="target_edition" form="row-9"><option value="PRO" selected>Pro</option></select></td>
<td>29.01.27<small>90 dni pozostało</small><details><summary>Wybierz ważność</summary></details>
<label>Potwierdzam otrzymanie płatności</label></td>
<td><form id="row-9" action="/multiguard/panel/licenses-grid/123/save"></form>
<button class="grid-save" form="row-9" disabled>Zapisz</button></td></tr></tbody></table>
<script data-mg-v44-term-version="1">oldPopup()</script></body></html>'''

class Contract(unittest.TestCase):
    def test_compact_date_and_payment_removed(self):
        result=render(sample)
        for x in ('>Pro</option>','>Standard</option>','>Service</option>',
                  'data-month="12"','data-month="6"','data-month="3"',
                  'name="term_date" form="row-9"','name="term_choice" form="row-9"',
                  'document.body.appendChild(popup)'):
            self.assertIn(x,result)
        self.assertNotIn('Potwierdzam otrzymanie płatności',result)
        self.assertNotIn('Wybierz ważność',result)
        self.assertNotIn('oldPopup()',result)
        self.assertEqual(result.count('name="term_choice"'),1)
        self.assertEqual(result.count('class="grid-save"'),1)

    def test_unknown_table_is_rejected(self):
        with self.assertRaises(RuntimeError):
            render(sample.replace('Ważna do','Brak kolumny'))

    def test_owner_direct_edit_is_not_payment(self):
        ast.parse(backend)
        for x in ('_keygate_set_valid_until(', 'owner_license_term_changes',
                  'FOR UPDATE', 'if previous:'):
            self.assertIn(x,backend)
        self.assertNotIn('payment_confirmed',backend)

    def test_rollback_and_protected_backend(self):
        ast.parse(deploy)
        self.assertIn('sessions_closed()',deploy)
        self.assertIn('live_preview(ui)',deploy)
        self.assertIn('shutil.copy2(backup/APP.name,APP)',deploy)
        self.assertIn('_owner_v44_grid_term_selection',deploy)

if __name__=="__main__":
    unittest.main()
