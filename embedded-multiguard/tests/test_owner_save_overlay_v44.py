"""Read-only unit tests for guarded V4.4 OWNER Save backend insertion."""
import ast, importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
path=ROOT/"scripts/stage_owner_grid_save_v44.py"
spec=importlib.util.spec_from_file_location("mg_save_v44",path)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

new=(ROOT/"app/routers/multiguard_license.py").read_text()
fixture=new.replace("def panel_grid_save(", "def panel_grid_save_row(",1)


class StagedGridSaveTests(unittest.TestCase):
    def test_exact_known_functions_only(self):
        revised=stage.prepare(fixture,new,new)
        ast.parse(revised)
        self.assertEqual(stage.canon(fixture,"panel_licenses_grid"),
                         stage.canon(revised,"panel_licenses_grid"))
        self.assertEqual(stage.canon(fixture,"panel_revoke_license"),
                         stage.canon(revised,"panel_revoke_license"))
        self.assertIn("plan_grid_license_change(",revised)
        self.assertIn("expected_end: datetime | None = None",revised)

    def test_unknown_live_save_aborts_without_changes(self):
        mutated=fixture.replace("def panel_grid_save_row(", "def panel_grid_save_row(",1)
        mutated=mutated.replace(
            'if not _token_valid(csrf_token) or confirmed != "yes":',
            'if not _token_valid(csrf_token):',1
        )
        with self.assertRaisesRegex(RuntimeError,"Save differs"):
            stage.prepare(mutated,new,new)

    def test_policy_flags_and_mode_switch_interlock_preserved(self):
        body=stage.body(new,"panel_grid_save")
        self.assertIn("MULTIGUARD_MODE_SWITCH_ENABLED",body)
        self.assertIn("MULTIGUARD_OWNER_GRID_PAID_TERM_ENABLED",body)
        self.assertIn("MULTIGUARD_OWNER_GRID_SERVICE_ENABLED",body)
        self.assertIn("explicit_paid_perpetual_supported=False",body)
        script=path.read_text()
        self.assertIn("STAGE2 HARD STOP",script)
        self.assertIn("no_open_sessions()",script)
        self.assertIn("DRY RUN: NO CHANGES",script)

if __name__=="__main__":
    unittest.main()
