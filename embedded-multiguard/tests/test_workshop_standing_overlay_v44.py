"""Pure overlay tests: exact function-only diff, no production or Mesh access."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"stage_workshop_standing_gate_v44.py"
spec=importlib.util.spec_from_file_location("service_gate_stage",SCRIPT)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

SOURCE=(ROOT/"app"/"routers"/"multiguard_workshop_remote.py").read_text()

class StageStandingConsentTests(unittest.TestCase):
    def test_new_source_only_patches_three_functions(self):
        revised=stage.overlay(SOURCE,SOURCE,SOURCE)
        self.assertEqual(revised,SOURCE)
        self.assertIn('standing_authorization_record(db, iid, lock=True)',revised)
        ast.parse(revised)

    def test_unrecognized_production_function_must_abort(self):
        modified=SOURCE.replace(
            'scope = standing["device_scope"]',
            'scope = "CLIENT_DIAGNOSTIC"',1)
        with self.assertRaisesRegex(RuntimeError,"Unrecognized production"):
            stage.overlay(modified,SOURCE,SOURCE)

    def test_non_target_v44_function_remains_unchanged(self):
        original=stage.function_nodes(SOURCE)
        revised=stage.function_nodes(stage.overlay(SOURCE,SOURCE,SOURCE))
        for name in original:
            self.assertEqual(
                ast.dump(original[name],include_attributes=False),
                ast.dump(revised[name],include_attributes=False),
                name
            )

    def test_deployment_requires_absence_of_any_active_mesh_share(self):
        code=SCRIPT.read_text()
        self.assertIn("ensure_no_open_remote_sessions()",code)
        self.assertIn("OR mesh_public_id IS NOT NULL",code)
        self.assertIn("backup-mg-standing-consent-",code)
        self.assertIn('if not args.apply:',code)
        self.assertIn('shutil.copy2(backup/PROD.name,PROD)',code)
        self.assertIn('STAGE2 HARD STOP:',code)

if __name__=="__main__":
    unittest.main()
