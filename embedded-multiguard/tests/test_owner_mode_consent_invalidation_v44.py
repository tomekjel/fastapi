"""V4.4 production-safe OWNER consent invalidation, no DB/KeyGate/Mesh."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
script=ROOT/"scripts"/"stage_owner_mode_consent_invalidation_v44.py"
spec=importlib.util.spec_from_file_location("owner_consent_v44",script)
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

UPGRADED=(ROOT/"app"/"routers"/"multiguard_license.py").read_text()
assert "workshop_remote.invalidate_standing_authorization(" in UPGRADED
assert "workshop_remote._schema()" in UPGRADED

BEFORE=UPGRADED.replace(
    '    from app.routers import multiguard_workshop_remote as workshop_remote\n',
    '',1
).replace(
    '    # The standing-consent registry must exist before opening the mode\n'
    '    # transition.  Grants alone never authorize unattended remote access.\n'
    '    workshop_remote._schema()\n',
    '',1
).replace(
    '        # Any ACTUAL OWNER rights change invalidates prior unattended consent\n'
    '        # within this same transaction. Switching back to SERVICE requires a\n'
    '        # fresh approval by OWNER and a separate local device opt-in.\n'
    '        workshop_remote.invalidate_standing_authorization(\n'
    '            con, iid, "SERVICE_RIGHTS_CHANGED",\n'
    '        )\n\n',
    '',1
)

class OwnerConsentInvalidationTests(unittest.TestCase):
    def test_surgical_patch_modifies_only_mode_function(self):
        revised,applied=stage.patch(BEFORE)
        self.assertFalse(applied)
        ast.parse(revised)
        self.assertIn('workshop_remote.invalidate_standing_authorization(',revised)
        self.assertIn('workshop_remote._schema()',revised)
        self.assertEqual(
            set(stage.functions(revised)),set(stage.functions(BEFORE))
        )
        for name in stage.functions(BEFORE):
            if name=="_owner_select_effective_mode":
                continue
            self.assertEqual(
                ast.dump(stage.functions(BEFORE)[name],include_attributes=False),
                ast.dump(stage.functions(revised)[name],include_attributes=False),
                name
            )

    def test_repeated_patch_is_noop(self):
        once,done=stage.patch(BEFORE)
        self.assertFalse(done)
        again,done=stage.patch(once)
        self.assertTrue(done)
        self.assertEqual(once,again)

    def test_partial_or_weakened_security_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError,"Partial"):
            stage.patch(BEFORE.replace(
                stage.SCHEMA_ANCHOR,stage.SCHEMA_CHANGE,1))
        with self.assertRaisesRegex(RuntimeError,"Missing audited"):
            stage.patch(BEFORE.replace("mesh_public_id IS NOT NULL",
                                       "mesh_public_id IS NULL",1))

    def test_consent_revoked_before_mode_selection(self):
        after,_=stage.patch(BEFORE)
        fn=stage.target_text(after)
        self.assertLess(fn.index("if active:"),
                        fn.index("workshop_remote.invalidate_standing_authorization("))
        self.assertLess(fn.index("workshop_remote.invalidate_standing_authorization("),
                        fn.index("INSERT INTO guard.owner_entitlement_selections("))
        self.assertIn('"SERVICE_RIGHTS_CHANGED"',fn)
        self.assertIn("workshop_remote._schema()",fn)
        self.assertIn("with engine.begin() as con:",fn)

if __name__=="__main__":
    unittest.main()
