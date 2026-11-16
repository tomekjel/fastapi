"""MASTER 1.10 release gate: OWNER rebind must not perform unjournaled KeyGate effects.

Read-only static regression tests. They operate on the source AST, require no
production credentials, and do not call KeyGate, PostgreSQL, or MeshCentral.
A failing test is an intentional release blocker until rebind is made durable.
"""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "embedded-multiguard/app/routers/multiguard_license.py"

def function_node(name):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    return next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)

def calls(node, name):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and n.func.id == name]

class RebindReleaseSafetyTests(unittest.TestCase):
    def test_owner_rebind_records_durable_intent_before_keygate_deactivation(self):
        fn = function_node("rebind_reception_license")
        deactivate = calls(fn, "_keygate_deactivate")
        self.assertEqual(len(deactivate), 1, "Rebind deactivation path has changed; review required")
        # The existing provisioning journal protects ACTIVATION only.
        # Rebind needs its own durable operation record, committed before
        # the external deactivation, with a reconciliation state on ambiguity.
        journals = calls(fn, "_begin_keygate_rebind_attempt")
        self.assertEqual(len(journals), 1,
                         "UNSAFE REBIND: missing durable release intent; do not deploy")
        self.assertLess(journals[0].lineno, deactivate[0].lineno,
                        "UNSAFE REBIND: KeyGate effect precedes committed intent")

    def test_owner_rebind_requires_recorded_completion_or_manual_reconciliation(self):
        fn = function_node("rebind_reception_license")
        self.assertEqual(len(calls(fn, "_finish_keygate_rebind_attempt")), 1,
                         "UNSAFE REBIND: missing persistent outcome/reconciliation handling")

    def test_approval_remains_owner_only(self):
        fn = function_node("approve_pending_recovery")
        rendered = ast.unparse(fn)
        self.assertIn("Depends(require_owner)", rendered)
        self.assertIn("FOR UPDATE", rendered)

if __name__ == "__main__":
    unittest.main()
