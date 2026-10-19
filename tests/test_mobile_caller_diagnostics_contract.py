"""Static integration checks for isolated Android diagnostics router.

These tests intentionally need only the Python stdlib; the production
database and authenticated live backend are tested later before rollout.
"""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTER = ROOT / "embedded-multiguard/app/routers/mobile_caller_diagnostics.py"
INSTALLER = ROOT / "embedded-multiguard/install.sh"


class AndroidDiagnosticsContract(unittest.TestCase):
    def setUp(self):
        self.source = ROUTER.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)
        self.installer = INSTALLER.read_text(encoding="utf-8")

    def test_both_routes_require_owner(self):
        endpoints = {
            "submit_caller_diagnostics",
            "list_caller_diagnostics",
        }
        funcs = {node.name: node for node in self.tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertTrue(endpoints.issubset(funcs))
        for name in endpoints:
            fn = funcs[name]
            self.assertTrue(any(
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id == "Depends"
                and any(isinstance(arg, ast.Name) and arg.id == "require_owner"
                        for arg in default.args)
                for default in fn.args.defaults
            ), msg="Missing require_owner in " + name)

    def test_schema_bounds_privacy_and_idempotence(self):
        source = self.source
        for required in (
            "Field(min_length=1, max_length=100)",
            "ON CONFLICT (device_id, event_id) DO NOTHING",
            "received_at < now() - INTERVAL '7 days'",
            "entry.errorClass",
            "_SAFE_ERROR",
            "eventId: uuid.UUID",
            "deviceId: uuid.UUID",
        ):
            self.assertIn(required, source)
        self.assertNotIn("recording_path", source)
        self.assertNotIn("phone_number", source)
        self.assertNotIn("authorization_token", source)

    def test_installer_carries_router_and_rollback(self):
        for required in (
            "MOBILE_DIAG_FILE=",
            "HAD_MOBILE_DIAG=0",
            'cp -a "$BACKUP_DIR/mobile_caller_diagnostics.py" "$MOBILE_DIAG_FILE"',
            "app.include_router(mobile_caller_diagnostics.router)",
            '"from app.routers import mobile_caller_diagnostics"',
            '"/mobile/diagnostics/caller"',
        ):
            self.assertIn(required, self.installer)


if __name__ == "__main__":
    unittest.main()
