"""Offline regression for consent-first OWNER PRO support actions.

This test needs no server, credentials or hosted Windows runner.
"""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "app/routers/multiguard_runtime.py"


class OwnerRemoteConsentFirstTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)
        cls.functions = {
            n.name: n for n in cls.tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def test_one_click_commercial_pro_handler_exists(self):
        handler = self.functions["owner_commercial_remote_request"]
        decorators = [
            arg.value for d in handler.decorator_list
            if isinstance(d, ast.Call) and d.args
            for arg in [d.args[0]]
            if isinstance(arg, ast.Constant)
        ]
        self.assertIn("/panel/remote/commercial/{installation_id}/request", decorators)
        body = ast.get_source_segment(self.source, handler)
        self.assertIn("_owner_remote_eligible(con, installation_id)", body)
        self.assertIn("_owner_remote_actor(csrf_token)", body)
        self.assertIn("remote.create_remote_session", body)
        self.assertNotIn("mesh_node_id", body)

    def test_connect_uses_token_mode_mesh_url_default(self):
        runtime = self.source
        self.assertIn("'wss://mesh.multi-servis.pl'", runtime)
        self.assertIn("remote.remote_session_connect(str(session_id),actor)", runtime)
        self.assertIn("if url.scheme!='https' or not configured.hostname", runtime)

    def test_expired_requests_do_not_hide_new_connect_button(self):
        panel = ast.get_source_segment(self.source, self.functions["_owner_remote_workspace"])
        self.assertIn('deadline > datetime.now(timezone.utc)', panel)
        self.assertIn('pending_or_active(s) for s in sessions', panel)
        self.assertIn('and pending_or_active(s) and s["status"] == "CONSENTED"', panel)
        # Backend still decides whether an old session must be closed before retry.
        request = ast.get_source_segment(
            self.source, self.functions["owner_commercial_remote_request"]
        )
        self.assertNotIn("SELECT id FROM guard.remote_sessions", request)

    def test_displayed_desktop_does_not_trigger_second_connect(self):
        panel = ast.get_source_segment(self.source, self.functions["_owner_remote_workspace"])
        self.assertIn("if ready_session and not desktop_url:", panel)
        self.assertIn('if desktop_url else', panel)

    def test_consent_is_not_bypassed_by_owner_button(self):
        handler = ast.get_source_segment(
            self.source, self.functions["owner_commercial_remote_request"]
        )
        self.assertNotIn("meshcentral.create_share", handler)
        self.assertNotIn("mesh_node_id", handler)
        self.assertIn("remote.create_remote_session", handler)

    def test_panel_does_not_gate_initial_request_on_mesh_agent(self):
        panel = ast.get_source_segment(self.source, self.functions["_owner_remote_workspace"])
        self.assertIn("'/multiguard/panel/remote/commercial/{selected}/request'", panel)
        self.assertIn("f'/multiguard/panel/remote/workshop/{selected}/request'", panel)
        self.assertNotIn("komponent zdalnego pulpitu nie został zarejestrowany", panel)
        self.assertIn('pending_or_active(s) and s["status"] in {"REQUESTED", "CONSENTED"}', panel)
        self.assertIn("connect_path", panel)
        self.assertIn("expires_at,mesh_share_expires_at", panel)
        self.assertIn("def pending_or_active(session):", panel)
        self.assertIn("bool(chosen[\"mesh_node_id\"])", panel)


if __name__ == "__main__":
    unittest.main()
