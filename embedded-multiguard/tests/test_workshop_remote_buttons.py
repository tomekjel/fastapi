import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "app" / "routers" / "multiguard_remote.py"


class WorkshopRemoteButtonsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = SOURCE.read_text(encoding="utf-8")
        cls.ui = src[src.index("def owner_workshop_workspace("):src.index('@router.post("/panel/remote-api/workshop/request/', src.index("def owner_workshop_workspace("))]
        cls.active = src[src.index("def panel_workshop_active("):src.index('@router.get("/panel/remote/workshop/',src.index("def panel_workshop_active("))]
        cls.status = src[src.index("def panel_workshop_status("):src.index('@router.post("/panel/remote-api/workshop/sessions/', src.index("def panel_workshop_status("))]

    def test_explicit_consent_endpoint_is_separate_from_unattended(self):
        source = SOURCE.read_text(encoding="utf-8")
        consent_route = source.split('@router.post("/panel/remote-api/workshop/request-consent/{installation_id}")', 1)[1].split('@router.post("/panel/remote-api/workshop/request/{installation_id}")', 1)[0]
        unattended_route = source.split('@router.post("/panel/remote-api/workshop/request/{installation_id}")', 1)[1].split('@router.get("/panel/remote-api/workshop/sessions/', 1)[0]
        self.assertIn("workshop.request_consent_for_owner(installation_id)", consent_route)
        self.assertNotIn("request_for_owner(installation_id)", consent_route)
        self.assertIn("workshop.request_for_owner(installation_id)", unattended_route)
        self.assertIn("Depends(_owner_panel_csrf)", consent_route)

    def test_confirmation_before_network_request(self):
        handler = self.ui[self.ui.index("start.onclick = async () => {"):]
        self.assertLess(handler.index("window.confirm("), handler.index("start.disabled = true;"))
        self.assertLess(handler.index("window.confirm("), handler.index("await api('request/' + installation, 'POST')"))

    def test_button_colors_and_disabled_gates(self):
        for needle in ("#ws-start{background:#1764b0}", "#ws-connect{background:#16834a}", "#ws-end{background:#be3030}", ".ws-controls button:disabled", 'id="ws-connect" disabled', 'id="ws-end" disabled'):
            with self.subTest(needle=needle): self.assertIn(needle, self.ui)

    def test_no_green_desktop_before_binding(self):
        self.assertIn('result["meshLinked"] = workshop.session_node_ready(grant, row)', self.status)
        self.assertIn('const ready = info.meshLinked === true;', self.ui)
        self.assertIn('connect.disabled = !ready;', self.ui)
        self.assertIn('Oczekiwanie na powiązanie MeshAgenta', self.ui)

    def test_refresh_recovers_server_session_without_duplicate_start(self):
        self.assertIn("async function recover()", self.ui)
        self.assertIn("await api('active/' + installation)", self.ui)
        self.assertIn("sid = data.session.sessionId;", self.ui)
        self.assertIn("start.disabled = true;", self.ui)
        self.assertIn("recover();", self.ui)
        self.assertIn("FROM guard.workshop_remote_sessions", self.active)
        self.assertIn("status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')", self.active)
        self.assertIn('result["meshLinked"]', self.active)

    def test_reset_on_end(self):
        self.assertIn("connect.disabled=true; end.disabled=true; start.disabled=false;", self.ui)
        self.assertIn("sid=null;", self.ui)
        self.assertIn("end.disabled=false;status.textContent=e.message;", self.ui)


if __name__ == "__main__":
    unittest.main()
