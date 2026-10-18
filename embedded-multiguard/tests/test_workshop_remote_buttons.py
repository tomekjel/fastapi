import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "app" / "routers" / "multiguard_remote.py"


class WorkshopRemoteButtonsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = SOURCE.read_text(encoding="utf-8")
        cls.ui = src[src.index("def owner_workshop_workspace("):src.index('@router.post("/panel/remote-api/workshop/request/', src.index("def owner_workshop_workspace("))]
        cls.status = src[src.index("def panel_workshop_status("):src.index('@router.post("/panel/remote-api/workshop/sessions/', src.index("def panel_workshop_status("))]

    def test_confirmation_before_network_request(self):
        handler = self.ui[self.ui.index("start.onclick = async () => {"):]
        self.assertLess(handler.index("window.confirm("), handler.index("start.disabled = true;"))
        self.assertLess(handler.index("window.confirm("), handler.index("await api('request/' + installation, 'POST')"))

    def test_button_colors_and_disabled_gates(self):
        for needle in ("#ws-start{background:#1764b0}", "#ws-connect{background:#16834a}", "#ws-end{background:#be3030}", ".ws-controls button:disabled", 'id="ws-connect" disabled', 'id="ws-end" disabled'):
            with self.subTest(needle=needle): self.assertIn(needle, self.ui)

    def test_no_green_desktop_before_binding(self):
        self.assertIn('result["meshLinked"] = bool(grant["mesh_node_id"])', self.status)
        self.assertIn('const ready = info.meshLinked === true;', self.ui)
        self.assertIn('connect.disabled = !ready;', self.ui)
        self.assertIn('Oczekiwanie na powiązanie MeshAgenta', self.ui)

    def test_reset_on_end(self):
        self.assertIn("connect.disabled=true; end.disabled=true; start.disabled=false;", self.ui)
        self.assertIn("sid=null;", self.ui)
        self.assertIn("end.disabled=false;status.textContent=e.message;", self.ui)


if __name__ == "__main__":
    unittest.main()
