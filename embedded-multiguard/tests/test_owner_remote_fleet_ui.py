"""Offline OWNER remote fleet UI security and routing contract."""
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "app/routers/multiguard_remote.py"
WORKSHOP = Path(__file__).resolve().parents[1] / "app/routers/multiguard_workshop_remote.py"

class RemoteFleetPageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PATH.read_text(encoding="utf-8")

    def test_owner_only_full_width_pro_fleet_route(self):
        self.assertIn('@router.get("/panel/remote")', self.source)
        self.assertIn('Depends(_panel_auth)', self.source)
        self.assertIn("UPPER(gi.plan_code)='PRO'", self.source)
        self.assertIn('class="table-wrap"', self.source)

    def test_expandable_support_history_without_financial_leaks(self):
        body = self.source.split('@router.get("/panel/remote")', 1)[1]
        self.assertIn('<details><summary>', body)
        self.assertIn('Cache-Control', body)
        self.assertNotIn('service.owner_finances', body)
        self.assertNotIn('service_amount', body)
        self.assertNotIn('material_cost', body)

    def test_service_history_requires_explicit_device_link(self):
        body = self.source.split('@router.get("/panel/remote")', 1)[1]
        self.assertIn("so.device_id=gi.service_device_id", body)
        self.assertIn("gi.service_device_id IS NOT NULL", body)
        self.assertIn('orders_by_installation.get(str(item["id"]), [])', body)
        self.assertIn("/multiguard/panel/service/", body)
        self.assertIn("<th>Naprawy</th><th>Zdjęcia</th>", body)
        self.assertIn("len(associated)", body)
        self.assertIn("total_photos", body)
        self.assertNotIn("LIKE", body)
        self.assertNotIn("owner_finances", body)

    def test_control_room_requires_explicit_pro_consent(self):
        section = self.source.split('@router.get("/panel/remote/session/{request_id}")', 1)[1]
        self.assertIn('Depends(_panel_auth)', section)
        self.assertIn('row["plan_code"] != "PRO"', section)
        self.assertIn("row[\"lifecycle\"] != \"ACTIVE\"", section)
        self.assertIn('request-connect', section)
        self.assertIn('session.status === \'CONSENTED\'', section)
        self.assertIn("panel/remote-api/sessions/' + sessionId + '/connect", section)
        self.assertIn("panel/remote-api/sessions/' + sessionId + '/end", section)
        self.assertIn("window.open('about:blank', '_blank')", section)
        self.assertIn("url.protocol !== 'https:'", section)

    def test_panel_basic_bridge_and_csrf(self):
        self.assertIn('def panel_create_remote_session(', self.source)
        self.assertIn('def panel_remote_session_connect(', self.source)
        self.assertIn('def panel_remote_session_end(', self.source)
        self.assertIn('Depends(_panel_auth)', self.source)
        self.assertIn('Depends(_owner_panel_csrf)', self.source)
        self.assertIn('_token_valid(x_owner_csrf)', self.source)
        self.assertIn("'X-Owner-CSRF':csrf", self.source)
        self.assertIn('/panel/remote-api/sessions/', self.source)

    def test_workshop_unattended_only_with_owner_enabled_pro(self):
        workshop = WORKSHOP.read_text(encoding="utf-8")
        mode = workshop.split("def request_for_owner(iid: uuid.UUID):", 1)[1].split("@router.post", 1)[0]
        self.assertIn("if not _eligible(grant)", mode)
        self.assertIn("'CONSENTED'", mode)
        self.assertIn("OWNER_UNATTENDED_WORKSHOP_CONNECT", mode)
        self.assertIn("request_for_owner", self.source)
        self.assertIn("Czy na pewno połączyć się z komputerem serwisowym?", self.source)
        self.assertIn("window.confirm", self.source)

    def test_customer_still_requires_client_consent(self):
        self.assertIn("session.status === 'CONSENTED'", self.source)
        self.assertIn("Wysłać klientowi prośbę o zatwierdzenie połączenia?", self.source)
        workshop = WORKSHOP.read_text(encoding="utf-8")
        self.assertIn("if not _eligible(grant)", workshop)
        self.assertIn("close_before_rights_change", workshop)

    def test_no_unconsented_remote_launch(self):
        body = self.source.split('@router.get("/panel/remote")', 1)[1]
        self.assertNotIn('remote_session_connect(', body)
        self.assertNotIn('meshcentral.create_share(', body)

if __name__ == "__main__":
    unittest.main()
