"""Offline OWNER remote fleet UI security and routing contract."""
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "app/routers/multiguard_remote.py"

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

    def test_no_unconsented_remote_launch(self):
        body = self.source.split('@router.get("/panel/remote")', 1)[1]
        self.assertNotIn('remote_session_connect(', body)
        self.assertNotIn('meshcentral.create_share(', body)

if __name__ == "__main__":
    unittest.main()
