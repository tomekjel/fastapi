"""OWNER V12: no financial amounts in overview or unattended remote UI.

This is an offline source contract; it does not need a database or customer data.
"""
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1] / "app" / "routers"


class OwnerFinancialDiscretion(unittest.TestCase):
    def test_order_finances_require_explicit_expand(self):
        service = (BASE / "multiguard_service_panel.py").read_text(encoding="utf-8")
        self.assertIn('<details class="card finance-disclosure">', service)
        self.assertIn('Dane właściciela · kliknij, aby rozwinąć', service)
        self.assertNotIn('<details class="card finance-disclosure" open', service)
        self.assertIn('Depends(_panel_auth)', service)

    def test_financial_details_not_in_remote_agent_module(self):
        remote = (BASE / "multiguard_remote.py").read_text(encoding="utf-8")
        self.assertNotIn('service.owner_finances', remote)
        self.assertNotIn('actual_profit', remote)
        workshop = (BASE / "multiguard_workshop_remote.py").read_text(encoding="utf-8")
        self.assertNotIn('service.owner_finances', workshop)
        self.assertNotIn('actual_profit', workshop)

    def test_photos_are_served_through_owner_only_route(self):
        service = (BASE / "multiguard_service_panel.py").read_text(encoding="utf-8")
        self.assertIn('/multiguard/panel/service/{order_id}/media/{media_id}', service)
        self.assertIn('Depends(_panel_auth)', service)
        self.assertIn('Cache-Control', service)


if __name__ == "__main__":
    unittest.main()
