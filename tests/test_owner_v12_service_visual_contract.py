"""Pure-stdlib checks for the OWNER V12 service-monitoring visual refresh.

These assertions deliberately do not load the FastAPI application or touch DB.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
LICENSE = ROOT / "embedded-multiguard/app/routers/multiguard_license.py"
THEME = ROOT / "embedded-multiguard/app/routers/multiguard_panel_theme.py"


class OwnerServiceVisualContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.license = LICENSE.read_text(encoding="utf-8")
        cls.theme = THEME.read_text(encoding="utf-8")

    def test_owner_template_and_styles_compile(self):
        compile(self.license, str(LICENSE), "exec")
        compile(self.theme, str(THEME), "exec")

    def test_monitoring_switch_is_accessible(self):
        self.assertIn('data-owner-monitor-toggle', self.license)
        self.assertIn('data-owner-monitor-state', self.license)
        self.assertIn('class="owner-monitor-switch"', self.license)
        self.assertIn('data-owner-monitor-save disabled', self.license)
        self.assertIn('profile.addEventListener(\'change\',update)', self.license)
        self.assertIn('input:focus-visible + .owner-monitor-switch', self.theme)

    def test_legacy_visual_defects_do_not_return(self):
        self.assertNotIn('Monitorowanie rozszerzone — WŁĄCZONE / WYŁĄCZONE', self.license)
        self.assertNotIn('data:image/webp;base64,', self.license)
        self.assertIn('mg-owner-silver', self.license)
        self.assertIn('owner-service-actions', self.license)


if __name__ == "__main__":
    unittest.main()
