"""Pure-stdlib checks for the OWNER V12 service-monitoring visual refresh.

These assertions deliberately do not load the FastAPI application or touch DB.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
LICENSE = ROOT / "embedded-multiguard/app/routers/multiguard_license.py"
THEME = ROOT / "embedded-multiguard/app/routers/multiguard_panel_theme.py"
RUNTIME = ROOT / "embedded-multiguard/app/routers/multiguard_runtime.py"


class OwnerServiceVisualContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.license = LICENSE.read_text(encoding="utf-8")
        cls.theme = THEME.read_text(encoding="utf-8")
        cls.runtime = RUNTIME.read_text(encoding="utf-8")

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

    def test_monitoring_form_keeps_backend_contract(self):
        # Visual changes cannot rename form fields or disable CSRF checks.
        self.assertIn('name="monitoring_enabled" value="yes"', self.license)
        # Only source-form behavior is checked; do not claim a browser E2E PASS.
        self.assertIn('name="csrf_token" value="{token}"', self.license)
        self.assertIn('name="profile" aria-label=', self.license)
        self.assertIn('name="csrf_token" value="{token}"', self.license)
        self.assertIn('data-owner-monitor-form', self.license)
        self.assertIn("if monitoring_enabled not in", self.license)
        self.assertIn('profile=profile if monitoring_enabled=="yes" else "OFF"', self.license)
        self.assertIn('return RedirectResponse("/multiguard/panel/service-mode#service-modes",status_code=303)', self.license)

    def test_controls_remain_owner_only(self):
        self.assertIn('def owner_set_workshop_monitoring(', self.license)
        self.assertIn('def owner_disable_workshop(', self.license)
        self.assertIn('csrf_token: str = Form(...)', self.license)
        self.assertIn('_: None = Depends(_panel_auth)', self.license)

    def test_service_grant_never_shows_as_waiting_license(self):
        self.assertIn("w.installation_id=p.installation_id AND w.enabled=TRUE", self.runtime)
        self.assertIn("WHERE p.status=:queue_status", self.runtime)
        self.assertIn("SELECT count(*) FROM guard.pending_installations p", self.runtime)

    def test_legacy_visual_defects_do_not_return(self):
        self.assertNotIn('Monitorowanie rozszerzone — WŁĄCZONE / WYŁĄCZONE', self.license)
        self.assertIn('data:image/webp;base64,', self.license)
        self.assertNotIn('class="owner-approved-shield"', self.license)
        self.assertNotIn('data:image/png;base64,', self.license)
        self.assertNotIn('mg-owner-silver', self.license)
        self.assertIn('owner-service-actions', self.license)
        self.assertIn('Wariant serwisowy', self.license)
        self.assertIn('Licencja klienta — ze zleceniem serwisowym', self.license)
        self.assertIn("SERWIS · ", self.license)
        self.assertIn('const initiallyEnabled=toggle.checked;', self.license)
        self.assertIn('if(state) state.textContent=changed', self.license)
        self.assertIn('if(save) save.disabled=!changed;', self.license)
        self.assertIn('Wyłączone · niezapisane', self.license)


if __name__ == "__main__":
    unittest.main()
