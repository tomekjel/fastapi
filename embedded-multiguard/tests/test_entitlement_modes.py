"""No credentials, database or KeyGate needed: OWNER mode-selection regression tests."""
from datetime import datetime, timedelta, timezone
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.routers.multiguard_entitlement_modes import (  # noqa: E402
    resolve_mode,
    paid_pro_authorized,
    service_grant_authorized,
    unattended_service_authorized,
)

NOW = datetime(2026, 10, 30, 16, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=31)
EARLIER = NOW - timedelta(seconds=1)


class EntitlementModeTests(unittest.TestCase):
    def paid(self, mode="CLIENT", **overrides):
        args = dict(edition="PRO", lifecycle="ACTIVE", valid_until=LATER, now=NOW)
        args.update(overrides)
        return paid_pro_authorized(mode, **args)

    def service(self, mode="SERVICE", **overrides):
        args = dict(enabled=True, edition="PRO", pending_status="PROVISIONED",
                    valid_until=None, now=NOW)
        args.update(overrides)
        return service_grant_authorized(mode, **args)

    def unattended(self, mode="SERVICE", **overrides):
        args = dict(enabled=True, edition="PRO", pending_status="PROVISIONED",
                    valid_until=None, now=NOW,
                    standing_authorization_valid=True)
        args.update(overrides)
        return unattended_service_authorized(mode, **args)

    def test_paid_link_takes_precedence_over_simultaneous_service_grant(self):
        self.assertEqual(resolve_mode(None, has_customer_link=True,
                                      has_service_grant=True), "CLIENT")

    def test_owner_may_select_service_without_deleting_paid_link(self):
        mode = resolve_mode("SERVICE", has_customer_link=True,
                            has_service_grant=True)
        self.assertTrue(self.service(mode))
        self.assertFalse(self.paid(mode))

    def test_switch_back_to_paid_preserves_original_expiry(self):
        mode = resolve_mode("CLIENT", has_customer_link=True,
                            has_service_grant=True)
        self.assertTrue(self.paid(mode, valid_until=LATER))
        self.assertFalse(self.service(mode))

    def test_service_only_legacy_without_customer_link(self):
        self.assertEqual(resolve_mode(None, has_customer_link=False,
                                      has_service_grant=True), "SERVICE")

    def test_neither_entitlement_means_none(self):
        self.assertEqual(resolve_mode(None, has_customer_link=False,
                                      has_service_grant=False), "NONE")
        self.assertFalse(self.paid("NONE"))
        self.assertFalse(self.service("NONE"))

    def test_invalid_mode_is_rejected_instead_of_falling_back(self):
        with self.assertRaises(ValueError):
            resolve_mode("BROKEN", has_customer_link=True, has_service_grant=True)

    def test_revoked_paid_does_not_fall_back_to_service_automatically(self):
        mode = resolve_mode(None, has_customer_link=True,
                            has_service_grant=True)
        self.assertFalse(self.paid(mode, lifecycle="REVOKED"))
        self.assertFalse(self.service(mode))

    def test_expired_paid_is_not_renewed_by_service_selection(self):
        self.assertFalse(self.paid("CLIENT", valid_until=EARLIER))
        self.assertFalse(self.paid("CLIENT", valid_until=NOW))

    def test_paid_standard_has_no_remote_access(self):
        self.assertFalse(self.paid("CLIENT", edition="STANDARD"))

    def test_service_standard_has_no_unattended_remote_access(self):
        self.assertTrue(self.service("SERVICE", edition="STANDARD"))
        self.assertFalse(self.unattended("SERVICE", edition="STANDARD"))

    def test_service_pro_needs_previous_standing_authorization(self):
        self.assertTrue(self.unattended("SERVICE"))
        self.assertFalse(self.unattended("SERVICE",
                                        standing_authorization_valid=False))

    def test_service_pro_cannot_bypass_client_prompt(self):
        self.assertFalse(self.unattended("CLIENT"))
        self.assertTrue(self.paid("CLIENT"))

    def test_disabled_service_and_uninstalled_device_fail_closed(self):
        self.assertFalse(self.service("SERVICE", enabled=False))
        self.assertFalse(self.service("SERVICE", pending_status="UNINSTALLED"))
        self.assertFalse(self.unattended("SERVICE", pending_status="ARCHIVED"))

    def test_explicit_service_expiry_is_exclusive(self):
        self.assertTrue(self.service("SERVICE", valid_until=LATER))
        self.assertFalse(self.service("SERVICE", valid_until=NOW))
        self.assertFalse(self.unattended("SERVICE", valid_until=EARLIER))

    def test_malformed_or_naive_expiration_fails_closed(self):
        naive = datetime(2026, 10, 31)
        self.assertFalse(self.service("SERVICE", valid_until=naive))
        self.assertFalse(self.paid("CLIENT", valid_until=naive))

    def test_no_date_means_indefinite_service_not_paid(self):
        self.assertTrue(self.service("SERVICE", valid_until=None))
        self.assertFalse(self.paid("CLIENT", valid_until=None))

    def test_pending_paid_license_cannot_start_remote_support(self):
        self.assertFalse(self.paid("CLIENT", lifecycle="PENDING_ACCEPTANCE"))


if __name__ == "__main__":
    unittest.main()
