"""No credentials, database or KeyGate needed: OWNER mode-selection regression tests."""
from datetime import date, datetime, timedelta, timezone
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.routers.multiguard_entitlement_modes import (  # noqa: E402
    resolve_mode,
    paid_pro_authorized,
    service_grant_authorized,
    unattended_service_authorized,
    validate_license_variant,
    license_within_period,
    license_term_selection,
    calendar_valid_until,
    service_valid_until,
    owner_valid_until,
    plan_grid_license_change,
)

NOW = datetime(2026, 10, 30, 16, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=31)
EARLIER = NOW - timedelta(seconds=1)


class SixLicenseVariantsTests(unittest.TestCase):
    """Edition and duration must be independently selectable in OWNER UI."""

    def test_all_three_editions_allow_timed_and_perpetual(self):
        for edition in ("STANDARD", "PRO", "SERVICE"):
            with self.subTest(edition=edition, period="TIMED"):
                self.assertEqual(
                    validate_license_variant(edition, "TIMED", 3),
                    (edition, "TIMED", 3),
                )
                self.assertEqual(
                    validate_license_variant(edition, "TIMED", 6),
                    (edition, "TIMED", 6),
                )
                self.assertEqual(
                    validate_license_variant(edition, "TIMED", 12),
                    (edition, "TIMED", 12),
                )
            with self.subTest(edition=edition, period="PERPETUAL"):
                self.assertEqual(
                    validate_license_variant(edition, "PERPETUAL", None),
                    (edition, "PERPETUAL", None),
                )

    def test_calendar_is_a_fourth_choice_for_every_edition(self):
        for edition in ("STANDARD", "PRO", "SERVICE"):
            self.assertEqual(
                license_term_selection(
                    edition, "TIMED", calendar_date=date(2026, 11, 15)
                ),
                (edition, "TIMED", None, date(2026, 11, 15)),
            )

    def test_calendar_one_week_and_two_weeks(self):
        now = datetime(2026, 10, 30, 16, 0, tzinfo=timezone.utc)
        for chosen_day in (date(2026, 11, 6), date(2026, 11, 13)):
            end = calendar_valid_until(chosen_day, now=now)
            self.assertEqual(
                end.astimezone(__import__("zoneinfo").ZoneInfo("Europe/Warsaw")).date(),
                chosen_day + timedelta(days=1),
            )

    def test_until_november_15_includes_whole_fifteenth(self):
        expires = calendar_valid_until(
            date(2026, 11, 15), now=NOW,
        )
        self.assertEqual(
            expires.astimezone(__import__("zoneinfo").ZoneInfo("Europe/Warsaw")).strftime("%Y-%m-%d %H:%M"),
            "2026-11-16 00:00",
        )

    def test_calendar_dst_transition_is_local_midnight(self):
        now = datetime(2026, 3, 27, 12, tzinfo=timezone.utc)
        expires = calendar_valid_until(date(2026, 3, 29), now=now)
        self.assertEqual(
            expires.astimezone(__import__("zoneinfo").ZoneInfo("Europe/Warsaw")).strftime("%Y-%m-%d %H:%M"),
            "2026-03-30 00:00",
        )

    def test_perpetual_never_keeps_hidden_calendar_date(self):
        with self.assertRaises(ValueError):
            license_term_selection(
                "SERVICE", "PERPETUAL", calendar_date=date(2026, 11, 15)
            )

    def test_two_period_sources_cannot_override_each_other(self):
        with self.assertRaises(ValueError):
            license_term_selection(
                "SERVICE", "TIMED", preset_months=3,
                calendar_date=date(2026, 11, 15),
            )

    def test_custom_date_cannot_be_in_the_past(self):
        with self.assertRaises(ValueError):
            calendar_valid_until(date(2026, 10, 29), now=NOW)

    def test_timed_service_expires_while_offline(self):
        self.assertTrue(license_within_period("TIMED", LATER, NOW))
        self.assertFalse(license_within_period("TIMED", NOW, NOW))
        self.assertFalse(license_within_period("TIMED", EARLIER, NOW))

    def test_perpetual_service_not_bound_to_end_date(self):
        self.assertTrue(license_within_period("PERPETUAL", None, NOW))
        self.assertFalse(license_within_period("PERPETUAL", LATER, NOW))

    def test_paid_perpetual_must_be_explicit_not_inferred(self):
        self.assertFalse(paid_pro_authorized(
            "CLIENT", edition="PRO", lifecycle="ACTIVE",
            valid_until=None, now=NOW,
        ))
        self.assertTrue(paid_pro_authorized(
            "CLIENT", edition="PRO", lifecycle="ACTIVE",
            valid_until=None, now=NOW, period="PERPETUAL",
        ))
        self.assertFalse(paid_pro_authorized(
            "SERVICE", edition="PRO", lifecycle="ACTIVE",
            valid_until=None, now=NOW, period="PERPETUAL",
        ))
        self.assertFalse(paid_pro_authorized(
            "CLIENT", edition="STANDARD", lifecycle="ACTIVE",
            valid_until=None, now=NOW, period="PERPETUAL",
        ))

    def test_missing_expiry_does_not_make_paid_pro_perpetual(self):
        self.assertFalse(license_within_period("TIMED", None, NOW))

    def test_invalid_time_and_edition_fail_closed(self):
        for edition, period, months in (
            ("SERVICE", "TIMED", None),
            ("SERVICE", "TIMED", 1),
            ("PRO", "PERPETUAL", 12),
            ("STANDARD", "PERPETUAL", 3),
            ("SERVICE", "INFINITE", None),
            ("UNKNOWN", "TIMED", 3),
        ):
            with self.subTest(edition=edition, period=period, months=months):
                with self.assertRaises(ValueError):
                    validate_license_variant(edition, period, months)

    def test_no_silent_conversion_on_invalid_date(self):
        self.assertFalse(
            license_within_period("TIMED", datetime(2026, 11, 1), NOW)
        )
        self.assertFalse(license_within_period("OTHER", None, NOW))



    def test_service_terms_are_explicit_and_never_implicitly_perpetual(self):
        for choice in ("", "KEEP", "7", "UNKNOWN"):
            with self.subTest(choice=choice), self.assertRaises(ValueError):
                service_valid_until(choice, "", now=NOW)
        self.assertIsNone(service_valid_until("PERPETUAL", "", now=NOW))
        with self.assertRaises(ValueError):
            service_valid_until("PERPETUAL", "2026-11-15", now=NOW)

    def test_service_calendar_and_months_are_independent(self):
        self.assertEqual(
            service_valid_until("CALENDAR", "2026-11-15", now=NOW),
            calendar_valid_until(date(2026, 11, 15), now=NOW),
        )
        self.assertEqual(
            service_valid_until("3", "", now=NOW),
            datetime(2027, 1, 30, 16, tzinfo=timezone.utc),
        )
        for choice, date_string in (("3", "2026-11-15"),
                                    ("CALENDAR", ""),
                                    ("CALENDAR", "2026-10-29"),
                                    ("CALENDAR", "2026-11-31")):
            with self.subTest(choice=choice, date_string=date_string), self.assertRaises(ValueError):
                service_valid_until(choice, date_string, now=NOW)

    def test_duration_policy_all_three_editions(self):
        for edition in ("STANDARD", "PRO", "SERVICE"):
            for choice in ("3", "6", "12"):
                with self.subTest(edition=edition, choice=choice):
                    self.assertGreater(
                        owner_valid_until(edition, choice, "", now=NOW),
                        NOW,
                    )
            self.assertIsNone(
                owner_valid_until(edition, "PERPETUAL", "", now=NOW)
            )
            self.assertEqual(
                owner_valid_until(
                    edition, "CALENDAR", "2026-11-15", now=NOW
                ),
                calendar_valid_until(date(2026, 11, 15), now=NOW),
            )

    def test_paid_extension_keeps_existing_remaining_months(self):
        remaining = datetime(2026, 12, 30, 16, tzinfo=timezone.utc)
        target = owner_valid_until(
            "PRO", "12", "", now=NOW, existing_end=remaining,
            extend=True,
        )
        self.assertEqual(
            target, datetime(2027, 12, 30, 16, tzinfo=timezone.utc)
        )
        assert target is not None
        self.assertGreater(target, remaining)

    def test_calendar_extension_cannot_shorten_paid_term(self):
        remaining = datetime(2027, 3, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            owner_valid_until(
                "STANDARD", "CALENDAR", "2026-11-15", now=NOW,
                existing_end=remaining, extend=True,
            )

    def test_month_end_extension_clamps_february(self):
        now = datetime(2027, 1, 31, 12, tzinfo=timezone.utc)
        self.assertEqual(
            owner_valid_until("SERVICE", "3", "", now=now),
            datetime(2027, 4, 30, 12, tzinfo=timezone.utc),
        )

    def test_edition_or_naive_expiry_invalid_fail_closed(self):
        with self.assertRaises(ValueError):
            owner_valid_until("UNKNOWN", "3", "", now=NOW)
        with self.assertRaises(ValueError):
            owner_valid_until("PRO", "12", "", now=NOW,
                              existing_end=datetime(2027, 2, 1),
                              extend=True)

    def test_service_calendar_dst_keeps_exclusive_local_midnight(self):
        self.assertEqual(
            service_valid_until(
                "CALENDAR", "2026-11-15", now=NOW
            ).astimezone(__import__("zoneinfo").ZoneInfo("Europe/Warsaw")).strftime("%Y-%m-%d %H:%M"),
            "2026-11-16 00:00",
        )

class GridSavePlanningTests(unittest.TestCase):
    """No SQL, KeyGate or remote calls in the Save decision engine."""

    def plan(self, **overrides):
        args = dict(
            current_mode="CLIENT", current_edition="PRO",
            target_edition="PRO", term_choice="KEEP", term_date="",
            now=NOW, paid_valid_until=LATER,
        )
        args.update(overrides)
        return plan_grid_license_change(**args)

    def test_existing_licence_keep_means_no_operation(self):
        result = self.plan()
        self.assertEqual(result["action"], "NONE")
        self.assertEqual(result["valid_until"], LATER)

    def test_paid_edition_change_preserves_keygate_expiry(self):
        result = self.plan(target_edition="STANDARD")
        self.assertEqual(result["action"], "PAID_EDITION")
        self.assertEqual(result["valid_until"], LATER)

    def test_paid_extension_adds_to_existing_term_not_current_date(self):
        old = datetime(2026, 12, 30, 16, tzinfo=timezone.utc)
        result = self.plan(
            paid_valid_until=old, term_choice="12",
        )
        self.assertEqual(result["action"], "PAID_EXTEND")
        self.assertEqual(result["valid_until"],
                         datetime(2027, 12, 30, 16, tzinfo=timezone.utc))

    def test_client_to_service_requires_explicit_term(self):
        with self.assertRaises(ValueError):
            self.plan(target_edition="SERVICE")
        result = self.plan(target_edition="SERVICE", term_choice="PERPETUAL")
        self.assertEqual(result["action"], "ENTER_SERVICE")
        self.assertEqual(result["mode"], "SERVICE")
        self.assertIsNone(result["valid_until"])

    def test_service_calendar_is_local_end_of_day(self):
        result = self.plan(
            target_edition="SERVICE",
            term_choice="CALENDAR", term_date="2026-11-15",
        )
        self.assertEqual(result["valid_until"],
                         calendar_valid_until(date(2026, 11, 15), now=NOW))

    def test_service_change_does_not_modify_paid_term(self):
        result = self.plan(
            current_mode="SERVICE", current_edition="SERVICE",
            target_edition="SERVICE", term_choice="3",
            service_valid_until_current=LATER,
        )
        self.assertEqual(result["action"], "SERVICE_TERM")
        self.assertEqual(result["valid_until"],
                         datetime(2027, 1, 30, 16, tzinfo=timezone.utc))
        self.assertEqual(self.plan(
            current_mode="SERVICE", current_edition="SERVICE",
            target_edition="SERVICE", term_choice="KEEP",
            service_valid_until_current=LATER,
        )["valid_until"], LATER)

    def test_return_to_paid_does_not_change_paid_expiry(self):
        result = self.plan(
            current_mode="SERVICE", current_edition="SERVICE",
            target_edition="PRO", term_choice="KEEP",
            paid_edition="PRO",
        )
        self.assertEqual(result["action"], "RESTORE_PAID")
        self.assertEqual(result["valid_until"], LATER)
        with self.assertRaisesRegex(ValueError, "original paid"):
            self.plan(
                current_mode="SERVICE", current_edition="SERVICE",
                target_edition="STANDARD", term_choice="KEEP",
                paid_edition="PRO",
            )

    def test_paid_perpetual_requires_keygate_capability(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.plan(term_choice="PERPETUAL")
        result = self.plan(
            term_choice="PERPETUAL",
            explicit_paid_perpetual_supported=True,
        )
        self.assertEqual(result["action"], "PAID_PERPETUAL")
        self.assertIsNone(result["valid_until"])

    def test_date_picker_and_paid_change_edition_are_independent(self):
        with self.assertRaises(ValueError):
            self.plan(target_edition="STANDARD", term_choice="12")
        result = self.plan(
            term_choice="CALENDAR", term_date="2026-11-15",
        )
        self.assertEqual(result["action"], "PAID_CALENDAR")
        self.assertEqual(result["valid_until"],
                         calendar_valid_until(date(2026, 11, 15), now=NOW))

    def test_invalid_or_stale_inputs_fail_before_mutations(self):
        cases = (
            dict(current_mode="NONE"),
            dict(current_mode="SERVICE", current_edition="PRO"),
            dict(current_edition="SERVICE"),
            dict(target_edition="INVALID"),
            dict(term_choice="KEEP", term_date="2026-11-15"),
            dict(target_edition="SERVICE", term_choice="3",
                 term_date="2026-11-15"),
            dict(term_choice="12", paid_valid_until=EARLIER),
        )
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.plan(**options)




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


class IntegrationSourceSafetyTests(unittest.TestCase):
    """Guardrails against exposing partial live conversion or mutating KeyGate."""

    @classmethod
    def setUpClass(cls):
        import ast
        root = Path(__file__).resolve().parents[1]
        cls.license_source = (root / "app/routers/multiguard_license.py").read_text()
        cls.remote_source = (root / "app/routers/multiguard_remote.py").read_text()
        cls.tree = ast.parse(cls.license_source)

    def find_function(self, name):
        import ast
        return next(n for n in self.tree.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name == name)

    def test_owner_service_term_is_never_written_as_unconditional_null(self):
        import ast
        fn = self.find_function("_owner_select_effective_mode")
        body = ast.get_source_segment(self.license_source, fn)
        self.assertIn("service_valid_until(", body)
        self.assertIn("valid_until=EXCLUDED.valid_until", body)
        self.assertIn('"service_end": service_end', body)
        self.assertNotIn("edition='PRO',enabled=TRUE,valid_until=NULL", body)

    def test_mode_route_requires_term_fields_and_remains_flag_gated(self):
        import ast
        fn = self.find_function("panel_owner_select_effective_mode")
        body = ast.get_source_segment(self.license_source, fn)
        self.assertIn("service_term_choice", body)
        self.assertIn("service_term_date", body)
        self.assertIn("MULTIGUARD_MODE_SWITCH_ENABLED", body)

    def test_owner_mode_switch_never_calls_keygate_mutators(self):
        import ast
        func = self.find_function("_owner_select_effective_mode")
        calls = [n.func.id for n in ast.walk(func)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        self.assertFalse(any(x.startswith("_keygate") for x in calls))
        self.assertNotIn("_set_workshop_grant", calls)

    def test_owner_route_stays_disabled_by_default(self):
        import ast
        fn = self.find_function("panel_owner_select_effective_mode")
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_setting"]
        self.assertEqual(len(calls), 1)
        self.assertEqual([x.value for x in calls[0].args], [
            "MULTIGUARD_MODE_SWITCH_ENABLED", "false"
        ])

    def test_owner_mode_requires_remote_session_shutdown(self):
        fn = self.find_function("_owner_select_effective_mode")
        import ast
        body = ast.get_source_segment(self.license_source, fn)
        self.assertIn("guard.remote_sessions", body)
        self.assertIn("guard.workshop_remote_sessions", body)
        self.assertIn("mesh_public_id IS NOT NULL", body)
        self.assertIn("owner_license_mode_transitions", body)

    def test_paid_refresh_checks_selection_before_keygate_get(self):
        import ast
        fn = self.find_function("refresh")
        body = ast.get_source_segment(self.license_source, fn)
        self.assertLess(body.index("_owner_effective_entitlement_mode"),
                        body.index("_keygate_license"))

    def test_paid_remote_verifies_client_mode_and_never_unattended(self):
        self.assertIn(') != "CLIENT":', self.remote_source)
        self.assertIn('def _has_verified_service_remote_pro', self.remote_source)
        self.assertIn('return False', self.remote_source)


class CompactGridPickerTests(unittest.TestCase):
    """Compact OWNER dropdown must expose independent options without silent mutation."""

    @classmethod
    def setUpClass(cls):
        import ast
        root = Path(__file__).resolve().parents[1]
        cls.source = (root / "app/routers/multiguard_license.py").read_text()
        cls.tree = ast.parse(cls.source)

    def function_source(self, name):
        import ast
        fn = next(node for node in self.tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == name)
        return ast.get_source_segment(self.source, fn)

    def test_three_editions_in_small_dropdown(self):
        body = self.function_source("panel_licenses_grid")
        for value in ("STANDARD", "PRO", "SERVICE"):
            self.assertIn(f'<option value="{value}"', body)
        self.assertIn("mg-grid-edition", body)

    def test_duration_menu_includes_months_calendar_and_perpetual(self):
        body = self.function_source("panel_licenses_grid")
        for value in ("3", "6", "12", "CALENDAR", "PERPETUAL"):
            self.assertIn(f'<option value="{value}"', body)
        self.assertIn('type="date"', body)
        self.assertIn("class=\"mg-grid-term-picker\"", body)
        self.assertIn("chosenDate.hidden=!calendar", body)

    def test_unwired_period_cannot_be_silently_saved(self):
        body = self.function_source("panel_grid_save")
        self.assertIn('term_edit_preview == "1"', body)
        self.assertIn('choice != "KEEP"', body)
        self.assertIn('raise HTTPException(409', body)


class WorkshopRemoteSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import ast
        root = Path(__file__).resolve().parents[1]
        cls.source = (root / "app/routers/multiguard_workshop_remote.py").read_text()
        cls.tree = ast.parse(cls.source)
        f = next(x for x in cls.tree.body
                 if isinstance(x, ast.FunctionDef)
                 and x.name == "remote_entitlement_mode")
        namespace = {}
        exec(compile(ast.Module(body=[f], type_ignores=[]),
                     "<workshop-mode-policy>", "exec"), namespace)
        cls.evaluate = staticmethod(namespace["remote_entitlement_mode"])

    def grant(self, **overrides):
        value = dict(
            status="PROVISIONED", enabled=True, edition="PRO",
            owner_mode="SERVICE",
        )
        value.update(overrides)
        return value

    def test_owner_explicit_service_can_coexist_with_paid_status(self):
        self.assertEqual(self.evaluate(self.grant()), "SERVICE_PRO")

    def test_customer_mode_never_uses_unattended_service(self):
        self.assertEqual(self.evaluate(self.grant(owner_mode="CLIENT")),
                         "CUSTOMER_LICENSE")

    def test_disabled_service_is_never_authorized(self):
        self.assertEqual(self.evaluate(self.grant(enabled=False)),
                         "SERVICE_DISABLED")

    def test_uninstalled_or_archived_installation_is_denied(self):
        self.assertEqual(self.evaluate(self.grant(status="ARCHIVED")),
                         "INACTIVE_INSTALLATION")
        self.assertEqual(self.evaluate(self.grant(status="UNINSTALLED")),
                         "INACTIVE_INSTALLATION")

    def test_standard_service_cannot_use_pro_remote(self):
        self.assertEqual(self.evaluate(self.grant(edition="STANDARD")),
                         "SERVICE_STANDARD")

    def test_grant_sql_checks_expiry_and_owner_mode(self):
        f = next(x for x in self.tree.body
                 if isinstance(x, __import__("ast").FunctionDef)
                 and x.name == "_grant")
        fragment = __import__("ast").get_source_segment(self.source, f)
        self.assertIn("g.valid_until > now()", fragment)
        self.assertIn("owner_entitlement_selections", fragment)
        self.assertIn("'CLIENT' ELSE 'SERVICE'", fragment)


if __name__ == "__main__":
    unittest.main()
