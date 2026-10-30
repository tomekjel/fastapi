"""Source-only compatibility regression for the surgical V4.4 overlay.

No database, network, KeyGate, MeshCentral, or service restart is used.
The fixture mimics the older installed backend by removing already integrated
code from the prepared GitHub branch. Production SHA/anchor checks remain
strict and can abort safely if any live file differs.
"""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stage_owner_license_modes_v44.py"
SPEC = importlib.util.spec_from_file_location("owner_v44_overlay", SCRIPT)
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)

LICENSE = (ROOT / "app/routers/multiguard_license.py").read_text()
WORKSHOP = (ROOT / "app/routers/multiguard_workshop_remote.py").read_text()


def without_func(source, name):
    start,end = overlay.locate_function(source,name,decorators=True)
    lines = source.splitlines(keepends=True)
    return "".join(lines[:start-1]+lines[end:])


def prepared_old_license_fixture():
    source = LICENSE
    for name in ("panel_owner_select_effective_mode",
                 "_owner_select_effective_mode",
                 "_owner_effective_entitlement_mode"):
        source = without_func(source, name)
    old_refresh = overlay.get_function(source,"refresh")
    service_guard = """    # Do not let an older paid refresh overwrite a signed OWNER workshop lease.
    with engine.connect() as mode_con:
        if _owner_effective_entitlement_mode(mode_con, link["installation_id"]) == "SERVICE":
            raise HTTPException(409, "Właściciel wybrał tryb serwisowy.")
"""
    assert old_refresh.count(service_guard) == 1
    # Rebuild the historical source *before* the new transactional lock
    # checks. This overlay test validates migration from that older shape;
    # production refresh/acceptance retain stronger OWNER rechecks.
    old_refresh = old_refresh.replace(service_guard, "")
    begin = old_refresh.index(
        "        # The OWNER mode changer locks pending_installations FIRST")
    end = old_refresh.index("        row = connection.execute(", begin)
    old_refresh = old_refresh[:begin] + old_refresh[end:]
    source = overlay.replace_function(source,"refresh",old_refresh)
    discovery = overlay.get_function(source,"discovery_assignment")
    first = discovery.find("    # Explicit OWNER service mode takes precedence")
    if first < 0:
        first = discovery.index("    # OWNER mode changes lock pending_installations")
    last = discovery.index('    reception_id = pending.get("assigned_reception_id")',first)
    discovery = discovery[:first] + discovery[last:]
    source = overlay.replace_function(source,"discovery_assignment",discovery)
    assert source.count("def panel_grid_save(") == 1
    source = source.replace("def panel_grid_save(", "def panel_grid_save_row(",1)
    ast.parse(source)
    return source


class OverlayTest(unittest.TestCase):
    def test_only_nullable_transition_metadata_is_added(self):
        columns = {"id", "installation_id", "license_link_id", "source_mode",
                   "target_mode", "state", "created_at", "updated_at"}
        self.assertEqual(
            overlay.safe_missing_transition_columns(columns),
            ("target_valid_until", "reason", "last_error"),
        )
        self.assertEqual(
            overlay.safe_missing_transition_columns(
                columns | {"target_valid_until", "reason", "last_error"}
            ), (),
        )
        self.assertEqual(
            overlay.safe_missing_transition_columns(
                columns | {"target_valid_until", "last_error"}
            ), ("reason",),
        )

    def test_unknown_missing_ledger_fields_are_rejected(self):
        valid = {"id", "installation_id", "license_link_id", "source_mode",
                 "target_mode", "target_valid_until", "state", "reason",
                 "created_at", "updated_at", "last_error"}
        with self.assertRaisesRegex(RuntimeError, "missing required columns: state"):
            overlay.safe_missing_transition_columns(valid - {"state"})

    def test_sql_migration_is_bounded_and_non_destructive(self):
        source = SCRIPT.read_text()
        self.assertIn("SET LOCAL lock_timeout = '3s'", source)
        self.assertIn("ADD COLUMN IF NOT EXISTS", source)
        self.assertIn("with engine.begin() as c:", source)
        self.assertNotIn("DROP TABLE guard.owner_license_mode_transitions", source)
        self.assertNotIn("DELETE FROM guard.owner_license_mode_transitions", source)

    def test_protected_baseline_accepts_only_unauthenticated_or_forbidden(self):
        script = SCRIPT.read_text()
        self.assertIn("if baseline not in (401, 403):", script)
        self.assertIn("if now_status == previous_status:", script)
        self.assertIn('["systemctl","is-active","--quiet","multiservis-api.service"]', script)

    def test_production_shape_insertion_compiles_without_router_collision(self):
        source = overlay.produce_license(prepared_old_license_fixture(),LICENSE)
        ast.parse(source)
        self.assertEqual(source.count("def _owner_effective_entitlement_mode("),1)
        self.assertEqual(source.count("def _owner_select_effective_mode("),1)
        self.assertEqual(source.count("def panel_owner_select_effective_mode("),1)
        self.assertEqual(source.count("def panel_grid_save_row("),1)
        self.assertIn("STAGE2 HARD STOP",source)
        self.assertIn("selected_mode == \"SERVICE\"",source)
        self.assertIn("if _owner_effective_entitlement_mode(mode_con",source)

    def test_overlay_fails_closed_on_unexpected_function_or_anchor(self):
        with self.assertRaises(RuntimeError):
            overlay.produce_license(LICENSE,LICENSE)
        with self.assertRaises(RuntimeError):
            overlay.produce_license(
                prepared_old_license_fixture().replace(
                    '    reception_id = pending.get("assigned_reception_id")',
                    '    reception_id = None',1),
                LICENSE,
            )

    def test_workshop_mode_switch_is_customer_first(self):
        source = overlay.produce_workshop(WORKSHOP,WORKSHOP)
        ast.parse(source)
        self.assertIn("p.status IN ('ASSIGNED','PROVISIONED')",source)
        self.assertIn('grant.get("owner_mode") != "SERVICE"',source)


if __name__ == "__main__":
    unittest.main()
