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
    source = overlay.replace_function(source,"refresh",old_refresh.replace(service_guard,""))
    discovery = overlay.get_function(source,"discovery_assignment")
    first = discovery.index("    # Explicit OWNER service mode takes precedence")
    last = discovery.index('    reception_id = pending.get("assigned_reception_id")',first)
    discovery = discovery[:first] + discovery[last:]
    source = overlay.replace_function(source,"discovery_assignment",discovery)
    assert source.count("def panel_grid_save(") == 1
    source = source.replace("def panel_grid_save(", "def panel_grid_save_row(",1)
    ast.parse(source)
    return source


class OverlayTest(unittest.TestCase):
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
