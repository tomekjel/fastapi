"""Source-level guard for all remote rights transitions; no DB/host access."""
import ast
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1] / "app" / "routers"


def source_of(path,name):
    src=(ROOT / path).read_text(encoding="utf-8")
    tree=ast.parse(src)
    fn=next(node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==name)
    return ast.get_source_segment(src,fn)


class StandingRemoteRightsChanges(unittest.TestCase):
    def test_all_service_pro_downgrades_and_paid_conversions_revoke_old_access(self):
        for name in ("_set_workshop_grant","_assign_pending_to_reception",
                     "_assign_direct_customer_license",
                     "owner_change_workshop_edition","owner_disable_workshop"):
            with self.subTest(name=name):
                src=source_of("multiguard_license.py",name)
                self.assertIn("workshop.close_before_rights_change(",src)

    def test_revocation_is_part_of_same_transaction_as_service_rights_change(self):
        src=source_of("multiguard_workshop_remote.py","close_before_rights_change")
        self.assertIn("_open(db, iid, entitlement_lost=True)",src)
        self.assertIn('invalidate_standing_authorization(db,iid,"SERVICE_RIGHTS_CHANGED")',src)

    def test_revocation_is_owner_authenticated_and_csrf_protected(self):
        src=source_of("multiguard_remote.py","panel_owner_revoke_standing_remote_authorization")
        self.assertIn("Depends(_panel_auth)",src)
        self.assertIn("Depends(_owner_panel_csrf)",src)
        ui=source_of("multiguard_remote.py","owner_workshop_workspace")
        self.assertIn('id="ws-revoke"',ui)
        self.assertIn("window.confirm('Cofnąć",ui)
        self.assertIn("'/multiguard/panel/remote-api/standing/'",ui)

    def test_missing_independent_authorization_cannot_open_unattended_share(self):
        # Until local device attestation, standing proof enrollment and
        # production MeshCentral groups exist, NO bypass is allowed.
        src=source_of("multiguard_workshop_remote.py","request_for_owner")
        self.assertIn("raise HTTPException(",src)
        share=source_of("multiguard_meshcentral.py","create_workshop_share")
        self.assertIn("raise MeshCentralError(",share)


if __name__=="__main__":
    unittest.main()
