import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).with_name("master15_owner_mesh_group_policy.py")
spec = importlib.util.spec_from_file_location("mg_mesh_policy", path)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class Policy(unittest.TestCase):
    def test_exact_three_existing_groups(self):
        self.assertEqual(set(module.GROUP_ENV.values()), {
            "MESH_CENTRAL_SESSION_CONSENT_MESH_ID",
            "MESH_STANDARD_GROUP_ID",
            "MESH_SERVICE_PRO_GROUP_ID"
        })
        self.assertEqual(module.resolve_edition("CLIENT","multi_guard_pro"), module.Group.CLIENT)
        self.assertEqual(module.resolve_edition("SERVICE","multi_guard"), module.Group.SERVICE)
        self.assertEqual(module.resolve_edition("CLIENT","multi_guard"),module.Group.STANDARD)
    def test_standard_requires_verified_windows_disabled_and_exact_group(self):
        standard="mesh/x/"+"a"*64
        self.assertEqual(module.status_after_verified_probe(
            target_id=standard,observed_group_id=standard,
            attempts=0,move_pending=False,mesh_agent_present=False,
            standard_target=True,windows_disabled_verified=False),module.SyncState.WAITING)
        self.assertEqual(module.status_after_verified_probe(
            target_id=standard,observed_group_id=standard,
            attempts=0,move_pending=False,mesh_agent_present=True,
            standard_target=True,windows_disabled_verified=False),module.SyncState.WAITING)
        self.assertEqual(module.status_after_verified_probe(
            target_id=standard,observed_group_id=standard,
            attempts=0,move_pending=False,mesh_agent_present=True,
            standard_target=True,windows_disabled_verified=True),module.SyncState.OK)
        self.assertEqual(module.status_after_verified_probe(
            target_id=standard,observed_group_id="mesh/x/"+"b"*64,
            attempts=3,move_pending=False,standard_target=True,
            windows_disabled_verified=True),module.SyncState.RETRY)
    def test_no_fabricated_ok(self):
        self.assertEqual(module.status_after_verified_probe(target_id="mesh/x/"+"a"*64,
             observed_group_id="mesh/x/"+"b"*64,attempts=3,move_pending=False),module.SyncState.RETRY)
        self.assertEqual(module.status_after_verified_probe(target_id="mesh/x/"+"a"*64,
             observed_group_id=None,attempts=0,move_pending=True),module.SyncState.MOVING)
        self.assertEqual(module.status_after_verified_probe(target_id="mesh/x/"+"a"*64,
             observed_group_id="mesh/x/"+"a"*64,attempts=0,move_pending=False),module.SyncState.OK)
    def test_groups_distinct_and_required(self):
        env={
            "MESH_CENTRAL_SESSION_CONSENT_MESH_ID":"mesh//"+"a"*64,
            "MESH_SERVICE_PRO_GROUP_ID":"mesh//"+"b"*64,
            "MESH_STANDARD_GROUP_ID":"mesh//"+"c"*64,
        }
        self.assertEqual(len(module.validate_groups(env)),3)
        env["MESH_SERVICE_PRO_GROUP_ID"]=env["MESH_CENTRAL_SESSION_CONSENT_MESH_ID"]
        with self.assertRaises(ValueError):module.validate_groups(env)
    def test_live_mesh_device_list_fields(self):
        node="node//"+"a"*64
        group="mesh//"+"b"*64
        self.assertEqual(module.observed_group_for_node([
            {"_id":node, "meshid":group, "groupname":"Klient"}],node),(True,group))
        self.assertEqual(module.observed_group_for_node([],node),(False,None))
        with self.assertRaises(ValueError):
            module.observed_group_for_node([{"_id":node,"meshid":group},
                                            {"_id":node,"meshid":group}],node)
        with self.assertRaises(ValueError):
            module.observed_group_for_node([{"_id":node,"groupname":"Klient"}],node)
    def test_retry_limit(self):
        self.assertTrue(module.should_retry(2,False))
        self.assertFalse(module.should_retry(3,False))
        self.assertTrue(module.should_retry(3,True))

if __name__=="__main__":
    unittest.main()
