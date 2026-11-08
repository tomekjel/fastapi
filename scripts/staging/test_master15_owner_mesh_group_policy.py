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
    def test_exact_two_existing_groups(self):
        self.assertEqual(set(module.GROUP_ENV.values()), {
            "MESH_CENTRAL_SESSION_CONSENT_MESH_ID",
            "MESH_SERVICE_PRO_GROUP_ID"
        })
        self.assertEqual(module.resolve_edition("CLIENT","multi_guard_pro"), module.Group.CLIENT)
        self.assertEqual(module.resolve_edition("SERVICE","multi_guard"), module.Group.SERVICE)
        self.assertIsNone(module.resolve_edition("CLIENT","multi_guard"))
    def test_standard_requires_no_remote_agent(self):
        self.assertEqual(module.status_after_verified_probe(target_id=None, observed_group_id=None,
             attempts=0,move_pending=False,mesh_agent_present=True), module.SyncState.WAITING)
        self.assertEqual(module.status_after_verified_probe(target_id=None, observed_group_id=None,
             attempts=0,move_pending=False,mesh_agent_present=False), module.SyncState.OK)
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
        }
        self.assertEqual(len(module.validate_groups(env)),2)
        env["MESH_SERVICE_PRO_GROUP_ID"]=env["MESH_CENTRAL_SESSION_CONSENT_MESH_ID"]
        with self.assertRaises(ValueError):module.validate_groups(env)
    def test_retry_limit(self):
        self.assertTrue(module.should_retry(2,False))
        self.assertFalse(module.should_retry(3,False))
        self.assertTrue(module.should_retry(3,True))

if __name__=="__main__":
    unittest.main()
