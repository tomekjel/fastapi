"""Regression guard for MASTER 1.10 Mesh sync diagnostic contract.

Pure source verification: no DB connections, CLI calls, API requests or state changes.
"""
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name("master15_owner_mesh_sync_engine.py").read_text(encoding="utf-8")

class MeshFailureReasonTests(unittest.TestCase):
    def test_known_internal_failure_codes_are_preserved(self):
        self.assertIn("except MeshSyncError as exc:", SOURCE)
        self.assertIn("issue=str(exc)[:180]", SOURCE)
        for reason in (
            "MESH_NODE_ID_NOT_LINKED",
            "MESH_NODE_NOT_VISIBLE",
            "MESH_NODE_MISSING_AFTER_MOVE",
            "MESH_GROUP_NOT_CONFIRMED",
        ):
            self.assertIn(reason, SOURCE)

    def test_unknown_external_errors_do_not_leak_secrets(self):
        self.assertIn("except Exception as exc:", SOURCE)
        self.assertIn("issue=type(exc).__name__", SOURCE)

    def test_requeue_after_verified_registration_is_scoped(self):
        self.assertIn("def requeue_after_verified_mesh_registration(", SOURCE)
        self.assertIn("if registered != node_id:", SOURCE)
        self.assertIn("WHERE installation_id=:iid", SOURCE)
        self.assertIn("AND status='RETRY'", SOURCE)
        self.assertIn("requested_group IN ('CLIENT','SERVICE')", SOURCE)
        self.assertIn("SET status='WAITING', attempts=0, revision=revision+1", SOURCE)

    def test_sync_reuses_paid_registration_not_only_workshop_registration(self):
        self.assertIn("COALESCE(i.mesh_node_id,n.mesh_node_id) AS mesh_node_id", SOURCE)
        self.assertIn("i.installation_external_id=s.installation_id", SOURCE)
        self.assertIn("WHERE i.installation_external_id=:iid", SOURCE)

    def test_no_fake_success_when_registration_is_missing(self):
        self.assertIn("if not current.mesh_node_id:", SOURCE)
        self.assertIn('raise MeshSyncError("MESH_NODE_ID_NOT_LINKED")', SOURCE)
        self.assertIn("ok=seen==current.target_mesh_id", SOURCE)

if __name__ == "__main__":
    unittest.main()
