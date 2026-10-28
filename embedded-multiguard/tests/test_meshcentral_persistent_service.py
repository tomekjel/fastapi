"""Offline: Windows service agent node checks; no real MeshCentral access."""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as mesh

NODE = "A" * 64
SESSION = "cc3c6623-92c0-4a0c-a9e9-a94b581a0cdd"
GROUP = "mesh//" + "B" * 64

class NativeScmAgentIdentity(unittest.TestCase):
    def check(self, records, *, persistent=True, name="Lenovo", connection=1):
        device = {"_id": "node//" + NODE, "meshid": GROUP,
                  "name": name, "conn": connection}
        if records is None:
            records = [device]
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": GROUP}), \
             patch.object(mesh, "_base_command", return_value=[
                "node", "/private/meshctrl.js", "DeviceSharing"]), \
             patch.object(mesh, "_run", return_value=json.dumps(records)) as execute:
            result=mesh.verify_session_node(NODE, SESSION, persistent_service=persistent)
            execute.assert_called_once()
            return result

    def test_verified_persistent_windows_service_does_not_need_session_name(self):
        self.assertEqual(self.check(None), "node//" + NODE)

    def test_old_session_process_check_requires_matching_ephemeral_name(self):
        with self.assertRaises(mesh.MeshCentralError):
            self.check(None, persistent=False)
        self.assertEqual(self.check(None, persistent=False, name="MultiGuard-" + SESSION),
                         "node//" + NODE)

    def test_stopped_and_foreign_group_agents_are_refused(self):
        with self.assertRaises(mesh.MeshCentralError):
            self.check(None, connection=0)
        foreign = [{"_id": "node//"+NODE, "meshid": "mesh//"+"C"*64,
                    "name":"Lenovo","conn":1}]
        with self.assertRaises(mesh.MeshCentralError):
            self.check(foreign)

    def test_duplicate_and_spoofed_node_identifiers_are_refused(self):
        device={"_id":"node//"+NODE, "meshid":GROUP, "name":"Lenovo","conn":1}
        with self.assertRaises(mesh.MeshCentralError):
            self.check([device, dict(device)])
        with self.assertRaises(mesh.MeshCentralError):
            self.check([{"_id":"node//"+("D"*64), "meshid":GROUP, "name":"Lenovo","conn":1}])
        with self.assertRaises(mesh.MeshCentralError):
            self.check(None, name="")

if __name__ == "__main__":
    unittest.main()
