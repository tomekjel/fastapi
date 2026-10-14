"""Offline tests: do not contact MeshCentral or provision production nodes."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as mesh


class AutomaticMeshBinding(unittest.TestCase):
    VALID = "node//" + "A" * 64
    OTHER = "node//" + "B" * 64

    def run_verify(self, payload, candidate):
        with patch.object(mesh, "_base_command", return_value=[
            "node", "/private/meshctrl.js", "DeviceSharing",
            "--url", "wss://mesh.example.test", "--loginuser", "OWNER",
        ]), patch.object(mesh, "_run", return_value=payload) as run:
            found = mesh.verify_registered_node(candidate)
        run.assert_called_once()
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[2], "ListDevices")
        self.assertEqual(cmd[-1], "--json")
        return found

    def test_matches_exact_node_from_meshcentral(self):
        self.assertTrue(self.run_verify(json.dumps([
            {"_id": self.VALID, "name": "Lenovo"},
            {"_id": self.OTHER, "name": "ASUS"}
        ]), self.VALID))

    def test_does_not_match_hostname_or_another_node(self):
        self.assertFalse(self.run_verify(json.dumps([
            {"_id": self.OTHER, "name": "Multi-Servis Lenovo"}
        ]), self.VALID))

    def test_grouped_meshctrl_json(self):
        payload = {"mesh//test": {"devices": [{ "_id": self.VALID }]}}
        self.assertTrue(self.run_verify(json.dumps(payload), self.VALID))

    def test_invalid_identity_skips_meshcentral_request(self):
        with patch.object(mesh, "_run") as run:
            self.assertFalse(mesh.verify_registered_node("node//" + "Z" * 63))
            self.assertFalse(mesh.verify_registered_node("node//" + "A" * 63 + "!"))
        run.assert_not_called()

    def test_broken_response_fails_closed(self):
        with patch.object(mesh, "_base_command", return_value=[
            "node", "/private/meshctrl.js", "DeviceSharing"
        ]), patch.object(mesh, "_run", return_value="not-json"):
            with self.assertRaises(mesh.MeshCentralError):
                mesh.verify_registered_node(self.VALID)


if __name__ == "__main__":
    unittest.main()
