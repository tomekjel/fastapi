"""Fast, offline MeshCtrl adapter safety checks (no server or database)."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as meshcentral


class MeshCentralRevocationTests(unittest.TestCase):
    def test_explicit_success_only(self):
        for output in ("OK", "ok", " \nOK\n "):
            with self.subTest(output=output):
                with patch.object(meshcentral, "_base_command",
                                  return_value=["node", "meshctrl", "DeviceSharing"]), \
                     patch.object(meshcentral, "_run", return_value=output) as run:
                    meshcentral.revoke_share("node/test/device", "test-share-id")
                    self.assertEqual(
                        run.call_args.args[0][-4:],
                        ["--id", "node/test/device", "--remove", "test-share-id"],
                    )

    def test_unknown_or_negative_response_never_closes_session(self):
        for output in ("", " ", "NOT OK", "Permission denied",
                       "Invalid device share identifier.", "OK but not removed",
                       "False: OK"):
            with self.subTest(output=output):
                with patch.object(meshcentral, "_base_command",
                                  return_value=["node", "meshctrl", "DeviceSharing"]), \
                     patch.object(meshcentral, "_run", return_value=output):
                    with self.assertRaises(meshcentral.MeshCentralError):
                        meshcentral.revoke_share("node/test/device", "test-share-id")

    def test_missing_ids_are_fail_closed(self):
        with patch.object(meshcentral, "_base_command") as cmd:
            for node_id, public_id in (("", "test"), ("node/test/device", ""),
                                       ("  ", "test"), ("node/test/device", "   ")):
                with self.subTest(node_id=node_id, public_id=public_id):
                    with self.assertRaises(meshcentral.MeshCentralError):
                        meshcentral.revoke_share(node_id, public_id)
            cmd.assert_not_called()

    def test_nonzero_meshctrl_exit_is_failure_even_if_output_says_ok(self):
        process = subprocess.CompletedProcess(
            args=["node", "meshctrl", "DeviceSharing"], returncode=1,
            stdout="OK\n", stderr="",
        )
        with patch.object(meshcentral.subprocess, "run", return_value=process):
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral._run(["node", "meshctrl", "DeviceSharing"])


if __name__ == "__main__":
    unittest.main()
