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


    def test_lost_response_reconciles_from_empty_server_list(self):
        calls = []
        def simulate_run(args):
            calls.append(args)
            if "--remove" in args:
                raise meshcentral.MeshCentralError("lost response")
            return "No device sharing links for this device."
        with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
             patch.object(meshcentral, "_run", side_effect=simulate_run):
            meshcentral.revoke_share("node/example/device", "old-id")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][-2:], ["--id", "node/example/device"])

    def test_lost_response_reconciles_when_other_shares_exist(self):
        listing = (
            "----------\nIdentifier:   another-id\nType: Desktop\n"
            "UserId: demo\nGuest Name: Operator\nUser Consent: Desktop Notify\n"
            "URL: https://mesh.example/share/another\n"
            "----------\nIdentifier:   third-id\nType: Files\n"
            "UserId: demo\nGuest Name: Operator\nUser Consent: Files Notify\n"
            "URL: https://mesh.example/share/third\n"
        )
        with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
             patch.object(meshcentral, "_run",
                          side_effect=["Invalid device share identifier.", listing]):
            meshcentral.revoke_share("node/example/device", "old-id")

    def test_lost_response_does_not_close_if_link_still_listed(self):
        listing = (
            "----------\nIdentifier:   old-id\nType: Desktop\n"
            "UserId: demo\nGuest Name: Operator\nUser Consent: Desktop Notify\n"
            "URL: https://mesh.example/share/old\n"
        )
        with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
             patch.object(meshcentral, "_run", side_effect=["NOT OK", listing]):
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.revoke_share("node/example/device", "old-id")

    def test_unknown_or_partial_server_list_never_confirms_removal(self):
        invalid = (
            "", "Access denied", "No links", "Unknown device",
            "----------\nInvalid entry",
            "----------\nIdentifier: other\n----------\nMissing entry",
            "No device sharing links for this device.\nUnexpected output",
            # A final entry truncated after Identifier must never imply absence.
            "----------\nIdentifier: another\nType: Desktop\n",
            # All mandatory fields present, but the URL (the last line in
            # upstream MeshCtrl's share output) is missing.
            "----------\nIdentifier: another\nType: Desktop\n"
            "UserId: demo\nGuest Name: Test\nUser Consent: Desktop Notify\n",
            # A complete first entry followed by a truncated second entry
            # must not be accepted as a complete server-side list.
            "----------\nIdentifier: another\nType: Desktop\n"
            "UserId: demo\nGuest Name: Test\nUser Consent: Desktop Notify\n"
            "URL: https://mesh.example/share/another\n"
            "----------\nIdentifier: old-id\nType: Desktop\n",
        )
        for listing in invalid:
            with self.subTest(listing=listing):
                with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
                     patch.object(meshcentral, "_run", side_effect=["", listing]):
                    with self.assertRaises(meshcentral.MeshCentralError):
                        meshcentral.revoke_share("node/example/device", "old-id")

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
