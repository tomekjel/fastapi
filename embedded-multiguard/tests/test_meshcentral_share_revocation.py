"""Fast, offline MeshCtrl adapter safety checks (no server or database)."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as meshcentral


class MeshCentralRevocationTests(unittest.TestCase):
    def test_session_node_uses_separate_group_only_when_single_prompt_enabled(self):
        import json

        legacy = "mesh/d/" + "L" * 64
        approved = "mesh/d/" + "S" * 64
        local_id = "A" * 64
        session_id = "00000000-0000-4000-8000-000000000001"
        device = {"_id": "node/d/" + local_id,
                  "meshid": legacy, "name": "MultiGuard-existing",
                  "conn": 1}

        def list_devices(command):
            self.assertIn("ListDevices", command)
            return json.dumps([device])

        with patch.dict(os.environ, {
            "MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": legacy,
            "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": approved,
        }), patch.object(meshcentral, "_base_command",
                        return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(meshcentral, "_run", side_effect=list_devices):
            self.assertEqual(meshcentral.verify_session_node(
                local_id, session_id, persistent_service=True),
                "node/d/" + local_id)
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_node(
                    local_id, session_id, persistent_service=True,
                    single_prompt=True)
            device["meshid"] = approved
            self.assertEqual(meshcentral.verify_session_node(
                local_id, session_id, persistent_service=True,
                single_prompt=True), "node/d/" + local_id)
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_node(
                    local_id, session_id, persistent_service=True)

    def test_client_approved_share_requires_attestation_and_exact_online_node(self):
        args = ("node/d/" + "A"*64, "00000000-0000-4000-8000-000000000001",
                "owner", ("desktop",), 60)
        with patch.dict(os.environ, {"MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED": "0"}), \
             patch.object(meshcentral, "create_share", return_value="fallback") as fallback, \
             patch.object(meshcentral, "verify_session_node") as verify, \
             patch.object(meshcentral, "_create_share") as direct:
            self.assertEqual(meshcentral.create_client_approved_share(*args), "fallback")
            fallback.assert_called_once()
            verify.assert_not_called()
            direct.assert_not_called()
        with patch.dict(os.environ, {"MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED": "1"}), \
             patch.object(meshcentral, "create_share", return_value="fallback") as fallback, \
             patch.object(meshcentral, "verify_session_node", return_value=args[0]) as verify, \
             patch.object(meshcentral, "verify_session_share_policy") as policy, \
             patch.object(meshcentral, "_create_share", return_value="approved") as direct:
            self.assertEqual(meshcentral.create_client_approved_share(*args), "approved")
            verify.assert_called_once_with("A"*64, args[1], persistent_service=True, single_prompt=True)
            policy.assert_called_with(args[0])
            self.assertTrue(direct.call_args.kwargs["workshop_unattended"])
            self.assertEqual(meshcentral.create_client_approved_share(
                args[0], args[1], args[2], ("desktop","files"), args[4]), "fallback")
        with patch.dict(os.environ, {"MESH_CENTRAL_SESSION_CONSENT_POLICY_ATTESTED": "1"}), \
             patch.object(meshcentral, "verify_session_node", return_value="node/d/" + "B"*64), \
             patch.object(meshcentral, "_create_share") as direct:
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.create_client_approved_share(*args)
            direct.assert_not_called()

    def test_session_share_policy_rejects_device_or_group_desktop_prompt(self):
        import json
        node = "node/d/" + "A"*64
        group = "mesh/d/" + "B"*64
        def run_ok(command):
            if "ListDeviceGroups" in command:
                return json.dumps([{"_id": group, "mtype": 2, "consent": 0}])
            return json.dumps([{"_id": node, "meshid": group, "consent": 0}])
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                                  "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group}), \
             patch.object(meshcentral, "_base_command",
                          return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(meshcentral, "_run", side_effect=run_ok):
            meshcentral.verify_session_share_policy(node)
        def run_bad_device(command):
            if "ListDeviceGroups" in command:
                return json.dumps([{"_id": group, "mtype": 2, "consent": 0}])
            return json.dumps([{"_id": node, "meshid": group, "consent": 8}])
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                                  "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group}), \
             patch.object(meshcentral, "_base_command",
                          return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(meshcentral, "_run", side_effect=run_bad_device):
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_share_policy(node)
        def run_bad_group(command):
            if "ListDeviceGroups" in command:
                return json.dumps([{"_id": group, "mtype": 2, "consent": 8}])
            return json.dumps([{"_id": node, "meshid": group, "consent": 0}])
        with patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                                  "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group}), \
             patch.object(meshcentral, "_base_command",
                          return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(meshcentral, "_run", side_effect=run_bad_group):
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_share_policy(node)

    def test_session_share_policy_inherits_group_when_device_consent_missing(self):
        import json
        node = "node/d/" + "A"*64
        group = "mesh/d/" + "B"*64
        for group_consent in (0, 8, None):
            def run(command):
                if "ListDeviceGroups" in command:
                    record = {"_id": group, "mtype": 2}
                    if group_consent is not None:
                        record["consent"] = group_consent
                    return json.dumps([record])
                return json.dumps([{"_id": node, "meshid": group}])
            with self.subTest(group_consent=group_consent), \
                 patch.dict(os.environ, {"MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                                  "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group}), \
                 patch.object(meshcentral, "_base_command",
                              return_value=["meshctrl", "DeviceSharing"]), \
                 patch.object(meshcentral, "_run", side_effect=run):
                if group_consent == 0:
                    meshcentral.verify_session_share_policy(node)
                else:
                    with self.assertRaises(meshcentral.MeshCentralError):
                        meshcentral.verify_session_share_policy(node)

    def test_legacy_consent_511_must_never_enable_single_prompt(self):
        import json
        group = "mesh/d/" + "B"*64
        node = "node/d/" + "A"*64
        def run(command):
            if "ListDeviceGroups" in command:
                return json.dumps([{"_id": group, "mtype": 2, "consent": 511}])
            return json.dumps([{"_id": node, "meshid": group}])
        with patch.dict(os.environ, {
                "MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group,
            }), patch.object(meshcentral, "_base_command",
                             return_value=["meshctrl", "DeviceSharing"]), \
             patch.object(meshcentral, "_run", side_effect=run):
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_share_policy(node)

    def test_single_prompt_group_must_be_separate_from_service_groups(self):
        group = "mesh/d/" + "B"*64
        node = "node/d/" + "A"*64
        with patch.dict(os.environ, {
                "MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": group,
                "MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID": group,
            }), patch.object(meshcentral, "_run") as run:
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_share_policy(node)
            run.assert_not_called()
        with patch.dict(os.environ, {
                "MESH_CENTRAL_TRANSIENT_CONSENT_MESH_ID": "mesh/d/" + "C"*64,
                "MESH_CENTRAL_SINGLE_PROMPT_MESH_ID": "mesh/d/" + "C"*64,
            }), patch.object(meshcentral, "_run") as run:
            with self.assertRaises(meshcentral.MeshCentralError):
                meshcentral.verify_session_share_policy(node)
            run.assert_not_called()

    def test_create_share_rejects_untrusted_urls(self):
        bad_urls = (
            "javascript:alert(1)",
            "http://mesh.example.test/sharing?token=1",
            "https://evil.example/sharing?token=1",
            "https://mesh.example.test@evil.example/sharing?token=1",
            "https://user:pass@mesh.example.test/sharing?token=1",
            "https://mesh.example.test:99999/sharing?token=1",
            "https://mesh.example.test/sharing?token=1#fragment",
            "https://mesh.example.test:8080/sharing?token=1",
            "https://mesh.example.test:8443/sharing?token=1",
        )
        with patch.dict(os.environ, {"MESH_CENTRAL_URL":
                                    "wss://mesh.example.test/control.ashx"}):
            for url in bad_urls:
                with self.subTest(url=url):
                    with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
                         patch.object(meshcentral, "_run", return_value=f"ID: ci-id\nURL: {url}"):
                        with self.assertRaises(meshcentral.MeshCentralError):
                            meshcentral.create_share("node/domain/id", "owner", ["desktop"])

            with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
                 patch.object(meshcentral, "_run", return_value=(
                     "ID: ci-id\nURL: https://mesh.example.test/sharing?ci=1")):
                share = meshcentral.create_share("node/domain/id", "owner", ["desktop"])
                self.assertEqual(share.public_id, "ci-id")
                self.assertEqual(share.url, "https://mesh.example.test/sharing?ci=1")

        # The public share may use a custom HTTPS port if that same port is
        # explicitly configured in the MeshCentral control URL.
        with patch.dict(os.environ, {
            "MESH_CENTRAL_URL": "wss://mesh.example.test:8443/control.ashx"
        }):
            with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
                 patch.object(meshcentral, "_run", return_value=(
                     "ID: ci-custom\nURL: https://mesh.example.test:8443/sharing?ci=2")):
                custom = meshcentral.create_share(
                    "node/domain/id", "owner", ["desktop"]
                )
                self.assertEqual(
                    custom.url, "https://mesh.example.test:8443/sharing?ci=2"
                )
            with patch.object(meshcentral, "_base_command", return_value=["meshctrl"]), \
                 patch.object(meshcentral, "_run", return_value=(
                     "ID: ci-wrong\nURL: https://mesh.example.test/sharing?ci=3")):
                with self.assertRaises(meshcentral.MeshCentralError):
                    meshcentral.create_share(
                        "node/domain/id", "owner", ["desktop"]
                    )

    def test_client_shares_always_require_prompt_and_privacy_bar(self):
        # An env override cannot silently change customer desktop consent.
        response = (
            "ID: safe-guest-id\n"
            "URL: https://mesh.example.test/sharing?nonce=safe\n"
        )
        with patch.dict(os.environ, {
            "MESH_CENTRAL_URL": "wss://mesh.example.test",
            "MESH_CENTRAL_SHARE_CONSENT": "prompt,bar",
        }):
            with patch.object(meshcentral, "_base_command",
                              return_value=["meshctrl", "DeviceSharing"]), \
                 patch.object(meshcentral, "_run", return_value=response) as run:
                share = meshcentral.create_share(
                    "node/test/device", "private-session", ["desktop"], 30
                )
                self.assertEqual(share.public_id, "safe-guest-id")
                params = run.call_args.args[0]
                self.assertEqual(params[params.index("--consent")+1], "prompt,bar")
        for unsafe in ("notify", "notify,bar", "prompt", "none", "owner", "0"):
            with self.subTest(unsafe=unsafe), \
                 patch.dict(os.environ, {
                     "MESH_CENTRAL_SHARE_CONSENT": unsafe,
                 }), \
                 patch.object(meshcentral, "_run") as run:
                with self.assertRaises(meshcentral.MeshCentralError):
                    meshcentral.create_share(
                        "node/test/device", "private-session", ["desktop"]
                    )
                run.assert_not_called()

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
