"""Offline security tests for OWNER's MeshCentral login-token adapter."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.routers import multiguard_meshcentral as mesh


class ProtectedLoginTokenTests(unittest.TestCase):
    def test_missing_explicit_token_fails_closed(self):
        with patch.dict(os.environ, {
            "MESH_CENTRAL_MESHCTRL_PATH": "/opt/meshctrl.js",
            "MESH_CENTRAL_URL": "wss://mesh.example.test",
            "MESH_CENTRAL_TOKEN_FILE": "/nonexistent/meshcentral-token.json",
            "MESH_CENTRAL_LOGIN_USER": "owner",
            "MESH_CENTRAL_LOGIN_PASS": "legacy-secret",
        }), patch.object(mesh.os.path, "isfile", return_value=False):
            with self.assertRaises(mesh.MeshCentralError):
                mesh._base_command()

    def test_generated_command_contains_no_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            token = Path(folder) / "token.json"
            secret = "synthetic-not-production-secret"
            token.write_text(json.dumps({
                "username": "~t:ci-token",
                "password": secret,
            }), encoding="utf8")
            with patch.dict(os.environ, {
                "MESH_CENTRAL_MESHCTRL_PATH": "/opt/meshctrl.js",
                "MESH_CENTRAL_URL": "wss://mesh.example.test",
                "MESH_CENTRAL_TOKEN_FILE": str(token),
            }):
                command = mesh._base_command()
                self.assertEqual(command[1], "-e")
                self.assertIn("DeviceSharing", command)
                self.assertNotIn(secret, repr(command))
                self.assertNotIn("~t:ci-token", repr(command))
                self.assertNotIn("--loginpass", command)
                self.assertNotIn("--loginkeyfile", command)
                self.assertEqual(command[4], str(token))

    def test_existing_owner_token_is_auto_detected_without_systemd_secrets(self):
        with patch.dict(os.environ, {
            "MESH_CENTRAL_TOKEN_FILE": "",
            "MESH_CENTRAL_MESHCTRL_PATH": "",
            "MESH_CENTRAL_URL": "",
            "MESH_CENTRAL_LOGIN_USER": "",
        }), patch.object(mesh.os.path, "isfile", side_effect=lambda p:
            p == "/etc/multiservis/meshcentral-token.json"):
            command = mesh._base_command()
        self.assertEqual(command[1], "-e")
        self.assertEqual(command[-2:], ["--url", "wss://mesh.multi-servis.pl"])
        self.assertIn(
            "/opt/multiservis-meshctrl/node_modules/meshcentral/meshctrl.js",
            command
        )
        self.assertNotIn("mg-bridge", command)

    def test_bootstrap_reads_credentials_only_in_node_process(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not available on this CI host")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            script = root / "fake-meshctrl.js"
            script.write_text(
                "if (process.argv[2] === 'ListDevices' && "
                "process.argv.includes('--loginuser') && "
                "process.argv.includes('~t:ci-token') && "
                "process.argv.includes('synthetic-not-production-secret')) "
                "{ console.log('[]') } else { process.exit(4) }\n",
                encoding="utf8"
            )
            token = root / "token.json"
            token.write_text(json.dumps({
                "username": "~t:ci-token",
                "password": "synthetic-not-production-secret",
            }), encoding="utf8")
            env = dict(os.environ, **{
                "MESH_CENTRAL_NODE_BIN": node,
                "MESH_CENTRAL_MESHCTRL_PATH": str(script),
                "MESH_CENTRAL_URL": "wss://mesh.example.test",
                "MESH_CENTRAL_TOKEN_FILE": str(token),
            })
            with patch.dict(os.environ, env, clear=True):
                command = mesh._base_command()
                command[command.index("DeviceSharing")] = "ListDevices"
                # The Node bootstrap must get the file path from argv,
                # not from systemd or MESH_CENTRAL_TOKEN_FILE.
                child_env = dict(env)
                child_env.pop("MESH_CENTRAL_TOKEN_FILE", None)
                process = subprocess.run(command, env=child_env, text=True,
                                         capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout.strip(), "[]")
            self.assertNotIn("synthetic-not-production-secret", repr(command))

    def test_invalid_login_even_with_exit_zero_is_error(self):
        result = subprocess.CompletedProcess(
            args=["node", "meshctrl"], returncode=0,
            stdout="Invalid login.\n", stderr=""
        )
        with patch.object(mesh.subprocess, "run", return_value=result):
            with self.assertRaises(mesh.MeshCentralError):
                mesh._run(["node", "meshctrl"])

    def test_silent_meshctrl_result_is_error(self):
        result = subprocess.CompletedProcess(
            args=["node", "meshctrl"], returncode=0,
            stdout="", stderr=""
        )
        with patch.object(mesh.subprocess, "run", return_value=result):
            with self.assertRaises(mesh.MeshCentralError):
                mesh._run(["node", "meshctrl"])


if __name__ == "__main__":
    unittest.main()
