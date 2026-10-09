#!/usr/bin/env python3
"""Offline, privilege-free tests of the automatic web-only deployment gate."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

AGENT_FILE=Path(__file__).resolve().parents[1]/"scripts/owner_v12_pull_agent.py"
spec=importlib.util.spec_from_file_location("agent_tested",AGENT_FILE)
agent=importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
OLD="892a8c66e1e3cae662136ddf1360bf880b785ba8"
NEW="a"*40
BAD="b"*40

class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.runner_calls=[]
        self.fetch_calls=[]
        self.initial={
          "applied_sha":OLD,"sequence":0,
          "failed_sequence":None,"last_failed_sha":None
        }
        self.state=self.root/"state.json"
        self.state.write_text(json.dumps(self.initial),encoding="utf-8")
        self.patches=[
          patch.object(agent,"STATE",self.state),
          patch.object(agent,"HOME",self.root),
          patch.object(agent,"DEPLOY",self.root/"fixed-deploy.sh"),
        ]
        for p in self.patches:p.start()
        agent.DEPLOY.write_text("#!/bin/bash\n",encoding="utf-8")
        agent.DEPLOY.chmod(0o700)
        self.manifest={
            "schema_version":1,"scope":"owner-web-only",
            "sequence":0,"target_sha":OLD,"summary":"Existing prod"
        }
        self.compare_file="embedded-multiguard/app/routers/multiguard_panel_theme.py"
        self.ci_success=True
        self.run_failed=False
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def fetch(self,url,limit=agent.MAX_BYTES):
        self.fetch_calls.append(url)
        if "/branches/" in url:
            return {"commit":{"sha":"c"*40}}
        if "raw.githubusercontent.com" in url:
            assert "/"+("c"*40)+"/" in url, "Manifest must use immutable commit ref"
            return dict(self.manifest)
        if "/actions/workflows/" in url:
            return {"workflow_runs":[{
              "head_sha":self.manifest["target_sha"],
              "head_branch":agent.BRANCH,
              "status":"completed",
              "conclusion":"success" if self.ci_success else "failure",
            }]}
        if "/compare/" in url:
            return {"status":"ahead","ahead_by":2,"total_commits":2,
                    "files":[{"filename":self.compare_file,"status":"modified"}]}
        raise AssertionError("Unexpected network URL: "+url)
    def runner(self,args,env,check,timeout):
        self.runner_calls.append((args,env,check,timeout))
        if self.run_failed:
            raise subprocess.CalledProcessError(1,args)
        return subprocess.CompletedProcess(args,0)

    def test_noop_never_restarts_production(self):
        self.assertEqual(agent.poll(self.fetch,self.runner),"NO_CHANGE")
        self.assertEqual(self.runner_calls,[])
        self.assertEqual(len(self.fetch_calls),2)
        self.assertIn("/branches/",self.fetch_calls[0])
        self.assertIn("/"+("c"*40)+"/",self.fetch_calls[1])

    def test_one_approved_web_release_runs_once_and_records_state(self):
        self.manifest.update(sequence=1,target_sha=NEW)
        self.assertEqual(agent.poll(self.fetch,self.runner),"DEPLOYED")
        self.assertEqual(len(self.runner_calls),1)
        self.assertEqual(self.runner_calls[0][1]["MULTISERVIS_OWNER_WEB_REF"],NEW)
        self.assertEqual(json.loads(self.state.read_text())["applied_sha"],NEW)
        self.assertEqual(agent.poll(self.fetch,self.runner),"NO_CHANGE")
        self.assertEqual(len(self.runner_calls),1)

    def test_cannot_deploy_when_ci_fails(self):
        self.manifest.update(sequence=1,target_sha=NEW)
        self.ci_success=False
        with self.assertRaisesRegex(agent.Blocked,"CI"):
            agent.poll(self.fetch,self.runner)
        self.assertEqual(self.runner_calls,[])

    def test_blocks_android_and_client_files_even_with_green_ci(self):
        for name in ("app/routers/receptions.py",
                     "embedded-multiguard/app/routers/multiguard_updates.py",
                     "embedded-multiguard/install.sh",
                     ".github/workflows/deploy-multiservis-backend.yml",
                     "README.md"):
            self.manifest.update(sequence=1,target_sha=NEW)
            self.compare_file=name
            with self.subTest(name=name),self.assertRaisesRegex(agent.Blocked,"non-owner-web"):
                agent.poll(self.fetch,self.runner)
            self.assertEqual(self.runner_calls,[])

    def test_exact_owner_deploy_trigger_is_allowed_but_no_other_trigger(self):
        """Regression: the first real rollout was blocked on this exact file."""
        self.manifest.update(sequence=1, target_sha=NEW)
        self.compare_file="embedded-multiguard/deploy/owner-v12-deploy.trigger"
        self.assertEqual(agent.poll(self.fetch,self.runner),"DEPLOYED")
        self.assertEqual(len(self.runner_calls),1)

    def test_arbitrary_deploy_trigger_stays_blocked(self):
        self.manifest.update(sequence=1, target_sha=NEW)
        self.compare_file="embedded-multiguard/deploy/something-else.trigger"
        with self.assertRaisesRegex(agent.Blocked,"non-owner-web"):
            agent.poll(self.fetch,self.runner)
        self.assertEqual(self.runner_calls,[])

    def test_rejects_downgrade(self):
        self.manifest.update(sequence=1,target_sha=NEW)
        agent.poll(self.fetch,self.runner)
        self.manifest.update(sequence=0,target_sha=OLD)
        with self.assertRaisesRegex(agent.Blocked,"rollback"):
            agent.poll(self.fetch,self.runner)
        self.assertEqual(len(self.runner_calls),1)

    def test_failing_release_does_not_retry_until_manifest_changes(self):
        self.manifest.update(sequence=1,target_sha=NEW)
        self.run_failed=True
        with self.assertRaisesRegex(agent.Blocked,"Deployment failed"):
            agent.poll(self.fetch,self.runner)
        self.run_failed=False
        self.assertEqual(agent.poll(self.fetch,self.runner),"BLOCKED_PREVIOUS_ATTEMPT")
        self.assertEqual(len(self.runner_calls),1)
        self.manifest["sequence"]=2
        self.assertEqual(agent.poll(self.fetch,self.runner),"DEPLOYED")
        self.assertEqual(len(self.runner_calls),2)

    def test_release_manifest_denies_injected_commands_and_other_scope(self):
        self.manifest["evil_command"]="sudo systemctl stop multiservis-api.service"
        with self.assertRaises(agent.Blocked):
            agent.poll(self.fetch,self.runner)
        del self.manifest["evil_command"]
        self.manifest["scope"]="full-server"
        with self.assertRaises(agent.Blocked):
            agent.poll(self.fetch,self.runner)
        self.assertEqual(self.runner_calls,[])

    def test_deploy_path_is_owned_by_bootstrap_not_manifest(self):
        self.manifest.update(sequence=1,target_sha=NEW)
        agent.poll(self.fetch,self.runner)
        self.assertEqual(self.runner_calls[0][0],[str(agent.DEPLOY)])
        self.assertTrue(str(agent.DEPLOY).startswith(str(self.root)))

if __name__=="__main__":
    unittest.main(verbosity=2)
