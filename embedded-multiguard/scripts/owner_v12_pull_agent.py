#!/usr/bin/env python3
"""Outbound-only GitHub release poller for Multi-Servis OWNER WWW V12.

No listening port, SSH key, personal token, GitHub runner or production DB read.
Deployment is possible ONLY on a strictly increasing versioned release-manifest
request, targeting immutable SHA whose isolated CI workflow passed and whose
changes are restricted to an allowlist that cannot touch Android or Windows.
A root-owned, bootstrapped DEPLOYER file performs preflight, local file backup,
restart health check and rollback. The manifest never supplies a command/URL.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPO="tomekjel/fastapi"
BRANCH="multiservis-panel-multiguard-gold-crimson-v1"
CONTROLLER=(
    f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"
    "embedded-multiguard/deploy/owner-v12-release.json"
)
API="https://api.github.com/repos/"+REPO
CI_WORKFLOW="multiservis-panel-preview-ci.yml"
HOME=Path("/var/lib/multiservis-owner-v12")
STATE=HOME/"state.json"
LOCK=HOME/"agent.lock"
DEPLOY=Path("/usr/local/libexec/multiservis-owner-v12-deploy.sh")
SHA=re.compile(r"^[a-f0-9]{40}$")
MAX_BYTES=1024*1024

# File-boundary check: even a successful repo CI run cannot deploy changes to
# Android, Cloudflare tunnel, Windows Multi-Guard or release-sync code.
OWNER_FILES=frozenset({
    "embedded-multiguard/app/routers/multiguard_license.py",
    "embedded-multiguard/app/routers/multiguard_runtime.py",
    "embedded-multiguard/app/routers/multiguard_service_panel.py",
    "embedded-multiguard/app/routers/multiguard_panel_theme.py",
    "embedded-multiguard/app/routers/multiguard_panel_settings.py",
    "embedded-multiguard/app/routers/multiguard_panel_devices.py",
    "embedded-multiguard/app/routers/multiguard_panel_triage.py",
    "embedded-multiguard/app/routers/multiguard_panel_diagnostics.py",
    "embedded-multiguard/deploy-owner-web-v12.sh",
    "embedded-multiguard/install-owner-v12-agent.sh",
    "embedded-multiguard/deploy/owner-v12-release.json",
    "embedded-multiguard/deploy/owner-v12-livecheck.trigger",
    "embedded-multiguard/deploy/owner-v12-preflight.trigger",
    "embedded-multiguard/scripts/owner_v12_pull_agent.py",
    "embedded-multiguard/scripts/preflight_owner_panel.py",
    "embedded-multiguard/scripts/preview_owner_panel.py",
    "embedded-multiguard/scripts/audit_backend_storage.py",
    ".github/workflows/multiservis-panel-preview-ci.yml",
    ".github/workflows/multiservis-owner-v12-live-smoke.yml",
})
SAFE_PREFIXES=(
    "embedded-multiguard/tests/",
    "embedded-multiguard/docs/",
)

class Blocked(Exception):
    """Safe, fail-closed refusal; never execute anything."""


def fetch_json(url: str, limit: int=MAX_BYTES) -> dict:
    req=urllib.request.Request(url,headers={
        "Accept":"application/vnd.github+json" if url.startswith(API) else "application/json",
        "User-Agent":"Multi-Servis-Owner-Web-ReadOnly-Poller/1",
        "Cache-Control":"no-cache",
    })
    with urllib.request.urlopen(req,timeout=18) as resp:
        if resp.status != 200:
            raise Blocked("Unexpected GitHub HTTP status")
        content=resp.read(limit+1)
        if len(content)>limit:
            raise Blocked("Remote JSON exceeds safe size limit")
    doc=json.loads(content)
    if not isinstance(doc,dict):
        raise Blocked("Remote JSON must be an object")
    return doc


def release_request(fetch=fetch_json) -> dict:
    raw=fetch(CONTROLLER)
    expected_keys={"schema_version","scope","sequence","target_sha","summary"}
    if raw.keys()!=expected_keys:
        raise Blocked("Owner release manifest has unexpected fields")
    if type(raw["schema_version"]) is not int or raw["schema_version"]!=1:
        raise Blocked("Unknown manifest version")
    if raw["scope"]!="owner-web-only":
        raise Blocked("Blocked non-web deployment")
    if type(raw["sequence"]) is not int or not 0<=raw["sequence"]<1000000:
        raise Blocked("Invalid release sequence")
    if not isinstance(raw["target_sha"],str) or SHA.fullmatch(raw["target_sha"]) is None:
        raise Blocked("Invalid immutable source SHA")
    if not isinstance(raw["summary"],str) or len(raw["summary"])>320:
        raise Blocked("Invalid release note")
    return raw


def validate_ci(sha: str, fetch=fetch_json) -> None:
    url=(f"{API}/actions/workflows/{CI_WORKFLOW}/runs?"
         f"head_sha={sha}&branch={BRANCH}&per_page=15")
    runs=fetch(url).get("workflow_runs",[])
    if not isinstance(runs,list):
        raise Blocked("CI workflow response format invalid")
    if not any(
        r.get("head_sha")==sha and r.get("head_branch")==BRANCH
        and r.get("status")=="completed" and r.get("conclusion")=="success"
        for r in runs if isinstance(r,dict)
    ):
        raise Blocked("Verified successful PostgreSQL + browser CI is required")


def validate_changed_files(old: str,new: str,fetch=fetch_json) -> None:
    if SHA.fullmatch(old) is None or SHA.fullmatch(new) is None:
        raise Blocked("Invalid compare revision")
    doc=fetch(f"{API}/compare/{old}...{new}",limit=2*MAX_BYTES)
    if doc.get("status")!="ahead" or not 0<int(doc.get("ahead_by",0))<=250:
        raise Blocked("Target must be a bounded, forward-only descendant of current release")
    files=doc.get("files",[])
    if not isinstance(files,list) or len(files)>250 or doc.get("total_commits",0)>250:
        raise Blocked("Too many changed files or commits")
    for item in files:
        if not isinstance(item,dict): raise Blocked("Invalid change list")
        name=item.get("filename","")
        if name not in OWNER_FILES and not any(name.startswith(p) for p in SAFE_PREFIXES):
            raise Blocked("Refusing non-owner-web change: "+str(name)[:160])
        if item.get("status")=="removed" and name in OWNER_FILES:
            raise Blocked("Removing owner module is not supported")


def load_state() -> dict:
    raw=json.loads(STATE.read_text(encoding="utf-8"))
    if not isinstance(raw,dict) or not isinstance(raw.get("applied_sha"),str)        or not SHA.fullmatch(raw["applied_sha"]) or type(raw.get("sequence")) is not int:
        raise Blocked("Invalid local release state, refusing automatic deployment")
    return raw


def save_state(state: dict):
    HOME.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=".state-",dir=str(HOME))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as file:
            os.fchmod(file.fileno(),0o600)
            json.dump(state,file,sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(name,STATE)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def poll(fetch=fetch_json, runner=subprocess.run) -> str:
    manifest=release_request(fetch)
    state=load_state()
    seq=manifest["sequence"]
    sha=manifest["target_sha"]
    old=state["applied_sha"]
    if seq<state["sequence"]:
        raise Blocked("Manifest rollback forbidden")
    if seq==state["sequence"]:
        if sha!=old and state.get("failed_sequence")!=seq:
            raise Blocked("Published SHA differs without increased sequence")
        return "NO_CHANGE"
    if sha==old:
        # Explicit no-op sequence is safe but recorded, never execute shell.
        state["sequence"]=seq
        state["failed_sequence"]=None
        save_state(state)
        return "ALREADY_APPLIED"
    if state.get("failed_sequence")==seq:
        return "BLOCKED_PREVIOUS_ATTEMPT"
    validate_ci(sha,fetch)
    validate_changed_files(old,sha,fetch)
    if not DEPLOY.is_file() or not os.access(DEPLOY,os.X_OK):
        raise Blocked("Pinned deploy script missing")
    print(f"AUTHORIZED OWNER-WEB ROLLOUT: {old[:12]} -> {sha[:12]}",flush=True)
    try:
        runner([str(DEPLOY)],env={
            **os.environ,"MULTISERVIS_OWNER_WEB_REF":sha,
        },check=True,timeout=240)
    except Exception as exc:
        # Fail closed: never keep restarting production on the same manifest.
        state["failed_sequence"]=seq
        state["last_failed_sha"]=sha
        save_state(state)
        raise Blocked("Deployment failed (see local journal); retry requires a new release sequence") from exc
    state["applied_sha"]=sha
    state["sequence"]=seq
    state["failed_sequence"]=None
    state["last_failed_sha"]=None
    save_state(state)
    return "DEPLOYED"


def main() -> int:
    if os.geteuid()!=0:
        print("BLOCKED: agent needs isolated root-owned systemd service",file=sys.stderr)
        return 2
    HOME.mkdir(mode=0o700,parents=True,exist_ok=True)
    with LOCK.open("a+") as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            value=poll()
        except (Blocked,urllib.error.URLError,ValueError,OSError) as exc:
            print(f"OWNER-WEB AGENT BLOCKED: {exc}",file=sys.stderr)
            return 2
        print("OWNER-WEB AGENT:",value)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
