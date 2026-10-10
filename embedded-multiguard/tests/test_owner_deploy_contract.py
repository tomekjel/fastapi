#!/usr/bin/env python3
"""Exercise the EXACT staged deployment AST guard with real old/new router files.

No DB access, production writes, credentials, or server calls. Both original
API handlers remain callable with the same request signatures. Any unrelated
legacy agent or Android route body alteration must fail closed.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE_SHA="d4a665f501ad769bbb89bb21da9cc73011da21f7"
NAMES=("multiguard_license.py","multiguard_runtime.py")
script=(ROOT/"deploy-owner-web-v12.sh").read_text(encoding="utf-8")
start_marker='"$PY" - "$ROUTERS" "$STAGE" <<\'PY\'\n'
assert script.count(start_marker)==1, "Ambiguous deployment security guard"
body=script.split(start_marker,1)[1].split("\nPY",1)[0]
assert "AUTHORIZED_LICENSE_EVOLUTION" in body, "Missing narrow API authorization"
assert "ast.dump" in body, "Must compare entire handler ASTs"

with tempfile.TemporaryDirectory(prefix="owner-license-contract-") as folder:
    root=Path(folder)
    old=root/"before"; new=root/"after"
    old.mkdir();new.mkdir()
    for name in NAMES:
        url=f"https://raw.githubusercontent.com/tomekjel/fastapi/{BASE_SHA}/embedded-multiguard/app/routers/{name}"
        request=urllib.request.Request(url,headers={"User-Agent":"Multi-Servis-licence-CI"})
        with urllib.request.urlopen(request,timeout=25) as source:
            (old/name).write_bytes(source.read())
        (new/name).write_bytes((ROOT/"app/routers"/name).read_bytes())

    def run()->subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable,"-c",body,str(old),str(new)],
                              capture_output=True,text=True,timeout=20)
    ok=run()
    assert ok.returncode==0,(ok.stdout,ok.stderr)
    print("PASS: OWNER deployer accepts the reviewed licensing and reconnect handlers.")

    # Any unrelated existing agent endpoint mutation must still be denied.
    path=new/"multiguard_runtime.py"
    original=path.read_text(encoding="utf-8")
    tag="def heartbeat(body: HeartbeatBody):"
    assert original.count(tag)==1
    path.write_text(original.replace(tag,tag+"\n    pass",1),encoding="utf-8")
    reject=run()
    assert reject.returncode!=0,(reject.stdout,reject.stderr)
    assert "unrelated" in (reject.stderr+reject.stdout)
    path.write_text(original,encoding="utf-8")
    print("PASS: unrelated heartbeat mutation is rejected.")

    # A mutated request interface on an explicitly authorised licensing
    # handler must also be denied, not accidentally treated as compatible.
    path=new/"multiguard_license.py"
    original=path.read_text(encoding="utf-8")
    tag="def provision(req: ProvisionRequest):"
    assert original.count(tag)==1
    path.write_text(original.replace(
        tag,"def provision(req: ProvisionRequest, insecure: bool = False):",1
    ),encoding="utf-8")
    reject=run()
    assert reject.returncode!=0,(reject.stdout,reject.stderr)
    assert "interface" in (reject.stdout+reject.stderr)
    print("PASS: modified provision API signature is rejected.")
    path.write_text(original,encoding="utf-8")

    # An attacker cannot add an unauthenticated bypass to discovery/register,
    # even though its internal status-revival logic is explicitly reviewed.
    tag="def discovery_register(req: DiscoveryRegisterRequest):"
    assert original.count(tag)==1
    path.write_text(original.replace(
        tag,"def discovery_register(req: DiscoveryRegisterRequest, bypass: bool = False):",1
    ),encoding="utf-8")
    reject=run()
    assert reject.returncode!=0,(reject.stdout,reject.stderr)
    assert "interface" in (reject.stdout+reject.stderr)
    path.write_text(original,encoding="utf-8")
    print("PASS: discovery/register authentication signature is protected.")

    # New no-license uninstall messages must use a strict discovery secret.
    assert "def discovery_uninstall(req: DiscoveryUninstallRequest):" in original
    assert "_authenticate_pending(" in original
    assert "UPDATE guard.pending_installations" in original
    assert "status='UNINSTALLED'" in original
    print("PASS: no-license uninstall uses authenticated, archived events.")

print("PASS: approved narrow rollout guard is ready for immutable release.")
