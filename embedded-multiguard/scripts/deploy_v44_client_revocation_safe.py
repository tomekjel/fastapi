#!/usr/bin/env python3
"""Surgical production install: signed CLIENT-mode revocation for retained SERVICE.

No KeyGate, Mesh or database writes. Fail-closed on unexpected live source.
Automatic backup, syntax + contract assertions, API restart, health and rollback.
"""
from __future__ import annotations
import ast,hashlib,os,shutil,subprocess,tempfile,time,urllib.request
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path("/opt/multiservis")
TARGET=ROOT/"app/routers/multiguard_license.py"
REF="8d27cd7d9a57915f720cc947490529d5453ff17c"
URL=("https://raw.githubusercontent.com/tomekjel/fastapi/"+REF+
"/embedded-multiguard/app/routers/multiguard_license.py")
NAME="_client_mode_revocation_lease"
SERVICE="multiservis-api.service"
def funcs(s):
    return {n.name:n for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
def text_fn(s,n):
    x=funcs(s)[n]; L=s.splitlines(keepends=True)
    return "".join(L[x.lineno-1:x.end_lineno])
def build(before,ref):
    a=funcs(before); b=funcs(ref)
    if NAME in a:
        raise RuntimeError("ALREADY_PRESENT: no deployment needed")
    for n in ("discovery_assignment","_signed_workshop_grant","_owner_effective_entitlement_mode"):
        if n not in a:raise RuntimeError("BLOCK missing live "+n)
    if NAME not in b:raise RuntimeError("BLOCK missing reference helper")
    old=text_fn(before,"discovery_assignment")
    if "_owner_effective_entitlement_mode(" not in old:
        raise RuntimeError("BLOCK no OWNER mode recheck")
    # Production V4.4 may have a differently formatted WAITING response.
    # Select only an unambiguous, literal WAITING dictionary returned
    # from the discovery handler. Never alter an unrelated endpoint.
    parsed=ast.parse(old)
    fn=parsed.body[0]
    found=[]
    for node in ast.walk(fn):
        if not isinstance(node,ast.Return) or not isinstance(node.value,ast.Dict):
            continue
        d=node.value
        pairs=[(k.value,v) for k,v in zip(d.keys,d.values)
               if isinstance(k,ast.Constant) and isinstance(k.value,str)]
        waiting=any(k=="status" and isinstance(v,ast.Constant)
                    and v.value=="WAITING" for k,v in pairs)
        unassigned=any(k=="assigned" and isinstance(v,ast.Constant)
                       and v.value is False for k,v in pairs)
        if waiting and unassigned:
            found.append(node)
    if len(found)!=1:
        raise RuntimeError("BLOCK: expected one unassigned WAITING return; got "+str(len(found)))
    target=found[0]
    if any(k is None for k in target.value.keys):
        raise RuntimeError("BLOCK: existing WAITING unpack; manual review")
    waiting_source=ast.get_source_segment(old,target)
    # AST source offsets match original function source. Inject a single
    # dictionary unpack BEFORE the last key, preserving all existing data.
    last=target.value.keys[-1]
    if not isinstance(last,ast.Constant) or last.value!="serverTime":
        raise RuntimeError("BLOCK: WAITING return tail changed; manual review")
    line=old.splitlines(keepends=True)
    last_line=last.lineno-1
    prefix=line[last_line][:last.col_offset]
    if not prefix.isspace():
        raise RuntimeError("BLOCK: ambiguous WAITING indentation")
    line.insert(last_line, prefix+"**_client_mode_revocation_lease(pending, selected_mode),\n")
    changed="".join(line)
    if 'selected_mode == "SERVICE"' not in old:
        raise RuntimeError("BLOCK no independent SERVICE selection")
    # Insert helper BEFORE the endpoint decorator, never between decorator and def.
    decorators=['@router.post("/v1/multi-guard/discovery/assignment")','@router.post(\'/v1/multi-guard/discovery/assignment\')']
    hits=[x for x in decorators if before.count(x)==1]
    if len(hits)!=1:raise RuntimeError("BLOCK discovery decorator differs")
    decorator=hits[0]
    if before.index(decorator)>before.index(old):raise RuntimeError("BLOCK decorator order")
    helper=text_fn(ref,NAME)
    upgraded=before.replace(old,changed,1)
    upgraded=upgraded.replace(decorator,helper+"\n\n"+decorator,1)
    aft=funcs(upgraded)
    if set(aft)!=set(a)|{NAME}:raise RuntimeError("BLOCK unexpected function set")
    for n in a:
        if n!="discovery_assignment" and ast.dump(a[n],include_attributes=False)!=ast.dump(aft[n],include_attributes=False):
            raise RuntimeError("BLOCK unrelated function altered: "+n)
    compile(upgraded,str(TARGET),"exec")
    return upgraded
def system(*argv):
    return subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=50)
def code():
    try:
        with urllib.request.urlopen("https://api.multi-servis.pl/multiguard/panel/licenses-grid",timeout=12) as r:return r.status
    except urllib.error.HTTPError as e:return e.code
    except Exception:return 0
def main():
    if not TARGET.is_file():raise RuntimeError("Missing production router")
    before=TARGET.read_text()
    with urllib.request.urlopen(URL,timeout=25) as res:
        ref=res.read().decode()
    upgraded=build(before,ref)
    baseline=code()
    if baseline not in (200,302,303,401,403):raise RuntimeError("BLOCK baseline panel HTTP "+str(baseline))
    backup=ROOT/("backup-mg-client-revocation-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    backup.mkdir(mode=0o700)
    shutil.copy2(TARGET,backup/TARGET.name)
    print("BASELINE:",baseline,"BACKUP:",backup,flush=True)
    wrote=False
    try:
        fd,tmp=tempfile.mkstemp(prefix=".mg-revocation-",dir=TARGET.parent)
        with os.fdopen(fd,"w") as out:out.write(upgraded)
        os.chmod(tmp,TARGET.stat().st_mode & 0o777)
        os.replace(tmp,TARGET)
        wrote=True
        result=system("systemctl","restart",SERVICE)
        if result.returncode:raise RuntimeError("restart failed: "+result.stderr[-300:])
        for _ in range(20):
            if system("systemctl","is-active","--quiet",SERVICE).returncode==0 and code()==baseline:
                live=TARGET.read_text()
                if NAME not in funcs(live):raise RuntimeError("missing deployed helper")
                print("DEPLOY PASS: signed CLIENT revocation guard")
                print("HTTP:",code(),"SHA256:",hashlib.sha256(live.encode()).hexdigest())
                print("KEYGATE/MESH/LICENSE DATA: UNCHANGED")
                return
            time.sleep(1)
        raise RuntimeError("health check failed")
    except Exception:
        if wrote:
            shutil.copy2(backup/TARGET.name,TARGET)
            system("systemctl","restart",SERVICE)
        print("AUTOMATIC ROLLBACK COMPLETED",flush=True)
        raise
if __name__=="__main__":
    import urllib.error
    main()
