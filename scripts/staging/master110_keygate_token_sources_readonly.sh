#!/usr/bin/env bash
set -Eeuo pipefail
echo '=== MASTER110 KEYGATE — SAFE EXISTING TOKEN SOURCE INVENTORY ==='
python3 - <<'PY'
import os,re,json,subprocess,pathlib
targets=("MULTIGUARD_KEYGATE_LICENSES_TOKEN","KEYGATE_LICENSES_TOKEN")
found=[]
def add(source,key,value):
    if isinstance(value,str) and value.strip() and not value.strip().startswith(("#","$","<")):
        found.append((source,key,value.strip()))
def examine_file(p):
    try:
        if not p.is_file() or p.is_symlink() or p.stat().st_size>1_000_000:return
        data=p.read_text(encoding="utf-8")
    except (OSError,UnicodeError):return
    if p.suffix.lower()==".json":
        try:
            o=json.loads(data)
            if isinstance(o,dict):
                for k in targets:add(str(p),k,o.get(k))
        except (ValueError,TypeError):pass
    for line in data.splitlines():
        m=re.match(r'^\s*(?:export\s+)?(MULTIGUARD_KEYGATE_LICENSES_TOKEN|KEYGATE_LICENSES_TOKEN)\s*=\s*(.*?)\s*$',line)
        if m:
            v=m.group(2).strip().strip("'\"")
            add(str(p),m.group(1),v)
roots=[pathlib.Path("/opt/multiservis/config"),pathlib.Path("/opt/multiservis/license-bridge"),
       pathlib.Path("/etc/multiservis"),pathlib.Path("/etc/default"),pathlib.Path("/etc/systemd/system")]
base=pathlib.Path("/opt/multiservis")
for p in [base/".env",base/"config/multiguard-license.json",base/"config/keygate.env",
          pathlib.Path("/etc/default/multiservis-api")]:examine_file(p)
for root in roots:
    if not root.is_dir():continue
    for p in root.rglob("*"):
        if len(p.parts)-len(root.parts)>4:continue
        if p.is_file() and (p.name.endswith((".env",".conf",".service",".json")) or p.name in (".env","environment")):
            examine_file(p)
try:
    pid=subprocess.check_output(["systemctl","show","-p","MainPID","--value","multiservis-api.service"],text=True).strip()
    if pid.isdigit() and int(pid)>0:
        raw=pathlib.Path("/proc")/pid/"environ"
        for part in raw.read_bytes().split(b"\x00"):
            if b"=" not in part:continue
            k,v=part.split(b"=",1)
            if k.decode(errors="ignore") in targets:add("RUNNING_MULTISERVIS_API_ENV",k.decode(),v.decode(errors="replace"))
except (OSError,subprocess.SubprocessError):pass
print("SOURCES_WITH_TOKEN",len(found))
for source,key,_ in found:
    print("FOUND_SOURCE",source,"NAME",key,"VALUE","[REDACTED]")
print("DISTINCT_TOKEN_VALUES",len(set(v for _,_,v in found)))
print("MULTIGUARD_NAMED_SOURCE_PRESENT",any(k==targets[0] for _,k,_ in found))
print("BRIDGE_NAMED_SOURCE_PRESENT",any(k==targets[1] for _,k,_ in found))
print("NEXT","SOURCE_RECONCILIATION_REQUIRED" if found else "NO_EXISTING_TOKEN_IN_CHECKED_LOCATIONS")
print("=== END — READ ONLY — NO SECRET DISPLAY ===")
PY
