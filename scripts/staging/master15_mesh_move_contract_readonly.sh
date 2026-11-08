#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import inspect,subprocess,os
from pathlib import Path
from app.routers import multiguard_meshcentral as mc
print("=== REAL MESHCTRL RUN ERROR HANDLING ===")
source=inspect.getsource(mc._run).splitlines()
for line in source:
    if any(x in line.lower() for x in ("password","loginkey","secret","token","credential")):
        print("    [REDACTED]")
    else:
        print(line[:220])
print("=== REAL MESHCTRL MOVE HELP ===")
cmd=mc._base_command()
if cmd.count("DeviceSharing")!=1: raise SystemExit("STOP: unexpected command")
pos=cmd.index("DeviceSharing")
# meshctrl "Help MoveToDeviceGroup" is a non-mutating, no-login action.
help_cmd=cmd[:pos]+["Help","MoveToDeviceGroup"]
result=subprocess.run(help_cmd,capture_output=True,text=True,timeout=12,check=False)
print("EXIT:",result.returncode)
for line in (result.stdout+"\n"+result.stderr).splitlines()[:75]:
    # Don't print unknown strings outside documented help text.
    lower=line.lower()
    if any(x in lower for x in ("login","key","token","password","secret","cookie")):
        continue
    if line.lstrip().startswith(("--","MeshCtrl","MoveToDeviceGroup","Required","Optional","Example","Move","Usage","Device","  ")):
        print(line[:180])
print("=== DONE READONLY ===")
PY
