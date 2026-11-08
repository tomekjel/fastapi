#!/usr/bin/env bash
set -euo pipefail
P=/opt/multiservis/app/routers/multiguard_license.py
M=/opt/multiservis/app/routers/multiguard_meshcentral.py
W=/opt/multiservis/app/routers/multiguard_workshop_remote.py
python3 - "$P" "$M" "$W" <<'PY'
import ast,sys
from pathlib import Path
a,b,c=map(Path,sys.argv[1:])
def output(p,name,context=0):
    src=p.read_text(encoding="utf8")
    lines=src.splitlines()
    tree=ast.parse(src,filename=str(p))
    matches=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
    if len(matches)!=1:
        print(f"STOP: {p.name}:{name} functions={len(matches)}")
        return
    n=matches[0]
    print(f"=== {p.name}::{name} L{n.lineno}-{n.end_lineno} ===")
    for i in range(n.lineno-1,n.end_lineno):
        line=lines[i]
        if any(key in line.lower() for key in ("password","secret","private_key","credential","token","loginpass")):
            print(f"{i+1}: [redacted]")
        else:
            print(f"{i+1}: {line[:260]}")
output(b,"move_registered_node_to_group")
output(a,"panel_grid_save_row")
for p in (b,c):
    for name in ("_auto_mesh_command","_auto_mesh_identifier","_grant"):
        if name in p.read_text(encoding="utf8"):
            output(p,name)
print("=== OWNER GRID EXACT HEADER AND CELL BUILDERS ===")
lines=a.read_text(encoding="utf8").splitlines()
for i,line in enumerate(lines):
    if 6150 < i+1 < 7000 and any(q in line for q in ("license_cell =", "license_type_cell =", "<th", "{license_cell}", "{license_type_cell}", "trs.append(")):
        print(f"{i+1}: {line[:240]}")
print("=== DONE READ ONLY ===")
PY
