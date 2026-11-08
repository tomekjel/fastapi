#!/usr/bin/env bash
# MASTER 1.5: read-only discovery for correctly implementing OWNER -> Mesh groups.
set -euo pipefail
cd /opt/multiservis
PY=/opt/multiservis/.venv/bin/python
"$PY" - <<'PY'
from pathlib import Path
import ast,re
from sqlalchemy import text
from app.database import engine

root=Path("/opt/multiservis/app/routers")
p=root/"multiguard_license.py"
src=p.read_text(encoding="utf8")
lines=src.splitlines()
print("=== GRID V4.4: HEADERS, CELLS AND SAVE ===")
for a,b in [(5880,5905),(6158,6178),(6458,6520)]:
    print(f"--- {p.name}:{a}-{b} ---")
    for n in range(a,min(b,len(lines))+1):
        line=lines[n-1]
        if any(secret in line.lower() for secret in ("password","private_key","secret","credential")): continue
        print(f"{n}: {line[:220]}")
print("=== SAVE HANDLER: DB MUTATION LINES ONLY ===")
for n in range(5900,min(6150,len(lines))+1):
    line=lines[n-1]
    if re.search(r"INSERT INTO|UPDATE guard\.|_owner_effective_entitlement_mode|target_edition|selected_mode|return RedirectResponse|with engine\.|commit|_set_workshop",line,re.I):
        print(f"{n}: {line.strip()[:200]}")
print("=== MESH RELATED MODULE FUNCTIONS ===")
for name in ("multiguard_meshcentral.py","multiguard_workshop_remote.py"):
    path=root/name
    if path.exists():
        code=path.read_text(encoding="utf8")
        for line_no, l in enumerate(code.splitlines(),1):
            if l.startswith(("def ","async def ")) and any(t in l.lower() for t in ("mesh","group","_base_command","_run","_grant")):
                print(f"{name}:{line_no}: {l[:170]}")
print("=== MESH CONFIG: KEY NAMES, NO VALUES ===")
import os
print("PRESENT_IN_PROCESS:", ",".join(sorted(k for k in os.environ if (k.startswith("MESH_") or k.startswith("MULTIGUARD_")) and any(t in k for t in ("GROUP","MESHCTRL","NODE_BIN","LOGIN","URL")))))
print("=== TABLE SCHEMAS (NO ROW DATA) ===")
with engine.connect() as db:
    for tab in ("owner_entitlement_selections","workshop_mesh_nodes","workshop_profile_transitions","license_links","pending_installations"):
        columns=db.execute(text("""
        SELECT column_name,data_type FROM information_schema.columns
        WHERE table_schema='guard' AND table_name=:t ORDER BY ordinal_position
        """),{"t":tab}).fetchall()
        print(tab,[(a,b) for a,b in columns])
print("=== READONLY_COMPLETE ===")
PY
