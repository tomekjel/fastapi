#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
import ast,importlib.util,inspect
from pathlib import Path
from sqlalchemy import text
from app.database import engine

print("=== MASTER 1.5 / OWNER BROKER PRODUCTION PREFLIGHT (READONLY) ===")
modules={
 "license":"/opt/multiservis/app/routers/multiguard_license.py",
 "workshop":"/opt/multiservis/app/routers/multiguard_workshop_remote.py",
 "grant":"/opt/multiservis/app/routers/multiguard_owner_profile_grant.py",
 "bridge":"/opt/multiservis/app/routers/master15_owner_profile_bridge.py",
}
for key,p in modules.items():
    obj=Path(p)
    print("FILE",key,"PRESENT" if obj.exists() else "ABSENT")
    if not obj.exists():continue
    source=obj.read_text(encoding="utf8")
    tree=ast.parse(source,filename=p)
    names={n.name for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    lookups={
      "license":["_owner_effective_entitlement_mode","_signing_key","_authenticate_pending"],
      "workshop":["_schema","_service_transition_sessions"],
      "grant":["create_profile_transition_grant"],
      "bridge":["owner_profile_grant","owner_profile_report"]
    }
    for func in lookups.get(key,[]):
        print("FUNCTION",key,func,"PRESENT" if func in names else "ABSENT")
print("=== SESSION GUARD DEFINITION ===")
p=Path(modules["workshop"])
tree=ast.parse(p.read_text(encoding="utf8"))
for f in ast.walk(tree):
    if isinstance(f,ast.FunctionDef) and f.name=="_service_transition_sessions":
        lines=p.read_text(encoding="utf8").splitlines()
        for i in range(f.lineno-1,min(f.end_lineno,f.lineno+65)):
            line=lines[i]
            if "password" not in line.lower() and "secret" not in line.lower():
                print(f"{i+1}: {line[:220]}")
print("=== LIVE TABLE COLUMNS ONLY ===")
with engine.connect() as db:
    for name in ("workshop_profile_transitions","license_links","pending_installations",
                 "workshop_grants","remote_sessions","workshop_remote_sessions"):
        cols=db.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema='guard' AND table_name=:name
            ORDER BY ordinal_position
        """),{"name":name}).scalars().all()
        print("TABLE",name,"COLUMNS",",".join(cols))
print("=== END READONLY ===")
PY
