"""READ-ONLY forensic check for warranty API route-registration failure.

No DB mutations, no private data or content of main.py printed. The temporary
FastAPI route registration is in this one Python interpreter and never
written to disk, restarted, or exposed to the running service.
"""
from __future__ import annotations
import ast
import hashlib
import importlib.util
from pathlib import Path
import sys

ROOT=Path("/opt/multiservis")
MAIN=ROOT/"app/main.py"
STAGED=Path("/tmp/warranty-api-diagnostic.py")
if not MAIN.is_file() or not STAGED.is_file():
    raise SystemExit("MISSING: app/main.py or temporary staged API module")

text=MAIN.read_text("utf-8")
tree=ast.parse(text,filename=str(MAIN))
print("MAIN_SHA256:",hashlib.sha256(text.encode()).hexdigest())
print("MAIN_LINES:",len(text.splitlines()))
print("MAIN_TOP_LEVEL_LAST_TYPES:",[type(node).__name__ for node in tree.body[-12:]])
print("MAIN_END_HAS_WARRANTY_INCLUDE:", "app.include_router(_ms_warranty.router)" in text)
print("MAIN_HAS_MOUNT:",any(isinstance(n,ast.Call) and
    isinstance(n.func,ast.Attribute) and n.func.attr=="mount" for n in ast.walk(tree)))
print("MAIN_HAS_API_ROUTE_REGISTRATION:",any(
    isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
    and n.func.attr in ("include_router","add_route") for n in ast.walk(tree)))
# No contents of app/main.py, environment secrets, clients, tokens or PII.
sys.path.insert(0,str(ROOT))
from app.main import app
existing={(r.path,tuple(sorted(r.methods or ()))) for r in app.routes
          if hasattr(r,"path") and hasattr(r,"methods")}
wanted="/receptions/{reception_id}/warranty-return"
print("APP_TYPE:",type(app).__name__)
print("ROUTES_BEFORE:",len(existing))
print("REGISTERED_BEFORE:",any(path==wanted and "POST" in methods
      for path,methods in existing))
spec=importlib.util.spec_from_file_location(
    "app.routers.multiservis_warranty_api_diagnostic",STAGED)
assert spec and spec.loader
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
defined={(r.path,tuple(sorted(r.methods or ()))) for r in module.router.routes
         if hasattr(r,"methods")}
print("STAGED_MODULE_ROUTES:",len(defined))
print("STAGED_HAS_POST:",any(path==wanted and "POST" in methods
      for path,methods in defined))
# Change only the in-memory Python app that will disappear at process exit.
app.include_router(module.router)
after={(r.path,tuple(sorted(r.methods or ()))) for r in app.routes
       if hasattr(r,"path") and hasattr(r,"methods")}
print("APP_ROUTES_AFTER_EPHEMERAL_INCLUDE:",len(after))
print("REGISTERED_AFTER_EPHEMERAL_INCLUDE:",any(
      path==wanted and "POST" in methods for path,methods in after))
if any(path==wanted and "POST" in methods for path,methods in after):
    print("DIAG_PASS: router itself registers correctly; bug is in main.py injection/check path")
else:
    raise SystemExit("DIAG_BLOCKED: router did not register even in isolated app import")
