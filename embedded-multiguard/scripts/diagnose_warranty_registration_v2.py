"""Read-only investigation of FastAPI route registration on LXC103.

Loads FastAPI in this short-lived Python interpreter only; does not write
production files, touch customer records, or restart the systemd service.
"""
from __future__ import annotations
import ast
from pathlib import Path
import importlib.util
import inspect
import sys

ROOT=Path("/opt/multiservis")
MAIN=ROOT/"app/main.py"
STAGED=Path("/tmp/warranty-api-diagnostic.py")
if not MAIN.is_file() or not STAGED.is_file():
    raise SystemExit("BLOCKED: missing main.py or staged warranty API")
text=MAIN.read_text(encoding="utf-8")
parsed=ast.parse(text)
sys.path.insert(0,str(ROOT))
from app.main import app
from fastapi import FastAPI, APIRouter
print("MAIN_LINES",len(text.splitlines()))
print("MAIN_APP_ASSIGNMENTS",[
    (node.lineno,type(node).__name__) for node in parsed.body
    if isinstance(node,(ast.Assign,ast.AnnAssign)) and "app" in
    ([target.id for target in getattr(node,"targets",[]) if isinstance(target,ast.Name)]
       + ([node.target.id] if isinstance(node,ast.AnnAssign)
          and isinstance(node.target,ast.Name) else []))
])
print("MAIN_INCLUDE_CALL_LINES",[
   n.lineno for n in ast.walk(parsed) if isinstance(n,ast.Call)
   and isinstance(n.func,ast.Attribute) and n.func.attr=="include_router"
][:30])
print("MAIN_WRITTEN_ASGI_APP_TYPE",type(app).__name__)
print("APP_IS_FASTAPI",isinstance(app,FastAPI))
print("APP_INCLUDE_MODULE",getattr(getattr(app.include_router,"__func__",None),"__module__","?"))
print("APP_INCLUDE_QUALNAME",getattr(app.include_router,"__qualname__","?"))
print("APP_ROUTER_TYPE",type(app.router).__name__)
print("APP_ROUTER_INCLUDE_MODULE",getattr(getattr(app.router.include_router,"__func__",None),"__module__","?"))
print("APP_ROUTER_INCLUDE_QUALNAME",getattr(app.router.include_router,"__qualname__","?"))
print("HAS_INSTANCE_INCLUDE_OVERRIDE","include_router" in vars(app))
print("HAS_INSTANCE_ROUTER_OVERRIDE","include_router" in vars(app.router))
print("ROUTES_BEFORE",len(app.router.routes))
print("STATIC_ROUTE_METHODS",[(getattr(r,"path","?"),sorted(getattr(r,"methods",[]) or []))
       for r in app.router.routes][:25])
spec=importlib.util.spec_from_file_location("app.routers.warranty_readonly_probe",STAGED)
if not spec or not spec.loader:
    raise SystemExit("BLOCKED: cannot load staged warranty API")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print("STAGED_ROUTER_TYPE",type(module.router).__name__)
print("STAGED_ROUTER_COUNT",len(module.router.routes))
print("STAGED_ROUTES",[(getattr(r,"path","?"),sorted(getattr(r,"methods",[]) or []))
      for r in module.router.routes])
before=list(app.router.routes)
app.include_router(module.router)
after=list(app.router.routes)
print("AFTER_APP_INCLUDE_COUNT",len(after))
print("AFTER_APP_INCLUDE_NEW",[(getattr(r,"path","?"),sorted(getattr(r,"methods",[]) or []))
      for r in after if r not in before])
print("APP_AND_ROUTER_ROUTES_SAME_OBJECT",app.routes is app.router.routes)
# If first method did not register, test FastAPI router's native method as
# a diagnostic in this interpreter. Never write the production main.py here.
if len(after)==len(before):
    app.router.include_router(module.router)
    last=list(app.router.routes)
    print("AFTER_ROUTER_INCLUDE_COUNT",len(last))
    print("AFTER_ROUTER_INCLUDE_NEW",[(getattr(r,"path","?"),sorted(getattr(r,"methods",[]) or []))
          for r in last if r not in before])
print("END: ephemeral FastAPI process exits without changing live server")
