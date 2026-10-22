"""Read-only diagnostics for an unusual ASGI route registry.

Never prints authentication headers, secrets, SQL values or customer content.
The probe only imports Python modules in this one-off CLI process and adds
routes in memory (not to the live server).
"""
from pathlib import Path
import importlib.util
import sys
import fastapi
import starlette

ROOT = Path("/opt/multiservis")
sys.path.insert(0, str(ROOT))
STAGED = Path("/tmp/warranty-api-diagnostic.py")
if not STAGED.is_file():
    raise SystemExit("No /tmp/warranty-api-diagnostic.py")

from app.main import app
from fastapi.routing import APIRoute
from starlette.routing import Route, Mount

def summary(label, route):
    cls = type(route)
    name = f"{cls.__module__}.{cls.__name__}"
    keys = sorted(vars(route).keys()) if hasattr(route, "__dict__") else []
    safe = {k: str(getattr(route, k, None))[:120]
            for k in ("path", "path_format", "name")
            if isinstance(getattr(route, k, None), str)}
    nested = getattr(route, "routes", None)
    router = getattr(route, "router", None)
    print(label, "CLASS", name, "IS_APIROUTE", isinstance(route, APIRoute),
          "IS_ROUTE", isinstance(route, Route),
          "IS_MOUNT", isinstance(route, Mount),
          "FIELDS", keys[:28], "SAFE", safe,
          "NESTED_ROUTES", len(nested) if isinstance(nested, list) else "-",
          "ROUTER", type(router).__name__ if router else "-")

print("VERSIONS", fastapi.__version__, starlette.__version__)
print("APP", type(app).__module__, type(app).__name__)
before = list(app.router.routes)
print("TOTAL_BEFORE", len(before))
for i, r in enumerate(before[:6]):
    summary(f"OLD_{i}", r)
spec = importlib.util.spec_from_file_location("app.routers.warranty_probe", STAGED)
if spec is None or spec.loader is None:
    raise SystemExit("Cannot import warranty router")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print("MODULE_ROUTE_COUNT", len(module.router.routes))
for i, r in enumerate(module.router.routes[:2]):
    summary(f"STAGED_{i}", r)
app.include_router(module.router)
after = list(app.router.routes)
print("TOTAL_AFTER", len(after))
for i, r in enumerate(after[len(before):]):
    summary(f"NEW_{i}", r)
try:
    paths = app.openapi().get("paths",{})
    wanted=[
        "/receptions/{reception_id}/warranty-return",
        "/mobile/warranty/active-receptions",
        "/mobile/receptions/{reception_id}/visits",
        "/mobile/receptions/search",
        "/mobile/finances/visit-report",
    ]
    print("OPENAPI_TOTAL_PATHS", len(paths))
    print("OPENAPI_PRESENT", [(p, sorted(paths.get(p,{}))) for p in wanted])
except Exception as e:
    print("OPENAPI_ERROR", type(e).__name__)
print("END: read-only probe finished; changes only in this process")
