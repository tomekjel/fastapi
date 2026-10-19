#!/usr/bin/env bash
# One-time guarded backend addon deployment (NO database migration).
# Explicit, pinned release only. Run only AFTER independent DB backup,
# migration compatibility review, sandbox integration test and OWNER approval.
set -Eeuo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo "Run as root on LXC103." >&2; exit 1; }
: "${MULTISERVIS_WARRANTY_REF:?Set full 40-character reviewed commit SHA}"
[[ "$MULTISERVIS_WARRANTY_REF" =~ ^[a-f0-9]{40}$ ]] ||
  { echo "Ref must be an immutable 40-character SHA." >&2; exit 1; }
[[ "${MULTISERVIS_WARRANTY_DB_BACKUP_VERIFIED:-}" == "YES" ]] ||
  { echo "BLOCKED: verified live DB backup required." >&2; exit 1; }

ROOT=/opt/multiservis
VENV="$ROOT/.venv/bin/python"
MAIN="$ROOT/app/main.py"
ROUTER="$ROOT/app/routers/multiservis_warranty_returns.py"
SERVICE=multiservis-api.service
[[ -x "$VENV" && -f "$MAIN" && -d "$ROOT/app/routers" ]] ||
  { echo "BLOCKED: unfamiliar app layout." >&2; exit 1; }
command -v curl >/dev/null && command -v systemctl >/dev/null ||
  { echo "BLOCKED: curl/systemctl missing." >&2; exit 1; }

cd "$ROOT"
# Read-only audit against actual, not target, database.
PYTHONPATH="$ROOT" "$VENV" - <<'PY'
from sqlalchemy import text
from app.database import engine
with engine.connect() as conn:
    record=conn.execute(text("""
       SELECT
         to_regclass('service.service_order_visits') IS NOT NULL,
         to_regclass('service.v_owner_completed_visit_profit') IS NOT NULL,
         to_regprocedure('service.reopen_warranty_return(uuid,uuid)') IS NOT NULL
    """)).one()
if not all(record):
    raise SystemExit("BLOCKED: warranty DB migration and finance ledger must exist")
print("PASS: read-only SQL preflight")
PY

TMP="$(mktemp -d)"
BACKUP="$ROOT/backups/warranty-api-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$BACKUP"
STAGED=0
WAS_PRESENT=0
cleanup() { rm -rf "$TMP"; }
rollback() {
  rc=$?
  trap - ERR
  if [[ "$STAGED" == 1 ]]; then
    cp -p "$BACKUP/main.py" "$MAIN"
    if [[ "$WAS_PRESENT" == 1 ]]; then
      cp -p "$BACKUP/multiservis_warranty_returns.py" "$ROUTER"
    else
      rm -f "$ROUTER"
    fi
    systemctl restart "$SERVICE" || true
  fi
  echo "Rollback snapshot: $BACKUP" >&2
  exit "$rc"
}
trap cleanup EXIT
trap rollback ERR
cp -p "$MAIN" "$BACKUP/main.py"
if [[ -f "$ROUTER" ]]; then
  WAS_PRESENT=1
  cp -p "$ROUTER" "$BACKUP/multiservis_warranty_returns.py"
fi

RAW="https://raw.githubusercontent.com/tomekjel/fastapi/$MULTISERVIS_WARRANTY_REF/embedded-multiguard/app/routers/multiservis_warranty_returns.py"
curl --fail --silent --show-error --location --retry 2 --max-time 25 \
   "$RAW" -o "$TMP/multiservis_warranty_returns.py"
"$VENV" -m py_compile "$TMP/multiservis_warranty_returns.py" "$MAIN"

# This script will not patch an unknown FastAPI main module.
"$VENV" - "$MAIN" <<'PY'
import ast,sys
root=ast.parse(open(sys.argv[1],encoding="utf-8").read())
if not any(isinstance(stmt,(ast.Assign,ast.AnnAssign))
    and ((isinstance(stmt,ast.Assign)
          and any(isinstance(x,ast.Name) and x.id=="app" for x in stmt.targets))
         or (isinstance(stmt,ast.AnnAssign)
             and isinstance(stmt.target,ast.Name) and stmt.target.id=="app"))
    for stmt in root.body):
    raise SystemExit("BLOCKED: FastAPI app object not identified in main.py")
PY

STAGED=1
cp -p "$TMP/multiservis_warranty_returns.py" "$ROUTER"
"$VENV" - "$MAIN" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text(encoding="utf-8")
snippet=(
    "\n# Multi-Servis warranty returns: reviewed authenticated addon.\n"
    "from app.routers import multiservis_warranty_returns as _ms_warranty\n"
    "app.include_router(_ms_warranty.router)\n"
)
if "app.include_router(_ms_warranty.router)" not in s:
    p.write_text(s+snippet,encoding="utf-8")
PY
PYTHONPATH="$ROOT" "$VENV" -m py_compile "$MAIN" "$ROUTER"
systemctl restart "$SERVICE"
curl --fail --silent --show-error --max-time 20 \
    https://api.multi-servis.pl/health >/dev/null
curl --fail --silent --show-error --max-time 20 \
    https://api.multi-servis.pl/openapi.json -o "$TMP/openapi.json"
"$VENV" - "$TMP/openapi.json" <<'PY'
import json,sys
paths=json.load(open(sys.argv[1],encoding="utf-8"))["paths"]
for route,method in (
  ("/receptions/{reception_id}/warranty-return","post"),
  ("/mobile/warranty/active-receptions","get"),
  ("/mobile/receptions/{reception_id}/visits","get"),
  ("/mobile/finances/visit-report","get"),
):
    assert method in paths.get(route,{}), f"Missing {method.upper()} {route}"
print("PASS: new authenticated warranty endpoints in OpenAPI")
PY
STAGED=0
echo "PASS: guarded backend addon installed, rollback snapshot $BACKUP"
