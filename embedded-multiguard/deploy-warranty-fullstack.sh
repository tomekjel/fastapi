#!/usr/bin/env bash
# Guarded one-step Multi-Servis API + OWNER service panel warranty rollout.
# DB migration must already have been applied and a verified full backup kept.
# Does not alter Android, Multi-Guard agent, OWNER deployment manifest or SQL.
set -Eeuo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo "BLOCKED: run on LXC103 as root" >&2; exit 1; }
: "${MULTISERVIS_WARRANTY_REF:?Pin tested 40-character GitHub SHA}"
[[ "$MULTISERVIS_WARRANTY_REF" =~ ^[a-f0-9]{40}$ ]] ||
  { echo "BLOCKED: use a 40-character immutable SHA" >&2; exit 1; }
[[ "${MULTISERVIS_WARRANTY_DB_BACKUP_VERIFIED:-}" == "YES" ]] ||
  { echo "BLOCKED: independently verify PG18 backup checksum first" >&2; exit 1; }

ROOT=/opt/multiservis
ROUTERS="$ROOT/app/routers"
MAIN="$ROOT/app/main.py"
API="$ROUTERS/multiservis_warranty_returns.py"
WEB="$ROUTERS/multiguard_service_panel.py"
PY="$ROOT/.venv/bin/python"
SERVICE=multiservis-api.service
[[ -x "$PY" && -f "$MAIN" && -f "$WEB" && -d "$ROUTERS" ]] ||
  { echo "BLOCKED: unknown API/OWNER panel layout" >&2; exit 1; }
command -v curl >/dev/null && command -v systemctl >/dev/null ||
  { echo "BLOCKED: curl and systemctl required" >&2; exit 1; }

# Existing OWNER web module must equal the previously reviewed manifest source.
# Fail closed if sequence changes or an operator made manual changes.
"$PY" - "$WEB" <<'PY'
from pathlib import Path
import hashlib,sys
p=Path(sys.argv[1]); data=p.read_bytes()
sha=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
expected="8b6e213cf555c19482f56847be50d4b479b40afa"
if sha!=expected:
    raise SystemExit("BLOCKED: installed OWNER service panel differs from reviewed baseline: "+sha)
print("PASS: exact OWNER service-panel baseline: "+sha)
PY

cd "$ROOT"
PYTHONPATH="$ROOT" "$PY" - <<'PY'
from sqlalchemy import text
from app.database import engine
with engine.connect() as db:
    compatible=db.execute(text("""
      SELECT to_regclass('service.service_order_visits') IS NOT NULL
         AND to_regclass('service.v_owner_completed_visit_profit') IS NOT NULL
         AND to_regprocedure('service.reopen_warranty_return(uuid,uuid)') IS NOT NULL
    """)).scalar_one()
    row=db.execute(text("""
      SELECT
        (SELECT count(*) FROM service.service_orders) AS orders,
        (SELECT count(*) FROM service.service_order_visits) AS visits,
        (SELECT count(*) FROM service.v_owner_completed_visit_profit) AS issued,
        (SELECT coalesce(sum(service_amount),0)
         FROM service.v_owner_completed_visit_profit) AS revenue,
        (SELECT coalesce(sum(material_cost),0)
         FROM service.v_owner_completed_visit_profit) AS material
    """)).mappings().one()
    if not compatible or row["visits"]<row["orders"] or row["issued"]<23:
        raise SystemExit("BLOCKED: DB schema/visit ledger not ready")
    if row["revenue"]<8120 or row["material"]<860:
        raise SystemExit("BLOCKED: historical finance totals below verified baseline")
    print("PASS: PG18 ledger orders=",row["orders"],
          "visits=",row["visits"],"issued=",row["issued"],
          "revenue=",row["revenue"],"material=",row["material"])
PY

STAGE="$(mktemp -d)"
BACKUP="$ROOT/backups/warranty-fullstack-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p -m 0700 "$BACKUP"
OLD_API=0
CHANGED=0
cleanup() { rm -rf "$STAGE"; }
rollback() {
  rc=$?
  trap - ERR
  if [[ "$CHANGED" -eq 1 ]]; then
    cp -p "$BACKUP/main.py" "$MAIN"
    cp -p "$BACKUP/multiguard_service_panel.py" "$WEB"
    if [[ "$OLD_API" == 1 ]]; then
      cp -p "$BACKUP/multiservis_warranty_returns.py" "$API"
    else
      rm -f "$API"
    fi
    systemctl restart "$SERVICE" || true
  fi
  echo "Recovery files: $BACKUP" >&2
  exit "$rc"
}
trap cleanup EXIT
trap rollback ERR
cp -p "$MAIN" "$BACKUP/main.py"
cp -p "$WEB" "$BACKUP/multiguard_service_panel.py"
if [[ -f "$API" ]]; then
  OLD_API=1
  cp -p "$API" "$BACKUP/multiservis_warranty_returns.py"
fi

curl -fsSL --retry 3 --max-time 30 \
  "https://raw.githubusercontent.com/tomekjel/fastapi/$MULTISERVIS_WARRANTY_REF/embedded-multiguard/app/routers/multiservis_warranty_returns.py" \
  -o "$STAGE/multiservis_warranty_returns.py"
curl -fsSL --retry 3 --max-time 30 \
  "https://raw.githubusercontent.com/tomekjel/fastapi/930a95404bad400cb51b6a7646658bc889328c81/embedded-multiguard/app/routers/multiguard_service_panel.py" \
  -o "$STAGE/multiguard_service_panel.py"
"$PY" -m py_compile "$STAGE"/*.py "$MAIN"

CHANGED=1
install -m 0644 "$STAGE/multiservis_warranty_returns.py" "$API"
install -m 0644 "$STAGE/multiguard_service_panel.py" "$WEB"
"$PY" - "$MAIN" <<'PY'
from pathlib import Path
import sys
main=Path(sys.argv[1])
source=main.read_text(encoding="utf-8")
marker="app.include_router(_ms_warranty.router)"
snippet=(
    "\n# Multi-Servis warranty/repeat-visit contract.\n"
    "from app.routers import multiservis_warranty_returns as _ms_warranty\n"
    +marker+"\n"
)
if marker not in source:
    main.write_text(source+snippet,encoding="utf-8")
PY

PYTHONPATH="$ROOT" "$PY" - <<'PY'
from app.main import app
routes={(r.path,method) for r in app.routes if hasattr(r,"path")
        for method in (r.methods or [])}
for route,verb in (
  ("/health","GET"),
  ("/receptions/{reception_id}/warranty-return","POST"),
  ("/mobile/warranty/active-receptions","GET"),
  ("/mobile/receptions/{reception_id}/visits","GET"),
  ("/mobile/receptions/search","GET"),
  ("/mobile/finances/visit-report","GET"),
  ("/multiguard/panel/service/{order_id}/warranty-return","POST"),
  ("/multiguard/panel/statistics","GET"),
  ("/multiguard/panel/service","GET"),
):
    if (route,verb) not in routes:
        raise SystemExit("BLOCKED: missing registered route "+verb+" "+route)
print("PASS: app import and existing + new routes verified before restart")
PY

systemctl restart "$SERVICE"
OK=0
for i in $(seq 1 15); do
  if curl -fsS --max-time 5 https://api.multi-servis.pl/health >/dev/null 2>&1; then
    OK=1
    break
  fi
  sleep 2
done
[[ "$OK" -eq 1 ]] || { echo "BLOCKED: public API did not recover"; false; }

curl -fsS --max-time 20 https://api.multi-servis.pl/openapi.json \
  -o "$STAGE/openapi.json"
"$PY" - "$STAGE/openapi.json" <<'PY'
import json,sys
paths=json.load(open(sys.argv[1],encoding="utf-8"))["paths"]
for path,method in (
  ("/receptions/{reception_id}/warranty-return","post"),
  ("/mobile/warranty/active-receptions","get"),
  ("/mobile/receptions/{reception_id}/visits","get"),
  ("/mobile/receptions/search","get"),
  ("/mobile/finances/visit-report","get"),
  ("/multiguard/panel/service/{order_id}/warranty-return","post"),
  ("/multiguard/panel/statistics","get"),
):
    assert method in paths.get(path,{}), "Missing public route "+method+" "+path
print("PASS: public OpenAPI includes warranty + OWNER routes")
PY

CHANGED=0
echo "PASS: warranty API + OWNER WWW deployed; file backups: $BACKUP"
