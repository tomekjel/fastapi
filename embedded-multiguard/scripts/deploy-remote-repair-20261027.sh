#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=/opt/multiservis
cd "$ROOT"
ROUTERS="$ROOT/app/routers"
SOURCE=efbf1ff607aef70042c51b861d4324dab26e777f
BASE="https://raw.githubusercontent.com/tomekjel/fastapi/$SOURCE/embedded-multiguard/app/routers"
SERVICE=multiservis-api.service
TIMER=multiservis-owner-v12-pull.timer
FILES=(multiguard_remote.py multiguard_workshop_remote.py multiguard_meshcentral.py)
BACKUP="$ROOT/backups/remote-fix-$(date -u +%Y%m%dT%H%M%SZ)"
TMP=$(mktemp -d)
CHANGED=0
finish() {
  code=$?
  trap - EXIT
  if ((code != 0 && CHANGED)); then
    echo "ERROR: health validation failed; restoring prior router files"
    for file in "${FILES[@]}"; do cp -p "$BACKUP/$file" "$ROUTERS/$file"; done
    systemctl restart "$SERVICE" || true
  fi
  systemctl start "$TIMER" || true
  rm -rf "$TMP"
  echo "BACKUP=$BACKUP"
  exit "$code"
}
trap finish EXIT
test -x "$ROOT/.venv/bin/python"
systemctl is-active --quiet "$SERVICE"
mkdir -p "$BACKUP"
systemctl stop "$TIMER"
for file in "${FILES[@]}"; do
  test -s "$ROUTERS/$file"
  cp -p "$ROUTERS/$file" "$BACKUP/$file"
  curl -fLsS --retry 2 --connect-timeout 8 --max-time 40 "$BASE/$file" -o "$TMP/$file"
  test -s "$TMP/$file"
done
"$ROOT/.venv/bin/python" -m py_compile "$TMP"/*.py
grep -Fq 'def request_consent_for_owner(' "$TMP/multiguard_workshop_remote.py"
grep -Fq 'authorization_kind' "$TMP/multiguard_workshop_remote.py"
grep -Fq 'request-consent/{installation_id}' "$TMP/multiguard_remote.py"
grep -Fq 'app.include_router(multiguard_workshop_remote.router)' "$ROOT/app/main.py"
grep -Fq 'app.include_router(multiguard_remote.router)' "$ROOT/app/main.py"
echo "PASS: downloaded 3 pinned modules and validated syntax/entrypoints"
for file in "${FILES[@]}"; do install -m 0644 "$TMP/$file" "$ROUTERS/$file"; done
CHANGED=1
# Schema is already migrated on this server. Validate read-only, do not force any DDL.
"$ROOT/.venv/bin/python" - <<'PY'
from sqlalchemy import text
from app.database import engine
with engine.connect() as db:
    exists=db.execute(text("SELECT 1 FROM information_schema.columns WHERE table_schema='guard' AND table_name='workshop_remote_sessions' AND column_name='authorization_kind'")).scalar()
    if not exists: raise RuntimeError("Missing authorization_kind migration")
print("PASS: existing DB migration")
PY
systemctl restart "$SERVICE"
healthy=0
for attempt in $(seq 1 25); do
  if systemctl is-active --quiet "$SERVICE" && curl -fsS --max-time 5 http://127.0.0.1:8000/openapi.json -o "$TMP/openapi.json" 2>/dev/null; then
    if "$ROOT/.venv/bin/python" - "$TMP/openapi.json" <<'PY'
import json,sys
paths=json.load(open(sys.argv[1]))['paths']
required=[
'/multiguard/panel/remote-api/workshop/request/{installation_id}',
'/multiguard/panel/remote-api/workshop/request-consent/{installation_id}',
'/multiguard/panel/remote-api/workshop/sessions/{session_id}/connect',
]
missing=[p for p in required if p not in paths]
if missing:
 print("MISSING ROUTES:",missing)
 sys.exit(1)
print("PASS: local API + three required routes")
PY
    then healthy=1; break; fi
  fi
  sleep 2
done
if ((healthy != 1)); then
  journalctl -u "$SERVICE" -n 35 --no-pager || true
  exit 1
fi
CHANGED=0
echo "SUCCESS: backend deployed; old code backed up; no Windows changes"
