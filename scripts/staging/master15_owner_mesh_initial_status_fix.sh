#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
P=/opt/multiservis/app/routers/master15_owner_mesh_sync_engine.py
PY=/opt/multiservis/.venv/bin/python
test -f "$P"
BACKUP="/opt/multiservis/backups/master15-owner-mesh-initial-$(date +%Y%m%d-%H%M%S).py"
cp -a "$P" "$BACKUP"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_sync_engine.py --jq .content | tr -d '\n' | base64 -d > "$TMP"
"$PY" -m py_compile "$TMP"
cp -a "$TMP" "$P"
if ! "$PY" - <<'PY'
from app.routers import master15_owner_mesh_sync_engine as sync
from app.database import engine
from sqlalchemy import text
from app.routers import multiguard_license as license
with engine.connect() as db:
    rows=db.execute(text("""
        SELECT l.installation_id FROM guard.license_links l
        WHERE l.installation_id IS NOT NULL
        ORDER BY l.updated_at DESC LIMIT 10
    """)).scalars().all()
    print("OWNER_ROWS_CHECKED",len(rows))
    for iid in rows:
        name,status,attempts=sync.get_status(db,iid)
        assert name in ("Brak","Klient","Serwis","—")
        assert status in ("Czeka","Przenoszenie…","OK","Ponów")
        print("GRUPA_MESH",name,"/",status)
print("PASS: read-only saved OWNER group status")
PY
then
    cp -a "$BACKUP" "$P"
    echo "ROLLBACK: original engine restored" >&2
    exit 1
fi
systemctl restart multiservis-api.service
echo "=== CHECK SERVICE READINESS ==="
ready=0
for attempt in $(seq 1 30); do
    if systemctl is-active --quiet multiservis-api.service &&
       curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:8000/openapi.json"; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "=== SERVICE STATE (NO SECRETS) ===" >&2
    systemctl is-active multiservis-api.service || true
    systemctl show multiservis-api.service -p ExecMainStatus -p ActiveState -p SubState --no-pager || true
    cp -a "$BACKUP" "$P"
    systemctl restart multiservis-api.service || true
    echo "ROLLBACK: no verified API readiness after retry" >&2
    exit 1
fi
echo "PASS: FastAPI ready after restart"
echo "OWNER_INITIAL_GROUP_STATUS_PATCH_PASS"
echo "BACKUP=$BACKUP"
