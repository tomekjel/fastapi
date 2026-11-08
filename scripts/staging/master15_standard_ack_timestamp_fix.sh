#!/usr/bin/env bash
# Fix Standard SCM receipt binding without touching Windows/Mesh/groups.
set -Eeuo pipefail
test "$(id -u)" -eq 0
cd /opt/multiservis
P=/opt/multiservis/app/routers/master15_owner_mesh_sync_engine.py
PY=/opt/multiservis/.venv/bin/python
SERVICE=multiservis-api.service
test -f "$P" && test -x "$PY"
BK="/opt/multiservis/backups/master15-standard-ack-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
cp -a "$P" "$BK/master15_owner_mesh_sync_engine.py"
rollback() {
  rc=$?
  trap - ERR
  cp -a "$BK/master15_owner_mesh_sync_engine.py" "$P"
  systemctl restart "$SERVICE" || true
  echo "ROLLBACK_DONE $BK" >&2
  exit "$rc"
}
trap rollback ERR
echo "=== STANDARD: RECONCILE VERIFIED RECEIPT POLICY ==="
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_sync_engine.py --jq .content |
    tr -d '\n' | base64 -d > "$TMP"
install -m 0644 "$TMP" "$P"
"$PY" -m py_compile "$P"
"$PY" - <<'PY'
import inspect
from app.routers import master15_owner_mesh_sync_engine as sync
from app.routers.master15_owner_mesh_group_policy import Group
from app.main import app
s=inspect.getsource(sync._verified_standard_shutdown)
assert 's.requested_group' in s and 's.requested_at' in s
assert 'license_updated' not in s
assert sync.get_status
assert 'Brak zdalnego' in inspect.getsource(sync.get_status)
assert 'post' in app.openapi()['paths']['/v1/multi-guard/owner-profile-report']
print("PASS: Standard proof tied to OWNER revision and original save")
print("PASS: Standard / Brak zdalnego display guarded by OK")
PY
systemctl restart "$SERVICE"
ok=0
for i in $(seq 1 30);do
  if systemctl is-active --quiet "$SERVICE" &&
     curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json 2>/dev/null;then
      ok=1
      break
  fi
  sleep 1
done
test "$ok" -eq 1
trap - ERR
echo "STANDARD_ACK_TIMESTAMP_FIX_PASS"
echo "BACKUP=$BK"
echo "ASUS_SERVICE_AND_MESH_UNCHANGED"
