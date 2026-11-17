#!/usr/bin/env bash
# MASTER 1.10: targeted OWNER Standard receipt-order fix.
# Run only within LXC 103, never on Windows. No database writes or Mesh moves.
set -Eeuo pipefail
test "$(id -u)" -eq 0 || { echo "STOP: ROOT_REQUIRED"; exit 1; }
cd /opt/multiservis
SRC=/opt/multiservis/app/routers/master15_owner_profile_bridge.py
PY=/opt/multiservis/.venv/bin/python
SERVICE=multiservis-api.service
test -f "$SRC" && test -x "$PY" || { echo "STOP: EXPECTED_OWNER_BRIDGE_MISSING"; exit 1; }
command -v gh >/dev/null || { echo "STOP: GH_REQUIRED"; exit 1; }
export GH_CONFIG_DIR=/root/.config/gh-tomekjel
gh auth status -h github.com >/dev/null 2>&1 || { echo "STOP: GH_AUTH_REQUIRED"; exit 1; }
TMP="$(mktemp)"
BACKUP="/opt/multiservis/backups/owner-standard-receipt-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a "$SRC" "$BACKUP/master15_owner_profile_bridge.py"
installed=0
rollback() {
  ec=$?
  trap - ERR
  if [ "$installed" -eq 1 ]; then
    cp -a "$BACKUP/master15_owner_profile_bridge.py" "$SRC"
    systemctl restart "$SERVICE" || true
    echo "ROLLBACK: ORIGINAL_OWNER_BRIDGE_RESTORED"
  fi
  rm -f "$TMP"
  exit "$ec"
}
trap rollback ERR
echo "=== OWNER STANDARD: PREFLIGHT ==="
# Pin immutable commit, not current branch head. Do not modify any other source.
gh api "repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_profile_bridge.py?ref=9d403414aa212d5f04ad02940a2cf2a9f92095d8" --jq .content |
  tr -d '\n' | base64 -d > "$TMP"
"$PY" - "$SRC" "$TMP" <<'PY'
from pathlib import Path
import ast,sys
old=Path(sys.argv[1]).read_text(encoding="utf-8")
new=Path(sys.argv[2]).read_text(encoding="utf-8")
for code in (old,new):
    ast.parse(code)
    assert 'def _sync_standard_after_verified_ack(' in code
    assert 'def owner_profile_report(' in code
    assert '@router.post("/owner-profile-report")' in code
assert "t.reservation_id=:reservation_id" in new
assert "if previous is None:" in new
assert "sync.ensure_schema(db)" in new
assert "background_tasks.add_task(_sync_standard_after_verified_ack, req.installationId, req.reservationId)" in new
# Do not deploy over unknown/more recent live implementation.
assert 'def _sync_standard_after_verified_ack(iid: UUID)' in old or 'def _sync_standard_after_verified_ack(iid: UUID, reservation_id: UUID)' in old, "STOP: UNKNOWN_LIVE_BRIDGE"
print("PASS: ONLY_EXISTING_OWNER_BRIDGE; EXACT_SIGNED_RESERVATION")
PY
echo "=== BACKUP AND DEPLOY ==="
install -m 0644 "$TMP" "$SRC"
installed=1
"$PY" -m py_compile "$SRC"
"$PY" - <<'PY'
from app.main import app
from app.routers import master15_owner_profile_bridge as bridge
assert "post" in app.openapi()["paths"].get("/v1/multi-guard/owner-profile-report",{})
assert bridge._sync_standard_after_verified_ack.__code__.co_argcount == 2
print("PASS: IMPORT_AND_OWNER_REPORT_ROUTE")
PY
systemctl restart "$SERVICE"
READY=0
for _ in $(seq 1 30); do
  if systemctl is-active --quiet "$SERVICE" && curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:8000/openapi.json; then
    READY=1; break
  fi
  sleep 1
done
test "$READY" -eq 1 || { echo "STOP: API_NOT_READY"; exit 1; }
echo "PASS: LIVE_API_HTTP_200"
rm -f "$TMP"
installed=0
trap - ERR
echo "=== READ-ONLY OWNER STATUS ==="
"$PY" - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import master15_owner_mesh_sync_engine as sync
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT p.installation_id,p.hostname,s.requested_group,s.status,s.attempts,
             s.last_error,t.target_mode,t.state AS windows_state
      FROM guard.pending_installations p
      LEFT JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
      LEFT JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
      WHERE upper(coalesce(p.hostname,'')) LIKE '%THINKPAD%'
         OR upper(coalesce(p.hostname,'')) LIKE '%LENOVO%'
      ORDER BY p.updated_at DESC LIMIT 5
    """)).mappings().all()
    if not rows:
        print("INFO: NO_LENOVO_HOSTNAME_MATCH; MANUAL_OWNER_STATUS_REVIEW_NEEDED")
    for r in rows:
        print("COMPUTER:",r["hostname"],"GROUP:",r["requested_group"],"SYNC:",r["status"],
              "ATTEMPTS:",r["attempts"],"ERROR:",r["last_error"],
              "WINDOWS:",r["target_mode"],"/",r["windows_state"])
        try:
            print("WINDOWS_STANDARD_ACK_VALID:",sync._verified_standard_shutdown(db,r["installation_id"]))
        except Exception as e:
            print("WINDOWS_ACK_QUERY_ERROR:",type(e).__name__)
print("READ_ONLY_DIAGNOSTIC_COMPLETE")
PY
echo "=== DEPLOY PASS: ONLY OWNER BRIDGE; NO LENOVO/MESH/LICENCE MODIFICATIONS ==="
echo "BACKUP=$BACKUP"
