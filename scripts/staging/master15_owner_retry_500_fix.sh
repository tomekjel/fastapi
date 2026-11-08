#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
PY=/opt/multiservis/.venv/bin/python
P=/opt/multiservis/app/routers/master15_owner_mesh_retry_router.py
BACKUP="/opt/multiservis/backups/master15-owner-retry-fix-$(date +%Y%m%d-%H%M%S).py"
test -r "$P" && test -x "$PY"
cp -a "$P" "$BACKUP"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
gh api repos/tomekjel/fastapi/contents/scripts/staging/master15_owner_mesh_retry_router.py --jq .content | tr -d '\n' | base64 -d > "$TMP"
"$PY" -m py_compile "$TMP"
install -m 0644 "$TMP" "$P"
echo "=== OWNER PONOW CORRECTION ==="
"$PY" - <<'PY'
from app.routers import master15_owner_mesh_retry_router as route
from app.routers.multiguard_panel_settings import _token_valid
from app.main import app
assert route._token_valid is _token_valid
paths=app.openapi()["paths"]
assert "/multiguard/panel/licenses-grid/{link_id}/mesh-retry" in paths
print("PASS: correct OWNER CSRF validator and retry route")
PY
systemctl restart multiservis-api.service
READY=0
for i in $(seq 1 35); do
  if systemctl is-active --quiet multiservis-api.service &&
     curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:8000/openapi.json 2>/dev/null; then
    READY=1; break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  install -m 0644 "$BACKUP" "$P"
  systemctl restart multiservis-api.service || true
  echo "ROLLBACK: API failed to become ready" >&2
  exit 1
fi
echo "PASS: API HTTP 200"
echo "=== MESH MOVE ERROR CONTRACT READONLY ==="
"$PY" - <<'PY'
import inspect
from app.routers import multiguard_meshcentral as mc
for name in ("_run","_auto_mesh_command","move_registered_node_to_group"):
    f=getattr(mc,name)
    print(name, "SIGNATURE",inspect.signature(f))
    src=inspect.getsource(f)
    for line in src.splitlines():
        line=line.strip()
        if "MeshCentralError(" in line or "subprocess.run(" in line or "return _run(" in line or "MoveToDeviceGroup" in line or "check=" in line:
            print("  ",line[:190])
print("=== READONLY END ===")
PY
echo "PASS: OWNER PONOW ERROR 500 FIX INSTALLED"
echo "BACKUP=$BACKUP"
