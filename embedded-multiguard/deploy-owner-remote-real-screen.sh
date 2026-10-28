#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=/opt/multiservis
ROUTERS="$ROOT/app/routers"
SHA=5d5082b86a6e0c05ce3630fac72552a6a58b060f
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$ROOT/backups/owner-real-remote-screen-$STAMP"
STAGE="$(mktemp -d)"
CHANGED=0
PAUSED=0
cleanup() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    echo "ROLLBACK: original OWNER screen and remote modules"
    for f in multiguard_runtime.py multiguard_remote.py multiguard_workshop_remote.py; do
      cp -p "$BACKUP/$f" "$ROUTERS/$f"
    done
    systemctl restart multiservis-api.service || true
  fi
  if [ "$PAUSED" -eq 1 ]; then systemctl start multiservis-owner-v12-pull.timer || true; fi
  rm -rf "$STAGE"
  exit "$rc"
}
trap cleanup EXIT
mkdir -m 700 "$BACKUP"
for f in multiguard_runtime.py multiguard_remote.py multiguard_workshop_remote.py; do
  cp -p "$ROUTERS/$f" "$BACKUP/$f"
done
URL="https://raw.githubusercontent.com/tomekjel/fastapi/$SHA/embedded-multiguard/app/routers"
for f in multiguard_remote.py multiguard_workshop_remote.py; do
  curl -fsSL --retry 3 --max-time 40 "$URL/$f" -o "$STAGE/$f"
done
# Patch ONLY the duplicate legacy /panel/remote handler in the live runtime.
# Never replace runtime.py as it hosts Android/agent endpoints.
"$ROOT/.venv/bin/python" - "$ROUTERS/multiguard_runtime.py" "$STAGE/multiguard_runtime.py" <<'PY'
from pathlib import Path
import sys
src=Path(sys.argv[1]).read_text(encoding='utf-8')
anchor="@router.get('/panel/remote', response_class=HTMLResponse)"
start=src.find(anchor)
end=src.find("\n\ndef _owner_remote_actor(",start)
if start<0 or end<0 or src.count(anchor)!=1:
    raise SystemExit("BLOCKED: legacy OWNER route not found exactly once")
existing=src[start:end]
if "def owner_remote_panel(" not in existing or "_owner_remote_workspace(" not in existing:
    raise SystemExit("BLOCKED: unexpected live OWNER route; no changes made")
updated='''@router.get('/panel/remote', response_class=HTMLResponse)
def owner_remote_panel(selected: Optional[uuid.UUID] = None, q: str = '', _: None = Depends(_panel_auth)):
    """OWNER sidebar uses the unified remote PRO fleet instead of legacy 2-column UI."""
    from app.routers import multiguard_remote as remote
    return remote.owner_remote_overview()
'''
Path(sys.argv[2]).write_text(src[:start]+updated+src[end:],encoding='utf-8')
PY
"$ROOT/.venv/bin/python" -m py_compile "$STAGE"/*.py
systemctl stop multiservis-owner-v12-pull.timer
PAUSED=1
for f in multiguard_runtime.py multiguard_remote.py multiguard_workshop_remote.py; do
  install -m 0644 "$STAGE/$f" "$ROUTERS/$f"
done
CHANGED=1
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
PASS=0
for n in $(seq 1 20); do
  if curl -fsS --max-time 10 https://api.multi-servis.pl/openapi.json -o "$STAGE/openapi.json" 2>/dev/null; then
    if "$ROOT/.venv/bin/python" - "$STAGE/openapi.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))["paths"]
for name in ("/multiguard/panel/remote","/multiguard/panel/remote/workshop/{installation_id}","/multiguard/agent/heartbeat","/multiguard/agent/workshop/remote/poll"):
    assert name in p,name
print("PASS: new OWNER remote and original agent routes")
PY
    then PASS=1;break;fi
  fi
  sleep 2
done
test "$PASS" -eq 1
test "$(curl -sS -o /dev/null -w '%{http_code}' https://api.multi-servis.pl/multiguard/panel/remote)" = "401"
CHANGED=0
systemctl start multiservis-owner-v12-pull.timer
PAUSED=0
echo "SUCCESS: original OWNER sidebar Remote Help switched to unified PRO UI"
echo "BACKUP: $BACKUP"
