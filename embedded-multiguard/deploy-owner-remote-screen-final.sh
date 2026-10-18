#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=/opt/multiservis
SHA=c81b61fc52c8cfef4fff833314c603763c262f8b
R=$ROOT/app/routers
B=$ROOT/backups/remote-screen-verified-$(date +%Y%m%d-%H%M%S)
T=$(mktemp -d)
CHANGED=0
PAUSED=0
mkdir -m 700 "$B"
cp -p "$R/multiguard_remote.py" "$B/remote.py"
cp -p "$R/multiguard_runtime.py" "$B/runtime.py"
finish() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    cp -p "$B/remote.py" "$R/multiguard_remote.py"
    cp -p "$B/runtime.py" "$R/multiguard_runtime.py"
    systemctl restart multiservis-api.service || true
    echo ROLLBACK
  fi
  if [ "$PAUSED" -eq 1 ]; then systemctl start multiservis-owner-v12-pull.timer || true; fi
  rm -rf "$T"
  exit "$rc"
}
trap finish EXIT
curl -fsSL --retry 3 --max-time 40 "https://raw.githubusercontent.com/tomekjel/fastapi/$SHA/embedded-multiguard/app/routers/multiguard_remote.py" -o "$T/new_remote.py"
$ROOT/.venv/bin/python -m py_compile "$T/new_remote.py"
systemctl stop multiservis-owner-v12-pull.timer
PAUSED=1
install -m 0644 "$T/new_remote.py" "$R/multiguard_remote.py"
CHANGED=1
cd "$ROOT"
PYTHONPATH="$ROOT" "$ROOT/.venv/bin/python" - <<'PY'
from app.routers.multiguard_remote import owner_remote_overview
r=owner_remote_overview()
h=r.body.decode('utf-8')
assert r.status_code==200, r.status_code
assert '<h2>1. PRO' in h, 'Missing workshop group'
assert '<h2>2. Zgłoszenia klientów PRO' in h, 'Missing customer group'
assert '<table' in h, 'Missing table'
assert 'Internal Server Error' not in h
print('PASS: live DB and actual rendered OWNER HTML',len(h))
PY
$ROOT/.venv/bin/python - "$R/multiguard_runtime.py" "$T/runtime.py" <<'PY'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text(encoding='utf-8')
a="@router.get('/panel/remote', response_class=HTMLResponse)"
i=s.find(a)
j=s.find('\n\ndef _owner_remote_actor(',i)
assert i>=0 and j>i and s.count(a)==1, 'Unexpected old route'
old=s[i:j]
assert 'def owner_remote_panel(' in old and '_owner_remote_workspace(' in old, 'Unknown live code; refusing replacement'
new="""@router.get('/panel/remote', response_class=HTMLResponse)
def owner_remote_panel(selected: Optional[uuid.UUID] = None, q: str = '', _: None = Depends(_panel_auth)):
    from app.routers import multiguard_remote
    return multiguard_remote.owner_remote_overview()
"""
Path(sys.argv[2]).write_text(s[:i]+new+s[j:],encoding='utf-8')
PY
$ROOT/.venv/bin/python -m py_compile "$T/runtime.py"
install -m 0644 "$T/runtime.py" "$R/multiguard_runtime.py"
systemctl restart multiservis-api.service
systemctl is-active --quiet multiservis-api.service
HTTP=000
for attempt in $(seq 1 15); do
  HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 https://api.multi-servis.pl/multiguard/panel/remote || true)
  if [ "$HTTP" = 401 ]; then break; fi
  sleep 2
done
test "$HTTP" = 401
CHANGED=0
systemctl start multiservis-owner-v12-pull.timer
PAUSED=0
echo 'SUCCESS: Render-verified OWNER screen enabled'
echo "BACKUP: $B"
