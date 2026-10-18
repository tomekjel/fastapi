#!/usr/bin/env bash
set -Eeuo pipefail
SHA="3b441e59a5d0e305719eeb4732c0cdb75cac21ab"
ROOT=/opt/multiservis
STATE=/var/lib/multiservis-owner-v12/state.json
ROUTERS="$ROOT/app/routers"
SERVICE=multiservis-api.service
TIMER=multiservis-owner-v12-pull.timer
B="$(mktemp -d /opt/multiservis/backups/remote-pro-20261018-XXXXXX)"
ST="$(mktemp -d)"
FILES=(multiguard_remote.py multiguard_workshop_remote.py)
CHANGED=0
PAUSED=0
cleanup() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ "$CHANGED" -eq 1 ]; then
    echo "ROLLBACK: restoring two router modules"
    for file in "${FILES[@]}"; do cp -p "$B/$file" "$ROUTERS/$file"; done
    systemctl restart "$SERVICE" || true
  fi
  if [ "$PAUSED" -eq 1 ]; then systemctl start "$TIMER" || true; fi
  rm -rf "$ST"
  exit "$rc"
}
trap cleanup EXIT
test -f "$STATE"
test -x "$ROOT/.venv/bin/python"
systemctl is-active --quiet "$SERVICE"
for file in "${FILES[@]}"; do
  test -s "$ROUTERS/$file"
  cp -p "$ROUTERS/$file" "$B/$file"
  curl -fsSL --retry 3 --connect-timeout 8 --max-time 30 \
    "https://raw.githubusercontent.com/tomekjel/fastapi/$SHA/embedded-multiguard/app/routers/$file" -o "$ST/$file"
done
"$ROOT/.venv/bin/python" -m py_compile "$ST"/*.py
grep -Fq 'app.include_router(multiguard_remote.router)' "$ROOT/app/main.py"
grep -Fq 'app.include_router(multiguard_workshop_remote.router)' "$ROOT/app/main.py"
systemctl stop "$TIMER"
PAUSED=1
for file in "${FILES[@]}"; do install -m 0644 "$ST/$file" "$ROUTERS/$file"; done
CHANGED=1
systemctl restart "$SERVICE"
systemctl is-active --quiet "$SERVICE"
PASS=0
for attempt in $(seq 1 20); do
  if curl -fsS --max-time 8 https://api.multi-servis.pl/openapi.json -o "$ST/openapi.json" 2>/dev/null; then
    if "$ROOT/.venv/bin/python" - "$ST/openapi.json" <<'PY'
import json,sys
paths=json.load(open(sys.argv[1]))['paths']
required=[
'/multiguard/panel/remote',
'/multiguard/panel/remote/workshop/{installation_id}',
'/multiguard/panel/remote-api/workshop/request/{installation_id}',
'/multiguard/panel/remote-api/workshop/sessions/{session_id}',
'/multiguard/panel/remote-api/workshop/sessions/{session_id}/connect',
'/multiguard/panel/remote-api/workshop/sessions/{session_id}/end',
'/multiguard/panel/remote/session/{request_id}',
'/multiguard/agent/workshop/remote/poll',
'/multiguard/agent/heartbeat',
]
assert all(p in paths for p in required),[p for p in required if p not in paths]
print('PASS: service PRO remote routes and agent API')
PY
    then PASS=1; break; fi
  fi
  sleep 2
done
test "$PASS" -eq 1
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.multi-servis.pl/multiguard/panel/remote)" = "401"
CHANGED=0
systemctl start "$TIMER"
PAUSED=0
echo "SUCCESS: remote PRO modules deployed from $SHA"
echo "BACKUP: $B"
echo "NOTE: deployment is not proof of remote desktop E2E."
