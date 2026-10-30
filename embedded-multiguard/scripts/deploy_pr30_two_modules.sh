#!/usr/bin/env bash
# Run inside LXC 103. DRY RUN by default. Source directory holds verified files.
set -Eeuo pipefail
MODE="${1:-check}"
SOURCE="${2:-/root/multiguard-pr30-validated}"
APP=/opt/multiservis/app/routers
SERVICE=multiservis-api.service
FILES=(multiguard_license.py multiguard_remote.py)
# Production SHA-256 baselines recorded on 2026-10-29 before staging.
BASELINE_LICENSE=2ce182d97bd7b97482301d99d6ef39e24fde08df10ed36d4ab3a7dcc60c2eaec
BASELINE_REMOTE=fdf567edec7bdd79db80bbe495786622352afa0bef5b822a7a5396ba5d0bfc5a
BASELINES=("$BASELINE_LICENSE" "$BASELINE_REMOTE")
if [[ ! -f "$SOURCE/multiguard_license.py" && -f "$SOURCE/embedded-multiguard/app/routers/multiguard_license.py" ]]; then
  SOURCE="$SOURCE/embedded-multiguard/app/routers"
fi
[[ "$MODE" == check || "$MODE" == deploy ]] || { echo "Usage: $0 check|deploy [source_directory]"; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "Run as root inside LXC103"; exit 2; }
[[ -d "$APP" && -x /opt/multiservis/.venv/bin/python ]] || { echo "Unexpected production layout"; exit 2; }
for i in "${!FILES[@]}"; do
  f="${FILES[$i]}"
  [[ -f "$SOURCE/$f" && -f "$APP/$f" ]] || { echo "Missing $f"; exit 2; }
  actual=$(sha256sum "$APP/$f"); actual="${actual%% *}"
  if [[ "$actual" != "${BASELINES[$i]}" ]]; then
    echo "BLOCKED: unexpected live $f hash. Manual diff review required; no deploy."
    exit 3
  fi
  /opt/multiservis/.venv/bin/python -m py_compile "$SOURCE/$f"
  printf '%s production: ' "$f"; sha256sum "$APP/$f"
  printf '%s candidate:  ' "$f"; sha256sum "$SOURCE/$f"
  diff -u "$APP/$f" "$SOURCE/$f" > "/tmp/multiguard-pr30-${f}.diff" || test "$?" -eq 1
  echo "Difference saved to /tmp/multiguard-pr30-${f}.diff"
done
# Never deploy a remote module that lacks the OWNER page API.
# An earlier rollout produced HTTP 500 when this function was absent.
if ! grep -Fq 'def owner_remote_overview(' "$SOURCE/multiguard_remote.py"; then
  echo "BLOCKED: remote module lacks owner_remote_overview; OWNER remote page would return HTTP 500."
  exit 4
fi
if [[ "$MODE" == check ]]; then echo "CHECK ONLY: no production files changed"; exit 0; fi
[[ "${MULTIGUARD_DEPLOY_APPROVED:-}" == "YES" ]] || { echo "BLOCKED: deploy requires explicit MULTIGUARD_DEPLOY_APPROVED=YES"; exit 3; }
BACKUP="/var/backups/multiguard-pr30/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP"
chmod 700 "$BACKUP"
for f in "${FILES[@]}"; do cp -p "$APP/$f" "$BACKUP/$f"; done
printf 'backup=%s\n' "$BACKUP"
restore() {
  echo "FAILED: restoring prior modules from $BACKUP"
  for f in "${FILES[@]}"; do cp -p "$BACKUP/$f" "$APP/$f"; done
  systemctl restart "$SERVICE" || true
}
trap restore ERR
for f in "${FILES[@]}"; do install -m 644 "$SOURCE/$f" "$APP/$f"; done
/opt/multiservis/.venv/bin/python -m py_compile "${FILES[@]/#/$APP/}"
systemctl restart "$SERVICE"
systemctl is-active --quiet "$SERVICE"
# Verify HTTP availability without leaking admin endpoints or credentials.
curl -fsS --max-time 10 -o /dev/null http://127.0.0.1:8000/openapi.json
trap - ERR
echo "DEPLOY OK. Backup: $BACKUP"
