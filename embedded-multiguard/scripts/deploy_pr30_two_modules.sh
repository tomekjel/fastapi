#!/usr/bin/env bash
# Run inside LXC 103. DRY RUN by default. Source directory holds verified files.
set -Eeuo pipefail
MODE="${1:-check}"
SOURCE="${2:-/root/multiguard-pr30-validated}"
APP=/opt/multiservis/app/routers
SERVICE=multiservis-api.service
FILES=(multiguard_license.py multiguard_remote.py)
[[ "$MODE" == check || "$MODE" == deploy ]] || { echo "Usage: $0 check|deploy [source_directory]"; exit 2; }
[[ "$(id -u)" == 0 ]] || { echo "Run as root inside LXC103"; exit 2; }
[[ -d "$APP" && -x /opt/multiservis/.venv/bin/python ]] || { echo "Unexpected production layout"; exit 2; }
for f in "${FILES[@]}"; do
  [[ -f "$SOURCE/$f" && -f "$APP/$f" ]] || { echo "Missing $f"; exit 2; }
  /opt/multiservis/.venv/bin/python -m py_compile "$SOURCE/$f"
  printf '%s production: ' "$f"; sha256sum "$APP/$f"
  printf '%s candidate:  ' "$f"; sha256sum "$SOURCE/$f"
  diff -u "$APP/$f" "$SOURCE/$f" > "/tmp/multiguard-pr30-${f}.diff" || test "$?" -eq 1
  echo "Difference saved to /tmp/multiguard-pr30-${f}.diff"
done
if [[ "$MODE" == check ]]; then echo "CHECK ONLY: no production files changed"; exit 0; fi
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
