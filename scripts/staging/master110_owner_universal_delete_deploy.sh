#!/usr/bin/env bash
set -Eeuo pipefail
export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh-tomekjel}"
cd /opt/multiservis
FILE=/opt/multiservis/app/routers/multiguard_license.py
MARK=MASTER110_UNIVERSAL_DELETE_RIGHTS_V1
if [[ ! -s "$FILE" ]]; then echo "STOP SOURCE_MISSING"; exit 2; fi
echo "=== OWNER UNIVERSAL REMOVE FIX: DEPLOY + CHECK ==="
if grep -Fq "$MARK" "$FILE"; then
 echo "ALREADY_PRESENT: SAME UNIVERSAL PATCH"
 exit 0
fi
TMP="$(mktemp /tmp/mg-universal-delete-XXXXXX.py)"
PREV="$(mktemp /tmp/mg-universal-delete-original-XXXXXX.py)"
cp -p "$FILE" "$PREV"
cleanup(){ rm -f "$TMP" "$PREV"; }
trap cleanup EXIT
gh api "repos/tomekjel/fastapi/contents/scripts/staging/master110_owner_universal_delete_rights_patch.py?ref=ea81b710e8135a548161932ea577457d986c6822" --jq .content | base64 -d > "$TMP"
echo "--- SOURCE VALIDATION + PATCH ---"
/opt/multiservis/.venv/bin/python "$TMP"
echo "--- PYTHON COMPILATION ---"
/opt/multiservis/.venv/bin/python -m py_compile "$FILE"
echo "--- SERVICE RESTART ---"
if ! systemctl restart multiservis-api.service; then
 echo "ERROR RESTART — RESTORING"
 cp -p "$PREV" "$FILE"
 systemctl restart multiservis-api.service || true
 exit 3
fi
sleep 3
if ! systemctl is-active --quiet multiservis-api.service; then
 echo "ERROR SERVICE_INACTIVE — RESTORING"
 cp -p "$PREV" "$FILE"
 systemctl restart multiservis-api.service || true
 exit 4
fi
echo "PASS PATCH_INSTALLED"
echo "PASS API_SERVICE_ACTIVE"
echo "NOTE: MeshCentral RemoveDevice still requires real group permission; this patch does not bypass Denied."
echo "=== END ==="
