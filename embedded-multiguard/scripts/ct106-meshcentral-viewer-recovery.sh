#!/usr/bin/env bash
# CT106 only: atomic viewer patch; original agent, consent and OWNER untouched.
# Run manually as root after reviewing the owner-only offline test results.
set -Eeuo pipefail
if [[ "$(id -u)" != 0 ]]; then echo "BLOCKED: root required"; exit 1; fi
systemctl is-active --quiet meshcentral || { echo "BLOCKED: meshcentral is not active"; exit 1; }
OLD=bc5057e86ec44bc58ea1ad2918dc524b5faa614431a62a113a79f0a99793962d
NEW='' # computed after exactly one controlled replacement
# Abort on unknown/multiple installations, custom files, or newer versions.
FOUND="$(find /opt /usr/local/lib/node_modules /root -type f -name agent-desktop-0.0.2.js -print 2>/dev/null || true)"
if [[ -z "$FOUND" || "$FOUND" == *$'\n'* || ! "$FOUND" =~ ^/[a-zA-Z0-9_./-]+$ ]]; then
  echo "BLOCKED: exactly one recognized MeshCentral viewer path is required"; exit 1
fi
VIEWER="$FOUND"
PKG="$(dirname "$(dirname "$(dirname "$VIEWER")")")/package.json"
if [[ ! -f "$PKG" ]]; then echo "BLOCKED: package.json missing"; exit 1; fi
python3 - "$PKG" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f:
    assert json.load(f)["version"]=="1.2.5", "BLOCKED: only MeshCentral 1.2.5 supported"
print("PASS: version 1.2.5")
PY
if [[ "$(sha256sum "$VIEWER" | cut -d' ' -f1)" != "$OLD" ]]; then
  echo "BLOCKED: live viewer differs from verified CT106 SHA256; no changes"; exit 1
fi
STAGE="$(mktemp -d)"
BACKUP="/var/backups/multi-guard-meshcentral-viewer-$(date -u +%Y%m%dT%H%M%SZ)"
CHANGED=0
cleanup() {
  rc=$?
  trap - EXIT
  if ((rc != 0 && CHANGED != 0)); then
    echo "ROLLBACK: restore viewer and restart MeshCentral"
    cp -p "$BACKUP/original.js" "$VIEWER"
    systemctl restart meshcentral || true
  fi
  rm -rf "$STAGE"
  exit "$rc"
}
trap cleanup EXIT
install -d -m 0700 "$BACKUP"
cp -p "$VIEWER" "$BACKUP/original.js"
python3 - "$VIEWER" "$STAGE/new.js" <<'PY'
import hashlib,pathlib,sys
src=pathlib.Path(sys.argv[1]).read_bytes().decode("utf-8")
old="        tile.error = function () { console.log('DecodeTileError'); }"
new="""        tile.onerror = function () {
            // A failed JPEG decode must still consume its ordered picture slot;
            // otherwise every later tile waits forever for this sequence id.
            obj.PendingOperations.push([r, 0]);
            while (obj.DoPendingOperations()) { }
            // The skipped tile could now contain stale pixels. Request a
            // bounded full redraw rather than resending on every bad JPEG.
            if (obj.State != 0) {
                var now = Date.now();
                if (obj.lastDecodeRecoveryAt == null || now - obj.lastDecodeRecoveryAt >= 5000) {
                    obj.lastDecodeRecoveryAt = now;
                    obj.SendRefresh();
                }
            }
        }"""
if src.count(old)!=1: raise SystemExit("BLOCKED: upstream handler not found exactly once")
out=src.replace(old,new,1).encode("utf-8")
hash=hashlib.sha256(out).hexdigest()
assert out != pathlib.Path(sys.argv[1]).read_bytes(), "BLOCKED: patch did not change source"
assert out.count(b"tile.onerror = function") == 1 and out.count(b"tile.error = function") == 0, "BLOCKED: ambiguous image callbacks"
pathlib.Path(sys.argv[2]).write_bytes(out)
print("PASS: tested JPEG callback applied to pinned CT106 source")
print("PATCHED_VIEWER_SHA256:", hash)
PY
node --check "$STAGE/new.js"
NEW="$(sha256sum "$STAGE/new.js" | cut -d' ' -f1)"
if [[ ! "$NEW" =~ ^[a-f0-9]{64}$ ]]; then echo "BLOCKED: candidate checksum invalid"; exit 1; fi
install -m "$(stat -c %a "$VIEWER")" -o "$(stat -c %u "$VIEWER")" \
  -g "$(stat -c %g "$VIEWER")" "$STAGE/new.js" "$VIEWER.mg-tmp-$$"
mv -f "$VIEWER.mg-tmp-$$" "$VIEWER"
CHANGED=1
systemctl restart meshcentral
for i in $(seq 1 15); do
  if systemctl is-active --quiet meshcentral; then break; fi
  sleep 1
done
systemctl is-active --quiet meshcentral
test "$(sha256sum "$VIEWER" | cut -d' ' -f1)" = "$NEW"
CHANGED=0
echo "PASS: CT106 viewer updated and MeshCentral active"
echo "BACKUP: $BACKUP/original.js"
echo "UNCHANGED: Lenovo, MeshAgent, OWNER, remote authorization and consent"
