#!/usr/bin/env bash
# Run on PVE, as root, after Windows ROG sends two files via Taildrop.
# Receipt, immutable hash verification and CT103 signing ONLY. Never publish.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo "BLOCKED: root on Proxmox required"; exit 1; }
for cmd in pct tailscale sha256sum curl; do
  command -v "$cmd" >/dev/null || { echo "BLOCKED: missing $cmd"; exit 1; }
done

STAGE=/root/multiservis-android111-transfer
RECEIVED="$STAGE/multi-servis-1.11-unsigned.apk"
RECEIVED_SHA="$STAGE/multi-servis-1.11-unsigned.apk.sha256"
EXPECTED=b88f6e640b58816e5aa0b205cda3817d0c11e8afc5f944abb42be0e073a048d2
SIGNER_URL=https://raw.githubusercontent.com/tomekjel/fastapi/e77f93d51366935d02935b92cbec3590bcee60eb/embedded-multiguard/scripts/sign-multiservis-android-111.sh
SIGNER_TARGET=/root/multiservis-release-staging-111/sign-android-111.sh

install -d -m 0700 "$STAGE"
if [[ ! -s "$RECEIVED" || ! -s "$RECEIVED_SHA" ]]; then
  echo "=== Receiving 1.11 unsigned APK from ASUS ROG over Taildrop ==="
  tailscale file get "$STAGE"
fi
for item in "$RECEIVED" "$RECEIVED_SHA"; do
  [[ -f "$item" && -s "$item" && ! -L "$item" ]] ||
    { echo "BLOCKED: missing Taildrop file: $item"; exit 1; }
done
echo "=== Verify exact 1.11 APK sent from ROG ==="
(cd "$STAGE" && sha256sum -c multi-servis-1.11-unsigned.apk.sha256)
[[ "$(sha256sum "$RECEIVED" | cut -d' ' -f1)" == "$EXPECTED" ]] ||
  { echo "BLOCKED: unsigned APK changed since ROG build"; exit 1; }
pct status 103 | grep -q running ||
  { echo "BLOCKED: CT103 is offline"; exit 1; }

pct exec 103 -- install -d -m 0700 /root/multiservis-release-staging-111
printf '%s  app-release-unsigned.apk\n' "$EXPECTED" > "$STAGE/app-release-unsigned.apk.sha256"
pct push 103 "$RECEIVED" /root/multiservis-release-staging-111/app-release-unsigned.apk
pct push 103 "$STAGE/app-release-unsigned.apk.sha256" /root/multiservis-release-staging-111/app-release-unsigned.apk.sha256
pct exec 103 -- sh -c 'cd /root/multiservis-release-staging-111 && sha256sum -c app-release-unsigned.apk.sha256'

echo "=== Load pinned owner-only signing script ==="
pct exec 103 -- curl --fail --show-error --silent --location --max-time 45 \
  "$SIGNER_URL" -o "$SIGNER_TARGET"
echo "=== Sign using original JKS held only on CT103 ==="
pct exec 103 -- bash "$SIGNER_TARGET"

pct pull 103 /root/multiservis-signing/signed-android-1.11/multi-servis-1.11.apk \
  "$STAGE/multi-servis-1.11.apk"
pct pull 103 /root/multiservis-signing/signed-android-1.11/SHA256.txt \
  "$STAGE/SHA256-signed.txt"
chmod 0600 "$STAGE/multi-servis-1.11.apk" "$STAGE/SHA256-signed.txt"
(cd "$STAGE" && sha256sum -c SHA256-signed.txt)
echo "=== PASS: Multi-Servis 1.11 signed and verified on PVE ==="
echo "SIGNED APK: $STAGE/multi-servis-1.11.apk"
echo "NOT PUBLISHED. Public Android 1.10 and phones are unchanged."
