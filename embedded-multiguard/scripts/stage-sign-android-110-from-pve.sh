#!/usr/bin/env bash
# Run on Proxmox PVE host (NOT in CT103) after staging unsigned APK over SSH.
# This only creates a signed 1.10 APK and never publishes it or modifies 1.9.
set -Eeuo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo "BLOCKED: root on Proxmox required"; exit 1; }
command -v pct >/dev/null || { echo "BLOCKED: pct only available on Proxmox"; exit 1; }
STAGE=/root/multiservis-android110-transfer
install -d -m 0700 "$STAGE"
if [[ ! -s "$STAGE/app-release-unsigned.apk" ||
      ! -s "$STAGE/app-release-unsigned.apk.sha256" ]]; then
    echo "=== Odbieram niepodpisany APK przez Tailscale Taildrop ==="
    command -v tailscale >/dev/null ||
      { echo "BLOCKED: Tailscale is not installed on PVE"; exit 1; }
    tailscale file get "$STAGE"
fi
for f in "$STAGE/app-release-unsigned.apk" "$STAGE/app-release-unsigned.apk.sha256"; do
    [[ -s "$f" && ! -L "$f" ]] || { echo "BLOCKED: missing unsigned upload $f"; exit 1; }
done
echo "=== Verify incoming unsigned APK ==="
(cd "$STAGE" && sha256sum -c app-release-unsigned.apk.sha256)

pct status 103 | grep -q running || { echo "BLOCKED: CT103 is not running"; exit 1; }
pct exec 103 -- mkdir -p -m 0700 /root/multiservis-release-staging
pct push 103 "$STAGE/app-release-unsigned.apk" \
  /root/multiservis-release-staging/app-release-unsigned.apk
pct push 103 "$STAGE/app-release-unsigned.apk.sha256" \
  /root/multiservis-release-staging/app-release-unsigned.apk.sha256

echo "=== Install Android signing utilities on CT103 (no removal or server changes) ==="
pct exec 103 -- env DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-remove --no-install-recommends \
  aapt zipalign apksigner default-jre-headless

echo "=== Read pinned signing script into CT103 ==="
pct exec 103 -- curl --fail --show-error --silent --location \
  --max-time 30 \
  "https://raw.githubusercontent.com/tomekjel/fastapi/2438b0ce54191f7fba31fe1dbd0d107653ac5753/embedded-multiguard/scripts/sign-multiservis-android-110.sh" \
  -o /root/multiservis-release-staging/sign-android-110.sh

echo "=== Sign with root-only original JKS; compare signature to 1.9 ==="
pct exec 103 -- bash /root/multiservis-release-staging/sign-android-110.sh

echo "=== Download nonsecret signed APK from CT103 onto Proxmox ==="
pct pull 103 /root/multiservis-signing/signed-android-1.10/multi-servis-1.10.apk \
  "$STAGE/multi-servis-1.10.apk"
pct pull 103 /root/multiservis-signing/signed-android-1.10/SHA256.txt \
  "$STAGE/SHA256.txt"
chmod 0600 "$STAGE/multi-servis-1.10.apk" "$STAGE/SHA256.txt"
(cd "$STAGE" && sha256sum -c SHA256.txt)
echo "PASS: signed 1.10 APK ready for SCP download from PVE."
echo "SERVER FILE: $STAGE/multi-servis-1.10.apk"
echo "No update manifest changed. Nothing installed on phone."
