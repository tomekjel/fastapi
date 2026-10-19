#!/usr/bin/env bash
# Multi-Servis 1.10: sign unsigned APK using the ORIGINAL, root-only CT103 JKS.
# Never copies JKS out of LXC, never prints passwords, NEVER publishes the APK,
# NEVER modifies Android 1.9 or the public latest.json update manifest.
# Usage on CT103: bash sign-multiservis-android-110.sh
set -Eeuo pipefail
umask 077

[[ "${EUID}" == 0 ]] || { echo "BLOCKED: root inside CT103 required"; exit 1; }
STAGING=/root/multiservis-release-staging
IN="$STAGING/app-release-unsigned.apk"
HASH="$STAGING/app-release-unsigned.apk.sha256"
KEYDIR=/root/multiservis-signing
JKS="$KEYDIR/multi-servis-release.jks"
CONF="$KEYDIR/signing.env"
OLD=/opt/multiservis/releases/android/1.9/multi-servis-1.9.apk
OUTDIR="$KEYDIR/signed-android-1.10"
OUT="$OUTDIR/multi-servis-1.10.apk"

for f in "$IN" "$HASH" "$JKS" "$CONF" "$OLD"; do
  [[ -s "$f" && ! -L "$f" ]] || {
    echo "BLOCKED: required regular file is missing or symlinked: $f"; exit 1;
  }
done
[[ "$(stat -c %u "$JKS")" == 0 && "$(stat -c %u "$CONF")" == 0 ]] ||
  { echo "BLOCKED: JKS and signing.env must be root-owned"; exit 1; }
for executable in sha256sum aapt zipalign apksigner; do
  command -v "$executable" >/dev/null ||
    { echo "BLOCKED: no $executable. Install client tools (aapt zipalign apksigner), then rerun."; exit 1; }
done

echo "=== Unsigned APK checksum ==="
(cd "$STAGING" && sha256sum -c app-release-unsigned.apk.sha256)
size="$(stat -c %s "$IN")"
[[ "$size" -ge 1000000 && "$size" -le 150000000 ]] ||
 { echo "BLOCKED: unexpected APK size"; exit 1; }
# A previous signing certificate is an immutable compatibility baseline.
# Verify rather than trust the filename.
old_meta="$(aapt dump badging "$OLD" | grep -m 1 '^package:')"
new_meta="$(aapt dump badging "$IN" | grep -m 1 '^package:')"
[[ "$old_meta" == *"name='pl.multi_servis.owner'"*
   && "$old_meta" == *"versionCode='10'"* ]] ||
  { echo "BLOCKED: original APK not versionCode 10"; exit 1; }
[[ "$new_meta" == *"name='pl.multi_servis.owner'"*
   && "$new_meta" == *"versionCode='11'"*
   && "$new_meta" == *"versionName='1.10'"* ]] ||
  { echo "BLOCKED: unsigned APK is not Multi-Servis 1.10 (11)"; exit 1; }
if apksigner verify "$IN" >/dev/null 2>&1; then
  echo "BLOCKED: input is already signed, expected unsigned build."; exit 1;
fi
old_certificate="$(
  apksigner verify --print-certs "$OLD" |
  sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})$/\1/p' |
  head -n1 | tr '[:upper:]' '[:lower:]'
)"
[[ "$old_certificate" =~ ^[a-f0-9]{64}$ ]] ||
  { echo "BLOCKED: cannot establish cert of version 1.9"; exit 1; }

# Official root-owned signing config created for the *previous* Android release.
set -a
# shellcheck disable=SC1090
. "$CONF"
set +a
: "${KEYSTORE_PASSWORD:?Missing KEYSTORE_PASSWORD}"
: "${KEY_ALIAS:?Missing KEY_ALIAS}"
# The prior signing config contains KEYSTORE_PASSWORD and KEY_ALIAS only.
# For keys with a distinct key password, KEY_PASSWORD may be added to
# root-owned signing.env. Fallback is the keystore password.
KEY_PASSWORD="${KEY_PASSWORD:-$KEYSTORE_PASSWORD}"
export KEYSTORE_PASSWORD KEY_PASSWORD

tmp="$(mktemp -d "$STAGING/sign-android-110.XXXXXXXX")"
trap 'rm -rf "$tmp"' EXIT
echo "=== Align, sign and compare with version 1.9 ==="
zipalign -f -p 4 "$IN" "$tmp/aligned.apk" >/dev/null
apksigner sign \
  --ks "$JKS" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass env:KEYSTORE_PASSWORD \
  --key-pass env:KEY_PASSWORD \
  --out "$tmp/multi-servis-1.10.apk" "$tmp/aligned.apk"
unset KEYSTORE_PASSWORD KEY_PASSWORD
apksigner verify --verbose "$tmp/multi-servis-1.10.apk" >/dev/null
new_certificate="$(
  apksigner verify --print-certs "$tmp/multi-servis-1.10.apk" |
  sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})$/\1/p' |
  head -n1 | tr '[:upper:]' '[:lower:]'
)"
[[ "$new_certificate" == "$old_certificate" ]] || {
  echo "BLOCKED: signing certificate differs from existing version 1.9"
  exit 1
}
final_meta="$(aapt dump badging "$tmp/multi-servis-1.10.apk" | grep -m 1 '^package:')"
[[ "$final_meta" == *"name='pl.multi_servis.owner'"*
   && "$final_meta" == *"versionCode='11'"* ]] ||
  { echo "BLOCKED: signed APK failed package/version check"; exit 1; }

mkdir -p -m 0700 "$OUTDIR"
[[ ! -e "$OUT" ]] ||
  { echo "BLOCKED: output already exists; inspect before replacing"; exit 1; }
install -m 0600 "$tmp/multi-servis-1.10.apk" "$OUT"
( cd "$OUTDIR"; sha256sum multi-servis-1.10.apk >SHA256.txt )
chmod 0600 "$OUTDIR/SHA256.txt"
echo "PASS: Multi-Servis 1.10 signed with original 1.9 certificate."
echo "CERT SHA256: $new_certificate"
echo "SIGNED APK: $OUT"
echo "SIGNED FILE CHECKSUM:"
cat "$OUTDIR/SHA256.txt"
echo "NOT PUBLISHED: no update manifest or phone installation changed."
