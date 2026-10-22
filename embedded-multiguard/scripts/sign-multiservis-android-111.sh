#!/usr/bin/env bash
# Multi-Servis 1.11 (12), owner-only signing in CT103.
# Never publishes, changes latest.json, exposes the JKS or installs on Android.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo "BLOCKED: only CT103 root may sign"; exit 1; }

STAGING=/root/multiservis-release-staging-111
IN="$STAGING/app-release-unsigned.apk"
HASH="$STAGING/app-release-unsigned.apk.sha256"
KEYDIR=/root/multiservis-signing
JKS="$KEYDIR/multi-servis-release.jks"
CONF="$KEYDIR/signing.env"
PREVIOUS=/opt/multiservis/releases/android/1.10/multi-servis-1.10.apk
OUTDIR="$KEYDIR/signed-android-1.11"
OUT="$OUTDIR/multi-servis-1.11.apk"
EXPECTED_UNSIGNED=b88f6e640b58816e5aa0b205cda3817d0c11e8afc5f944abb42be0e073a048d2
EXPECTED_PREVIOUS=813270de4ca48df84471899c11b1d08eef0f04e62ce2fe5924f37a81a842a075
EXPECTED_CERT=b6a736c267c7a21c77481e8b009205529d24221925890b64ee6784484ae633fa

for f in "$IN" "$HASH" "$JKS" "$CONF" "$PREVIOUS"; do
  [[ -s "$f" && -f "$f" && ! -L "$f" ]] || { echo "BLOCKED: missing or unsafe file: $f"; exit 1; }
done
[[ "$(stat -c %u "$JKS")" == 0 && "$(stat -c %u "$CONF")" == 0 ]] ||
  { echo "BLOCKED: signing secrets are not root-owned"; exit 1; }
for binary in sha256sum aapt zipalign apksigner; do
  command -v "$binary" >/dev/null || { echo "BLOCKED: missing $binary"; exit 1; }
done

echo "=== Version and source integrity ==="
( cd "$STAGING" && sha256sum -c app-release-unsigned.apk.sha256 )
[[ "$(sha256sum "$IN" | cut -d' ' -f1)" == "$EXPECTED_UNSIGNED" ]] ||
  { echo "BLOCKED: unsigned release SHA256 does not match owner's ROG build"; exit 1; }
[[ "$(sha256sum "$PREVIOUS" | cut -d' ' -f1)" == "$EXPECTED_PREVIOUS" ]] ||
  { echo "BLOCKED: published prior version has unexpected hash"; exit 1; }
size="$(stat -c %s "$IN")"
[[ "$size" -ge 1000000 && "$size" -le 150000000 ]] ||
  { echo "BLOCKED: suspicious unsigned APK size"; exit 1; }
oldmeta="$(aapt dump badging "$PREVIOUS")"
newmeta="$(aapt dump badging "$IN")"
[[ "$oldmeta" == *"name='pl.multi_servis.owner'"* &&
   "$oldmeta" == *"versionCode='11'"* &&
   "$oldmeta" == *"versionName='1.10'"* ]] ||
  { echo "BLOCKED: previous APK is not expected version 1.10 (11)"; exit 1; }
[[ "$newmeta" == *"name='pl.multi_servis.owner'"* &&
   "$newmeta" == *"versionCode='12'"* &&
   "$newmeta" == *"versionName='1.11'"* ]] ||
  { echo "BLOCKED: incoming APK is not Multi-Servis 1.11 (12)"; exit 1; }
if apksigner verify "$IN" >/dev/null 2>&1; then
  echo "BLOCKED: incoming APK already signed"; exit 1
fi
oldcert="$(apksigner verify --print-certs "$PREVIOUS" |
  sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})$/\1/p' |
  head -n1 | tr '[:upper:]' '[:lower:]')"
[[ "$oldcert" == "$EXPECTED_CERT" ]] ||
  { echo "BLOCKED: 1.10 signer does not match pinned original certificate"; exit 1; }
[[ ! -e "$OUT" ]] ||
  { echo "BLOCKED: 1.11 signed output already exists; will not overwrite"; exit 1; }

set -a
# shellcheck disable=SC1090
. "$CONF"
set +a
: "${KEYSTORE_PASSWORD:?Missing KEYSTORE_PASSWORD}"
: "${KEY_ALIAS:?Missing KEY_ALIAS}"
KEY_PASSWORD="${KEY_PASSWORD:-$KEYSTORE_PASSWORD}"
export KEYSTORE_PASSWORD KEY_PASSWORD
tmp="$(mktemp -d "$STAGING/sign-111.XXXXXXXX")"
trap 'rm -rf "$tmp"' EXIT

echo "=== Signing on CT103 with existing release key ==="
zipalign -f -p 4 "$IN" "$tmp/aligned.apk" >/dev/null
apksigner sign --ks "$JKS" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass env:KEYSTORE_PASSWORD --key-pass env:KEY_PASSWORD \
  --out "$tmp/multi-servis-1.11.apk" "$tmp/aligned.apk"
unset KEYSTORE_PASSWORD KEY_PASSWORD
apksigner verify --verbose "$tmp/multi-servis-1.11.apk" >/dev/null
newcert="$(apksigner verify --print-certs "$tmp/multi-servis-1.11.apk" |
  sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]{64})$/\1/p' |
  head -n1 | tr '[:upper:]' '[:lower:]')"
[[ "$newcert" == "$EXPECTED_CERT" && "$newcert" == "$oldcert" ]] ||
  { echo "BLOCKED: new signing certificate does not match v1.10"; exit 1; }
signedmeta="$(aapt dump badging "$tmp/multi-servis-1.11.apk")"
[[ "$signedmeta" == *"name='pl.multi_servis.owner'"* &&
   "$signedmeta" == *"versionCode='12'"* &&
   "$signedmeta" == *"versionName='1.11'"* ]] ||
  { echo "BLOCKED: signed APK package/version incorrect"; exit 1; }

mkdir -p -m 0700 "$OUTDIR"
install -m 0600 "$tmp/multi-servis-1.11.apk" "$OUT"
(cd "$OUTDIR" && sha256sum multi-servis-1.11.apk > SHA256.txt)
chmod 0600 "$OUTDIR/SHA256.txt"
echo "PASS: Multi-Servis 1.11 (12) signed with original 1.10 certificate"
echo "CERT SHA256: $newcert"
echo "SIGNED APK: $OUT"
cat "$OUTDIR/SHA256.txt"
echo "NOT PUBLISHED. Production manifest and phone remain unchanged."
