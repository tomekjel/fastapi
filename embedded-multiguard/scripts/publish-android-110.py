#!/usr/bin/env python3
"""Safely publish Multi-Servis Android 1.10 on CT103, with fail-closed preflight.
Run from PVE using pct exec 103 -- python3 /root/.../publish-android-110.py.
Does not restart services, use signing keys, install phone APKs or alter database.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path("/opt/multiservis/releases/android")
OLD = ROOT / "1.9/multi-servis-1.9.apk"
SIGNED = ROOT / "1.10/multi-servis-1.10.apk"
PUBLIC_APK = ROOT / "multi-servis-1.10.apk"
MANIFEST = ROOT / "latest.json"
NEW_DIGEST = "813270de4ca48df84471899c11b1d08eef0f04e62ce2fe5924f37a81a842a075"
OLD_DIGEST = "f168446b98e2a56183ef95c9330bb860ca644363cc0c3807d4332df5e29f3b9f"
APK_URL = "https://api.multi-servis.pl/app-updates/android/multi-servis-1.10.apk"
MANIFEST_URL = "https://api.multi-servis.pl/app-updates/android/latest.json"
API_BASE = "https://api.multi-servis.pl"
BACKUP_ROOT = Path("/opt/multiservis/backups/android-releases")
REQUIRED_ROUTES = {
    ("post", "/receptions/{reception_id}/warranty-return"),
    ("get", "/mobile/warranty/active-receptions"),
    ("get", "/mobile/receptions/{reception_id}/visits"),
    ("get", "/mobile/receptions/search"),
    ("get", "/mobile/finances/visit-report"),
}


def ensure(condition, message):
    if not condition:
        raise RuntimeError("BLOCKED: " + message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(url, *, json_data=False, hash_file=False):
    req = urllib.request.Request(url, headers={
        "User-Agent": "MultiServis-Android-Release-Verification/1.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=90) as response:
        ensure(response.status == 200, f"HTTP {response.status} at {url}")
        if hash_file:
            digest = hashlib.sha256()
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                digest.update(block)
                size += len(block)
                ensure(size < 150_000_000, "public APK too large")
            ensure(size > 1_000_000, "public APK too small")
            return digest.hexdigest()
        raw = response.read(2_000_000)
    return json.loads(raw) if json_data else raw


def manifest_from_disk():
    ensure(MANIFEST.is_file() and not MANIFEST.is_symlink(), "missing original manifest")
    content = MANIFEST.read_bytes()
    manifest = json.loads(content)
    ensure(manifest["version_code"] == 10 and manifest["version_name"] == "1.9",
           "existing version is not exactly 1.9 (10); manual inspection required")
    ensure(manifest["sha256"].lower() == OLD_DIGEST, "existing manifest SHA256 has changed")
    ensure(manifest["apk_url"] ==
           "https://api.multi-servis.pl/app-updates/android/multi-servis-1.9.apk",
           "existing manifest APK URL differs")
    return content, manifest


def apk_data(path):
    result = subprocess.run(["aapt", "dump", "badging", str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=True)
    line = result.stdout.splitlines()[0]
    m = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", line)
    ensure(m is not None, f"cannot read APK identity: {path}")
    return m.groups()


def certificate(path):
    result = subprocess.run(["apksigner", "verify", "--print-certs", str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=True)
    m = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]{64})",
                  result.stdout)
    ensure(m is not None, "cannot extract APK signer certificate")
    return m.group(1).lower()


def write_atomic(path, content):
    fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def public_json(url):
    return fetch(url + ("&" if "?" in url else "?") +
                 "release_check=" + str(time.time_ns()), json_data=True)


def main():
    ensure(os.geteuid() == 0, "must run as CT103 root")
    print("=== Multi-Servis Android 1.10 / production publish preflight ===", flush=True)
    original_bytes, original = manifest_from_disk()
    ensure(SIGNED.is_file() and not SIGNED.is_symlink(), "signed 1.10 APK missing")
    ensure(OLD.is_file() and not OLD.is_symlink(), "original 1.9 APK missing")
    ensure(sha256(SIGNED) == NEW_DIGEST, "signed 1.10 local SHA256 mismatch")
    ensure(sha256(OLD) == OLD_DIGEST, "original 1.9 local SHA256 mismatch")
    ensure(apk_data(OLD) == ("pl.multi_servis.owner", "10", "1.9"),
           "original APK package or version differs")
    ensure(apk_data(SIGNED) == ("pl.multi_servis.owner", "11", "1.10"),
           "new APK package or version differs")
    cert19, cert110 = certificate(OLD), certificate(SIGNED)
    ensure(cert19 == cert110, "release 1.10 signing certificate differs from 1.9")
    print("PASS: signed APK identity, version, local SHA256, and original certificate", flush=True)

    public_old_manifest = public_json(MANIFEST_URL)
    ensure(public_old_manifest["version_code"] == 10 and
           public_old_manifest["sha256"].lower() == OLD_DIGEST,
           "public latest.json is not the current production 1.9")
    ensure(fetch(original["apk_url"], hash_file=True) == OLD_DIGEST,
           "public 1.9 APK does not match manifest checksum")
    ensure(fetch(API_BASE + "/health"), "public API /health inaccessible")
    openapi = fetch(API_BASE + "/openapi.json", json_data=True)
    available = {(method.lower(), path)
                 for path, methods in openapi.get("paths", {}).items()
                 for method in methods.keys()}
    missing = sorted(REQUIRED_ROUTES - available)
    ensure(not missing, f"backend warranty API contract absent: {missing}")
    print("PASS: live v1.9 download, health and all five warranty API endpoints", flush=True)

    # Expose immutable 1.10 APK first; NEVER touch manifest before public
    # file is remotely downloadable with the exact checksum.
    if PUBLIC_APK.exists():
        ensure(PUBLIC_APK.is_file() and not PUBLIC_APK.is_symlink(),
               "public version 1.10 path is not a regular file")
        ensure(sha256(PUBLIC_APK) == NEW_DIGEST, "public path already has different APK")
    else:
        with SIGNED.open("rb") as source:
            fd, temporary = tempfile.mkstemp(prefix=".multi-servis-1.10-",
                                            suffix=".apk", dir=ROOT)
            try:
                with os.fdopen(fd, "wb") as target:
                    shutil.copyfileobj(source, target)
                    target.flush()
                    os.fsync(target.fileno())
                os.chmod(temporary, 0o644)
                # Refuse overwriting any concurrently published file.
                os.link(temporary, PUBLIC_APK)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    ensure(fetch(APK_URL, hash_file=True) == NEW_DIGEST,
           "public v1.10 URL not downloadable or checksum differs")
    print("PASS: HTTPS 1.10 APK public download SHA256 verified", flush=True)

    new_manifest = dict(original)
    new_manifest.update({
        "version_code": 11,
        "version_name": "1.10",
        "apk_url": APK_URL,
        "sha256": NEW_DIGEST,
        "mandatory": False,
        "notes": "Multi-Servis 1.10: naprawy gwarancyjne, historia wizyt i wyszukiwanie klientow.",
    })

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    backup = BACKUP_ROOT / ("latest-before-1.10-" + str(time.time_ns()) + ".json")
    with backup.open("xb") as file:
        file.write(original_bytes)
        file.flush()
        os.fsync(file.fileno())
    os.chmod(backup, 0o600)
    ensure(backup.read_bytes() == original_bytes, "manifest backup not verified")
    print("PASS: original v1.9 manifest backed up at " + str(backup), flush=True)

    new_bytes = (json.dumps(new_manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        write_atomic(MANIFEST, new_bytes)
        ensure(json.loads(MANIFEST.read_bytes()) == new_manifest,
               "local 1.10 manifest differs after atomic write")
        current = public_json(MANIFEST_URL)
        ensure(current.get("version_code") == 11 and
               current.get("version_name") == "1.10" and
               current.get("apk_url") == APK_URL and
               current.get("sha256", "").lower() == NEW_DIGEST,
               "public latest.json did not switch to 1.10 correctly")
    except Exception:
        write_atomic(MANIFEST, original_bytes)
        print("ROLLBACK: manifest restored to v1.9; v1.10 APK remains staged.",
              file=sys.stderr, flush=True)
        raise

    print("=== RELEASE PASS: latest.json now points to signed Android 1.10 ===", flush=True)
    print("APK URL: " + APK_URL)
    print("SHA256: " + NEW_DIGEST)
    print("CERT SHA256: " + cert110)
    print("ROLLBACK BACKUP: " + str(backup))
    print("Nothing installed on the phone; users may update from v1.9 when prompted.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAILED: " + str(exc), file=sys.stderr)
        sys.exit(1)
