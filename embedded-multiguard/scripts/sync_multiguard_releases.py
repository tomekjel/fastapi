#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import text

APP_ROOT = Path(os.getenv("MULTISERVIS_APP_ROOT", "/opt/multiservis")).resolve()
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from app.database import engine
from app.routers.multiguard_updates import _ensure_schema

REPO = os.getenv("MULTI_GUARD_GITHUB_REPO", "tomekjel/multi-guard")
RELEASE_ROOT = Path(
    os.getenv("MULTI_GUARD_RELEASE_ROOT", str(APP_ROOT / "releases" / "multiguard"))
).resolve()
PUBLIC_BASE = os.getenv(
    "MULTI_GUARD_PUBLIC_BASE_URL", "https://api.multi-servis.pl"
).rstrip("/")
TAG_RE = re.compile(
    r"^v(?P<version>\d+\.\d+\.\d+)-(?P<channel>TEST(?:-preview)?|LICENSE_TEST|PILOT|STABLE)$",
    re.IGNORECASE,
)


def run(*args: str, capture: bool = True) -> str:
    result = subprocess.run(
        list(args),
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=os.environ.copy(),
    )
    return (result.stdout or "").strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semver_key(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


def release_channel(raw: str) -> str:
    normalized = raw.upper()
    return "TEST" if normalized == "TEST-PREVIEW" else normalized


def load_releases() -> list[dict]:
    payload = run("gh", "api", f"repos/{REPO}/releases?per_page=100")
    data = json.loads(payload)
    if not isinstance(data, list):
        raise RuntimeError("GitHub zwrócił nieprawidłową listę release.")
    return data


def choose_assets(release: dict) -> tuple[dict, dict] | None:
    assets = release.get("assets") or []
    exe = next(
        (
            asset
            for asset in assets
            if str(asset.get("name") or "").lower().endswith("_x64-setup.exe")
        ),
        None,
    )
    if not exe:
        return None
    sig_name = f"{exe['name']}.sig"
    sig = next((asset for asset in assets if asset.get("name") == sig_name), None)
    return (exe, sig) if sig else None


def download_pair(tag: str, exe_name: str, sig_name: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(
        "gh",
        "release",
        "download",
        tag,
        "--repo",
        REPO,
        "--pattern",
        exe_name,
        "--pattern",
        sig_name,
        "--dir",
        str(destination),
        "--clobber",
        capture=False,
    )


def upsert_release(
    release: dict,
    version: str,
    channel: str,
    exe: Path,
    signature: str,
    sha256: str,
) -> None:
    _ensure_schema()
    filename = exe.name
    download_url = (
        f"{PUBLIC_BASE}/multiguard/update-assets/"
        f"{quote(channel)}/{quote(version)}/{quote(filename)}"
    )
    published_at = release.get("published_at") or release.get("created_at")
    notes = str(release.get("body") or "").strip()[:12000]

    with engine.begin() as connection:
        row = connection.execute(
            text(
                """
                INSERT INTO guard.release_versions(
                    version,channel,status,notes,rollout_percent,
                    force_install,rollback_safe,published_at,updated_at
                )
                VALUES(
                    :version,:channel,'AVAILABLE',:notes,100,
                    FALSE,FALSE,:published_at,now()
                )
                ON CONFLICT(version,channel)
                DO UPDATE SET
                    notes=EXCLUDED.notes,
                    published_at=COALESCE(
                        guard.release_versions.published_at,
                        EXCLUDED.published_at
                    ),
                    updated_at=now()
                RETURNING id,status,rollout_percent
                """
            ),
            {
                "version": version,
                "channel": channel,
                "notes": notes,
                "published_at": published_at,
            },
        ).mappings().one()

        connection.execute(
            text(
                """
                INSERT INTO guard.release_artifacts(
                    release_id,target,arch,bundle_type,
                    download_url,signature,sha256,size_bytes
                )
                VALUES(
                    :release_id,'windows','x86_64','nsis',
                    :download_url,:signature,:sha256,:size_bytes
                )
                ON CONFLICT(release_id,target,arch,bundle_type)
                DO UPDATE SET
                    download_url=EXCLUDED.download_url,
                    signature=EXCLUDED.signature,
                    sha256=EXCLUDED.sha256,
                    size_bytes=EXCLUDED.size_bytes
                """
            ),
            {
                "release_id": row["id"],
                "download_url": download_url,
                "signature": signature,
                "sha256": sha256,
                "size_bytes": exe.stat().st_size,
            },
        )

        connection.execute(
            text(
                """
                INSERT INTO guard.release_audit(release_id,action,details)
                VALUES(
                    :release_id,
                    'GITHUB_SYNC',
                    CAST(:details AS jsonb)
                )
                """
            ),
            {
                "release_id": row["id"],
                "details": json.dumps(
                    {
                        "tag": release.get("tag_name"),
                        "sha256": sha256,
                        "asset": filename,
                    },
                    separators=(",", ":"),
                ),
            },
        )


def main() -> int:
    if shutil.which("gh") is None:
        raise RuntimeError("Brak GitHub CLI (gh) na serwerze.")

    RELEASE_ROOT.mkdir(parents=True, exist_ok=True)
    releases = load_releases()
    candidates: list[tuple[tuple[int, int, int], dict, str, str, dict, dict]] = []

    for release in releases:
        if release.get("draft"):
            continue
        tag = str(release.get("tag_name") or "")
        match = TAG_RE.fullmatch(tag)
        if not match:
            continue
        selected = choose_assets(release)
        if not selected:
            continue
        exe_asset, sig_asset = selected
        version = match.group("version")
        channel = release_channel(match.group("channel"))
        candidates.append(
            (semver_key(version), release, version, channel, exe_asset, sig_asset)
        )

    candidates.sort(
        key=lambda item: (
            item[0],
            str(item[1].get("published_at") or item[1].get("created_at") or ""),
        )
    )

    if not candidates:
        print("Brak podpisanych release Multi-Guard do synchronizacji.")
        return 0

    synced = 0
    for _, release, version, channel, exe_asset, sig_asset in candidates:
        tag = str(release["tag_name"])
        destination = RELEASE_ROOT / version / channel
        exe = destination / str(exe_asset["name"])
        sig = destination / str(sig_asset["name"])

        expected_digest = str(exe_asset.get("digest") or "")
        expected_sha = (
            expected_digest.split(":", 1)[1].lower()
            if expected_digest.startswith("sha256:")
            else ""
        )

        local_sha = sha256_file(exe) if exe.is_file() else ""
        if (
            not exe.is_file()
            or not sig.is_file()
            or (expected_sha and local_sha != expected_sha)
        ):
            download_pair(tag, exe.name, sig.name, destination)
            local_sha = sha256_file(exe)

        if expected_sha and local_sha != expected_sha:
            raise RuntimeError(
                f"SHA-256 release {tag} nie zgadza się z digestem GitHub."
            )

        signature = sig.read_text(encoding="utf-8").strip()
        if not signature:
            raise RuntimeError(f"Pusty podpis aktualizacji dla {tag}.")

        upsert_release(
            release=release,
            version=version,
            channel=channel,
            exe=exe,
            signature=signature,
            sha256=local_sha,
        )
        print(f"OK {channel} {version} {local_sha} {exe.name}")
        synced += 1

    print(f"Zsynchronizowano release Multi-Guard: {synced}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
