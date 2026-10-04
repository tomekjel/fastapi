from __future__ import annotations

import os
import re
import threading
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner


router = APIRouter(prefix="/multiguard", tags=["multi-guard-updates"])

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_RELEASE_ROOT = Path(
    os.getenv("MULTI_GUARD_RELEASE_ROOT", "/opt/multiservis/releases/multiguard")
).resolve()
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
_VALID_CHANNELS = {"TEST", "LICENSE_TEST", "PILOT", "STABLE"}

_SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS guard;

CREATE TABLE IF NOT EXISTS guard.release_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT','AVAILABLE','PAUSED','RETIRED')),
    notes TEXT,
    rollout_percent INTEGER NOT NULL DEFAULT 0
        CHECK (rollout_percent BETWEEN 0 AND 100),
    force_install BOOLEAN NOT NULL DEFAULT FALSE,
    rollback_safe BOOLEAN NOT NULL DEFAULT FALSE,
    min_db_schema_supported INTEGER NOT NULL DEFAULT 1,
    max_db_schema_supported INTEGER NOT NULL DEFAULT 2147483647,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(version,channel)
);

CREATE TABLE IF NOT EXISTS guard.release_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    release_id UUID NOT NULL REFERENCES guard.release_versions(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    arch TEXT NOT NULL,
    bundle_type TEXT NOT NULL DEFAULT 'nsis',
    download_url TEXT NOT NULL CHECK (download_url LIKE 'https://%'),
    signature TEXT NOT NULL,
    sha256 TEXT CHECK (sha256 IS NULL OR length(sha256)=64),
    size_bytes BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(release_id,target,arch,bundle_type)
);

CREATE TABLE IF NOT EXISTS guard.release_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel TEXT NOT NULL,
    version TEXT NOT NULL,
    reason TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(channel,version)
);

CREATE TABLE IF NOT EXISTS guard.release_audit (
    id BIGSERIAL PRIMARY KEY,
    release_id UUID REFERENCES guard.release_versions(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_guard_release_versions_channel
    ON guard.release_versions(channel,status,published_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_release_blocks_active
    ON guard.release_blocks(channel,version) WHERE active=TRUE;
"""


class RolloutChange(BaseModel):
    status: str
    rolloutPercent: int = Field(ge=0, le=100)


class BlockVersion(BaseModel):
    channel: str
    version: str
    reason: str = Field(min_length=3, max_length=1000)


def _ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with engine.begin() as connection:
            for statement in [s.strip() for s in _SCHEMA_SQL.split(";") if s.strip()]:
                connection.execute(text(statement))

            # Older BS-10 drafts did not include LICENSE_TEST. Normalize only
            # the update catalog constraints; installation/licence rings remain
            # controlled by their own router.
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.release_versions
                    DROP CONSTRAINT IF EXISTS release_versions_channel_check
                    """
                )
            )
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.release_versions
                    ADD CONSTRAINT release_versions_channel_check
                    CHECK (channel IN ('TEST','LICENSE_TEST','PILOT','STABLE'))
                    """
                )
            )
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.release_blocks
                    DROP CONSTRAINT IF EXISTS release_blocks_channel_check
                    """
                )
            )
            connection.execute(
                text(
                    """
                    ALTER TABLE guard.release_blocks
                    ADD CONSTRAINT release_blocks_channel_check
                    CHECK (channel IN ('TEST','LICENSE_TEST','PILOT','STABLE'))
                    """
                )
            )
        _SCHEMA_READY = True


def _semver(value: str) -> tuple[int, int, int]:
    match = _SEMVER.match((value or "").strip())
    if not match:
        raise HTTPException(400, f"Nieprawidłowa wersja SemVer: {value}")
    return tuple(int(part) for part in match.groups())


def _rollout_bucket(installation_id: uuid.UUID, release_id: uuid.UUID) -> int:
    import hashlib

    digest = hashlib.sha256(f"{installation_id}:{release_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 100


def _normalized_channel(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    channel = value.strip().upper()
    return channel if channel in _VALID_CHANNELS else None


def _resolve_channel(
    connection,
    installation_header: Optional[str],
    requested_channel: Optional[str],
    current_version: str,
) -> tuple[Optional[str], Optional[uuid.UUID]]:
    installation_uuid: Optional[uuid.UUID] = None
    if installation_header:
        try:
            installation_uuid = uuid.UUID(installation_header)
        except ValueError:
            installation_uuid = None

    if installation_uuid is not None:
        row = connection.execute(
            text(
                """
                SELECT release_channel
                FROM guard.installations
                WHERE installation_external_id=:installation_id
                  AND is_current=TRUE
                LIMIT 1
                """
            ),
            {"installation_id": installation_uuid},
        ).mappings().first()
        if row:
            channel = _normalized_channel(row["release_channel"])
            if channel:
                return channel, installation_uuid

    # TEST builds are intentionally usable before provisioning. Starting with
    # 0.3.30 the desktop client explicitly sends X-Multi-Guard-Channel=TEST.
    requested = _normalized_channel(requested_channel)
    if requested == "TEST":
        return "TEST", installation_uuid

    # Compatibility bridge for the already-installed 0.3.29 TEST build, which
    # predates the channel header. It is deliberately bounded to <= 0.3.29.
    try:
        if _semver(current_version) <= (0, 3, 29):
            return "TEST", installation_uuid
    except HTTPException:
        pass

    return None, installation_uuid


@router.get("/releases/{target}/{arch}/{current_version}")
def release_manifest(
    target: str,
    arch: str,
    current_version: str,
    x_multi_guard_installation: Optional[str] = Header(
        default=None, alias="X-Multi-Guard-Installation"
    ),
    x_multi_guard_channel: Optional[str] = Header(
        default=None, alias="X-Multi-Guard-Channel"
    ),
):
    _ensure_schema()
    current = _semver(current_version)

    with engine.connect() as connection:
        channel, installation_uuid = _resolve_channel(
            connection,
            x_multi_guard_installation,
            x_multi_guard_channel,
            current_version,
        )
        if channel is None:
            return Response(status_code=204)

        blocked = connection.execute(
            text(
                """
                SELECT reason
                FROM guard.release_blocks
                WHERE channel=:channel
                  AND version=:version
                  AND active=TRUE
                LIMIT 1
                """
            ),
            {"channel": channel, "version": current_version.lstrip("v")},
        ).mappings().first()

        rows = connection.execute(
            text(
                """
                SELECT
                    rv.id,rv.version,rv.channel,rv.notes,rv.rollout_percent,
                    rv.force_install,rv.rollback_safe,
                    rv.min_db_schema_supported,rv.max_db_schema_supported,
                    rv.published_at,
                    ra.download_url,ra.signature,ra.sha256
                FROM guard.release_versions rv
                JOIN guard.release_artifacts ra ON ra.release_id=rv.id
                WHERE rv.channel=:channel
                  AND rv.status='AVAILABLE'
                  AND ra.target=:target
                  AND ra.arch=:arch
                  AND ra.sha256 IS NOT NULL
                """
            ),
            {"channel": channel, "target": target, "arch": arch},
        ).mappings().all()

    candidates = []
    for row in rows:
        try:
            version = _semver(row["version"])
        except HTTPException:
            continue
        if version <= current:
            continue
        if installation_uuid is not None and _rollout_bucket(
            installation_uuid, row["id"]
        ) >= int(row["rollout_percent"]):
            continue
        if installation_uuid is None and int(row["rollout_percent"]) <= 0:
            continue
        candidates.append((version, row))

    if not candidates:
        return Response(status_code=204)

    chosen = max(candidates, key=lambda item: item[0])[1]
    return {
        "version": chosen["version"],
        "notes": chosen["notes"] or "",
        "pub_date": (
            chosen["published_at"].isoformat() if chosen["published_at"] else None
        ),
        "url": chosen["download_url"],
        "signature": chosen["signature"],
        "sha256": chosen["sha256"],
        "releaseId": str(chosen["id"]),
        "channel": chosen["channel"],
        "rolloutPercent": int(chosen["rollout_percent"]),
        "forceInstall": bool(chosen["force_install"] or blocked),
        "rollbackSafe": bool(chosen["rollback_safe"]),
        "minDbSchemaSupported": int(chosen["min_db_schema_supported"]),
        "maxDbSchemaSupported": int(chosen["max_db_schema_supported"]),
        "blockedCurrentVersion": bool(blocked),
    }


@router.get("/update-assets/{channel}/{version}/{filename}")
def update_asset(channel: str, version: str, filename: str):
    normalized_channel = _normalized_channel(channel)
    if normalized_channel is None:
        raise HTTPException(404, "Nie znaleziono kanału aktualizacji.")
    _semver(version)
    if not _SAFE_FILENAME.fullmatch(filename):
        raise HTTPException(404, "Nie znaleziono pliku aktualizacji.")

    path = (_RELEASE_ROOT / version / normalized_channel / filename).resolve()
    expected_parent = (_RELEASE_ROOT / version / normalized_channel).resolve()
    if path.parent != expected_parent or not path.is_file():
        raise HTTPException(404, "Nie znaleziono pliku aktualizacji.")

    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=filename,
    )


@router.post("/admin/releases/{release_id}/rollout")
def change_rollout(
    release_id: str,
    body: RolloutChange,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    try:
        release_uuid = uuid.UUID(release_id)
    except ValueError as exc:
        raise HTTPException(400, "Nieprawidłowe release_id.") from exc

    status = body.status.strip().upper()
    if status not in {"DRAFT", "AVAILABLE", "PAUSED", "RETIRED"}:
        raise HTTPException(400, "Nieprawidłowy status wydania.")

    with engine.begin() as connection:
        changed = connection.execute(
            text(
                """
                UPDATE guard.release_versions
                SET
                    status=:status,
                    rollout_percent=:rollout,
                    published_at=CASE
                        WHEN :status='AVAILABLE' THEN COALESCE(published_at,now())
                        ELSE published_at
                    END,
                    updated_at=now()
                WHERE id=:release_id
                """
            ),
            {
                "status": status,
                "rollout": body.rolloutPercent,
                "release_id": release_uuid,
            },
        ).rowcount
    if not changed:
        raise HTTPException(404, "Nie znaleziono wydania.")
    return {"status": "ok"}


@router.post("/admin/releases/block")
def block_version(
    body: BlockVersion,
    user: CurrentUser = Depends(require_owner),
):
    _ensure_schema()
    channel = _normalized_channel(body.channel)
    if channel is None:
        raise HTTPException(400, "Nieprawidłowy kanał.")
    version = body.version.lstrip("v")
    _semver(version)

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO guard.release_blocks(channel,version,reason,active)
                VALUES(:channel,:version,:reason,TRUE)
                ON CONFLICT(channel,version)
                DO UPDATE SET reason=EXCLUDED.reason,active=TRUE,created_at=now()
                """
            ),
            {"channel": channel, "version": version, "reason": body.reason},
        )
        connection.execute(
            text(
                """
                UPDATE guard.release_versions
                SET status='PAUSED',updated_at=now()
                WHERE channel=:channel AND version=:version
                """
            ),
            {"channel": channel, "version": version},
        )
    return {"status": "blocked", "channel": channel, "version": version}
