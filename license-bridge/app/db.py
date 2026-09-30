from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import settings


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS multi_guard_license_links (
    keygate_license_id TEXT PRIMARY KEY,
    reception_number TEXT NOT NULL UNIQUE,
    keygate_plan_id TEXT NOT NULL,
    license_key_hash TEXT,
    plan_code TEXT NOT NULL CHECK (plan_code IN ('multi_guard','multi_guard_pro')),
    duration_months INTEGER NOT NULL CHECK (duration_months IN (3,6,12)),
    lifecycle TEXT NOT NULL DEFAULT 'UNASSIGNED',
    installation_id TEXT UNIQUE,
    device_id TEXT,
    credential_hash TEXT,
    app_version TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    provisioned_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    accepted_documents JSONB NOT NULL DEFAULT '[]'::jsonb
);
ALTER TABLE multi_guard_license_links ADD COLUMN IF NOT EXISTS license_key_hash TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_multi_guard_links_keyhash
    ON multi_guard_license_links(license_key_hash)
    WHERE license_key_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_multi_guard_links_device
    ON multi_guard_license_links(device_id);
CREATE INDEX IF NOT EXISTS idx_multi_guard_links_lifecycle
    ON multi_guard_license_links(lifecycle);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_license_key(value: str) -> str:
    return hashlib.sha256(value.strip().upper().encode("utf-8")).hexdigest()


@contextmanager
def connection():
    with psycopg.connect(settings.database_url) as conn:
        yield conn


def init_schema() -> None:
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()


def create_link(
    *,
    license_id: str,
    reception_number: str,
    plan_id: str,
    license_key: str,
    plan_code: str,
    duration_months: int,
) -> None:
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO multi_guard_license_links
                (keygate_license_id,reception_number,keygate_plan_id,license_key_hash,
                 plan_code,duration_months,lifecycle)
                VALUES (%s,%s,%s,%s,%s,%s,'UNASSIGNED')
                """,
                (
                    license_id,
                    reception_number,
                    plan_id,
                    hash_license_key(license_key),
                    plan_code,
                    duration_months,
                ),
            )
        conn.commit()


def _one(sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    with connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return cur.fetchone()


def keygate_plan_by_slug(slug: str) -> dict[str, Any] | None:
    return _one(
        """
        SELECT id, product_id, name, slug, license_type, billing_interval,
               duration_months, max_activations, active
        FROM plans
        WHERE slug=%s
        LIMIT 1
        """,
        (slug,),
    )


def by_key(license_key: str) -> dict[str, Any] | None:
    return _one(
        "SELECT * FROM multi_guard_license_links WHERE license_key_hash=%s",
        (hash_license_key(license_key),),
    )


def by_license(license_id: str) -> dict[str, Any] | None:
    return _one(
        "SELECT * FROM multi_guard_license_links WHERE keygate_license_id=%s",
        (license_id,),
    )


def by_reception(reception_number: str) -> dict[str, Any] | None:
    return _one(
        "SELECT * FROM multi_guard_license_links WHERE reception_number=%s",
        (reception_number,),
    )


def by_installation(installation_id: str) -> dict[str, Any] | None:
    return _one(
        "SELECT * FROM multi_guard_license_links WHERE installation_id=%s",
        (installation_id,),
    )


def list_recent(limit: int = 30) -> list[dict[str, Any]]:
    with connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT * FROM multi_guard_license_links ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            return list(cur.fetchall())


def update_link(license_id: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = utcnow()
    columns = list(fields)
    values: list[Any] = []
    for name in columns:
        value = fields[name]
        if name == "accepted_documents":
            value = Jsonb(value)
        values.append(value)
    sql = (
        "UPDATE multi_guard_license_links SET "
        + ", ".join(f"{name}=%s" for name in columns)
        + " WHERE keygate_license_id=%s"
    )
    values.append(license_id)
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)
        conn.commit()
