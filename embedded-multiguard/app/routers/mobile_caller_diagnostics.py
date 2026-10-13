"""Bounded OWNER-only Android caller diagnostics ingestion and readback.

This module deliberately does not depend on the Multi-Guard Windows agent or
on the HTML panel: its auth is the same Bearer OWNER auth used by the Android
Multi-Servis owner APIs. No raw phone numbers, filenames or exception messages
are part of the accepted schema.
"""
from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.database import engine
from app.security import CurrentUser, require_owner


router = APIRouter(prefix="/mobile/diagnostics", tags=["mobile-owner-diagnostics"])

Source = Literal["SCREENING", "PHONE_STATE", "PRESENTER", "OVERLAY", "NOTIFICATION", "ACTIVITY"]
Event = Literal[
    "INCOMING", "NUMBER_UNAVAILABLE", "LOOKUP_START", "MATCH_KNOWN",
    "MATCH_UNKNOWN", "MATCH_FAILED", "DUPLICATE_SIGNAL", "NOT_OWNER",
    "CALL_ENDED_BEFORE_DISPLAY", "OVERLAY_VISIBLE", "OVERLAY_FAILED",
    "OVERLAY_PERMISSION_MISSING", "NOTIFICATION_FALLBACK", "NOTIFICATION_FAILED",
    "ACTIVITY_FALLBACK", "ACTIVITY_FAILED", "HIDDEN", "UNEXPECTED_FAILURE",
]
_SEVEN_DAYS = timedelta(days=7)
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_SAFE_ERROR = re.compile(r"^[A-Za-z0-9_]{1,64}$")


class CallerEvent(BaseModel):
    eventId: uuid.UUID
    occurredAt: datetime
    source: Source
    event: Event
    activeJobs: int | None = Field(default=None, ge=0, le=99)
    latencyMs: int | None = Field(default=None, ge=0, le=60_000)
    errorClass: str | None = Field(default=None, max_length=64)


class CallerBatch(BaseModel):
    deviceId: uuid.UUID  # Random local diagnostics identifier, never the phone number.
    events: list[CallerEvent] = Field(min_length=1, max_length=100)


def _ensure_schema() -> None:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with engine.begin() as db:
            db.execute(text("CREATE SCHEMA IF NOT EXISTS guard"))
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS guard.android_caller_diagnostics (
                    device_id UUID NOT NULL,
                    event_id UUID NOT NULL,
                    occurred_at TIMESTAMPTZ NOT NULL,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    source TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    active_jobs SMALLINT,
                    latency_ms INTEGER,
                    error_class TEXT,
                    PRIMARY KEY (device_id, event_id)
                )
            """))
            db.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_guard_android_caller_diag_recent
                ON guard.android_caller_diagnostics(received_at DESC)
            """))
        _SCHEMA_READY = True


@router.post("/caller")
def submit_caller_diagnostics(
    batch: CallerBatch,
    _: CurrentUser = Depends(require_owner),
):
    """Idempotent authenticated ingest; seven-day retention and strict allowlists."""
    _ensure_schema()
    now = datetime.now(timezone.utc)
    old = now - _SEVEN_DAYS
    future = now + timedelta(minutes=5)
    for entry in batch.events:
        at = entry.occurredAt
        if at.tzinfo is None:
            raise HTTPException(422, "Brak strefy czasowej zdarzenia.")
        if not (old <= at <= future):
            raise HTTPException(422, "Data zdarzenia jest spoza dozwolonego zakresu.")
        if entry.errorClass is not None and not _SAFE_ERROR.fullmatch(entry.errorClass):
            raise HTTPException(422, "Niedozwolona klasa błędu.")

    with engine.begin() as db:
        db.execute(
            text("DELETE FROM guard.android_caller_diagnostics WHERE received_at < now() - INTERVAL '7 days'")
        )
        for entry in batch.events:
            db.execute(text("""
                INSERT INTO guard.android_caller_diagnostics (
                    device_id, event_id, occurred_at, source, event_name,
                    active_jobs, latency_ms, error_class
                )
                VALUES (
                    :device_id, :event_id, :occurred_at, :source, :event_name,
                    :active_jobs, :latency_ms, :error_class
                )
                ON CONFLICT (device_id, event_id) DO NOTHING
            """), {
                "device_id": batch.deviceId,
                "event_id": entry.eventId,
                "occurred_at": entry.occurredAt,
                "source": entry.source,
                "event_name": entry.event,
                "active_jobs": entry.activeJobs,
                "latency_ms": entry.latencyMs,
                "error_class": entry.errorClass,
            })
    return {"ok": True, "accepted": len(batch.events)}


@router.get("/caller")
def list_caller_diagnostics(
    limit: int = Query(default=100, ge=1, le=200),
    _: CurrentUser = Depends(require_owner),
):
    """Server-side OWNER diagnostics view; never exposed to STAFF/clients."""
    _ensure_schema()
    with engine.begin() as db:
        db.execute(text("DELETE FROM guard.android_caller_diagnostics WHERE received_at < now() - INTERVAL '7 days'"))
        rows = db.execute(text("""
            SELECT device_id, event_id, occurred_at, source, event_name,
                   active_jobs, latency_ms, error_class
            FROM guard.android_caller_diagnostics
            WHERE received_at >= now() - INTERVAL '7 days'
            ORDER BY occurred_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()
    return {
        "events": [{
            "deviceId": str(x["device_id"]),
            "eventId": str(x["event_id"]),
            "occurredAt": x["occurred_at"].isoformat(),
            "source": x["source"],
            "event": x["event_name"],
            "activeJobs": x["active_jobs"],
            "latencyMs": x["latency_ms"],
            "errorClass": x["error_class"],
        } for x in rows]
    }
