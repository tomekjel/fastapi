"""MASTER 1.5 — policy & durable states for MeshCentral GROUP synchronization.

Standard uses an isolated MeshCentral group, but may never enable remote access.
Group sync is independent of Windows SCM profile transitions, KeyGate,
workshop consent, and remote-session reservations.

This module is staging-only; do not expose "OK" without an independently
queried, exact MeshCentral node-group match.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

class Group(str, Enum):
    STANDARD = "STANDARD"
    CLIENT = "CLIENT"
    SERVICE = "SERVICE"

class SyncState(str, Enum):
    WAITING = "WAITING"
    MOVING = "MOVING"
    OK = "OK"
    RETRY = "RETRY"

DISPLAY_GROUP = {
    Group.STANDARD: "Standard",
    Group.CLIENT: "Klient",
    Group.SERVICE: "Serwis",
}
DISPLAY_STATE = {
    SyncState.WAITING: "Czeka",
    SyncState.MOVING: "Przenoszenie…",
    SyncState.OK: "OK",
    SyncState.RETRY: "Ponów",
}

# Three preapproved groups; STANDARD has no remote-access entitlement.
GROUP_ENV = {
    Group.STANDARD: "MESH_STANDARD_GROUP_ID",
    Group.CLIENT: "MESH_CENTRAL_SESSION_CONSENT_MESH_ID",
    Group.SERVICE: "MESH_SERVICE_PRO_GROUP_ID",
}

@dataclass(frozen=True)
class GroupDecision:
    target: Group
    group_id: str

def resolve_edition(owner_mode: str, plan_code: str) -> Group | None:
    if owner_mode == "SERVICE":
        return Group.SERVICE
    if owner_mode != "CLIENT":
        raise ValueError("UNVERIFIED_OWNER_MODE")
    if plan_code == "multi_guard":
        return Group.STANDARD
    if plan_code == "multi_guard_pro":
        return Group.CLIENT
    raise ValueError("UNKNOWN_CLIENT_EDITION")

def validate_groups(env: Mapping[str, str]) -> dict[Group,str]:
    import re
    resolved = {}
    for group, key in GROUP_ENV.items():
        value = env.get(key, "").strip()
        if not re.fullmatch(r"mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$._-]{32,128}",value):
            raise ValueError("MISSING_OR_INVALID_GROUP:"+key)
        resolved[group] = value
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("MESH_GROUPS_NOT_DISTINCT")
    return resolved

def status_after_verified_probe(*, target_id: str | None, observed_group_id: str | None,
                                attempts: int, move_pending: bool, mesh_agent_present: bool = True) -> SyncState:
    # Standard requires independently verified Windows disablement and an
    # exact isolated MeshCentral group match. A group match alone is unsafe.
    if target_id is not None and observed_group_id == target_id and not move_pending:
        if mesh_agent_present:
            return SyncState.WAITING
        return SyncState.OK
    if move_pending:
        return SyncState.MOVING
    if attempts >= 3:
        return SyncState.RETRY
    return SyncState.WAITING

def observed_group_for_node(records: object, node_id: str) -> tuple[bool, str | None]:
    """Read actual ListDevices _id/meshid; absent node is NOT proof of uninstall.

    Returns (visible,group). The caller must distinguish invisible/unreachable
    from a verified agent removal before declaring Standard OK.
    """
    if not isinstance(records, list):
        raise ValueError("MESH_DEVICES_RESPONSE_INVALID")
    matched = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("MESH_DEVICE_RECORD_INVALID")
        if item.get("_id") == node_id:
            meshid = item.get("meshid")
            if not isinstance(meshid, str) or not meshid:
                raise ValueError("MESH_DEVICE_GROUP_UNKNOWN")
            matched.append(meshid)
    if len(matched) > 1:
        raise ValueError("DUPLICATE_MESH_DEVICE")
    return (True, matched[0]) if matched else (False, None)

def should_retry(attempts: int, requested_by_owner: bool) -> bool:
    return 0 <= attempts < 3 or requested_by_owner

# Durable state is keyed by installationId, not Mesh node ID or link ID, so
# a license or channel update never accidentally reassigns another computer.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS guard.owner_mesh_group_sync (
  installation_id UUID PRIMARY KEY REFERENCES guard.pending_installations(installation_id),
  requested_group TEXT NOT NULL CHECK(requested_group IN ('NONE','CLIENT','SERVICE')),
  target_mesh_id TEXT,
  observed_mesh_id TEXT,
  status TEXT NOT NULL DEFAULT 'WAITING'
    CHECK(status IN ('WAITING','MOVING','OK','RETRY')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
  revision BIGINT NOT NULL DEFAULT 1,
  last_error TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempted_at TIMESTAMPTZ,
  confirmed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS owner_mesh_group_sync_pending_idx
  ON guard.owner_mesh_group_sync (status,updated_at)
  WHERE status IN ('WAITING','MOVING');
"""
