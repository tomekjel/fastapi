"""OWNER MeshCentral sync engine — staged, disabled until live integration.

Only ASUS is used during pilot, but all operations are installation-scoped.
No Windows SCM/profile operation is performed here. Standard is never
assigned a MeshCentral group. The remote-agent disablement must be verified
by the independent native Windows component before Standard becomes OK.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import text

from app.routers import multiguard_meshcentral as mesh
from app.routers.master15_owner_mesh_group_policy import (
    Group, SyncState, DISPLAY_GROUP, GROUP_ENV,
    SCHEMA_SQL, observed_group_for_node, resolve_edition, validate_groups,
)

class MeshSyncError(RuntimeError):
    pass

@dataclass(frozen=True)
class SyncRecord:
    installation_id: UUID
    revision: int
    requested_group: str
    status: str
    attempts: int
    mesh_node_id: str | None
    target_mesh_id: str | None

def ensure_schema(db) -> None:
    # SQLAlchemy text does not support a multi-statement string with all
    # PostgreSQL drivers: execute bounded DDL statements separately.
    for statement in SCHEMA_SQL.strip().split(";"):
        if statement.strip():
            db.execute(text(statement))

def _current_owner_target(db, iid: UUID) -> tuple[str, str | None]:
    """Read OWNER truth under the same installation lock; never trust UI input."""
    from app.routers import multiguard_license as license
    link = db.execute(text("""
        SELECT plan_code,lifecycle,valid_until,rebind_pending
        FROM guard.license_links WHERE installation_id=:iid
    """), {"iid":iid}).mappings().first()
    mode = license._owner_effective_entitlement_mode(db, iid)
    if mode == "SERVICE":
        grant=db.execute(text("""
            SELECT enabled,valid_until FROM guard.workshop_grants
            WHERE installation_id=:iid
        """), {"iid":iid}).mappings().first()
        if not grant or not grant["enabled"] or not grant["valid_until"] or grant["valid_until"] <= datetime.now(timezone.utc):
            raise MeshSyncError("SERVICE_NOT_ACTIVE")
        choice=Group.SERVICE
    elif mode == "CLIENT":
        if not link or link["lifecycle"]!="ACTIVE" or link["rebind_pending"] or not link["valid_until"] or link["valid_until"] <= datetime.now(timezone.utc):
            raise MeshSyncError("CUSTOMER_LICENSE_NOT_ACTIVE")
        choice=resolve_edition("CLIENT",str(link["plan_code"]))
    else:
        raise MeshSyncError("OWNER_MODE_NOT_VERIFIED")
    if choice is None:
        return "NONE",None
    config=validate_groups(os.environ)
    return choice.value,config[choice]

def queue_after_owner_save(db, iid: UUID) -> None:
    """Call INSIDE OWNER save transaction once the new edition is committed.

    The caller is responsible for ensuring the licence/selected mode update
    is already visible in this transaction. No Mesh operation happens here.
    """
    db.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).one()
    group,target = _current_owner_target(db,iid)
    ensure_schema(db)
    db.execute(text("""
        INSERT INTO guard.owner_mesh_group_sync
          (installation_id,requested_group,target_mesh_id,status,attempts,revision,updated_at)
        VALUES (:iid,:g,:target,'WAITING',0,1,now())
        ON CONFLICT (installation_id) DO UPDATE SET
          requested_group=EXCLUDED.requested_group,
          target_mesh_id=EXCLUDED.target_mesh_id,
          status=CASE WHEN
            guard.owner_mesh_group_sync.requested_group=EXCLUDED.requested_group AND
            guard.owner_mesh_group_sync.target_mesh_id IS NOT DISTINCT FROM EXCLUDED.target_mesh_id AND
            guard.owner_mesh_group_sync.status='OK'
          THEN 'OK' WHEN
            guard.owner_mesh_group_sync.requested_group=EXCLUDED.requested_group AND
            guard.owner_mesh_group_sync.target_mesh_id IS NOT DISTINCT FROM EXCLUDED.target_mesh_id AND
            guard.owner_mesh_group_sync.status='RETRY'
          THEN 'RETRY' ELSE 'WAITING' END,
          attempts=CASE WHEN
            guard.owner_mesh_group_sync.requested_group=EXCLUDED.requested_group AND
            guard.owner_mesh_group_sync.target_mesh_id IS NOT DISTINCT FROM EXCLUDED.target_mesh_id
          THEN guard.owner_mesh_group_sync.attempts ELSE 0 END,
          revision=guard.owner_mesh_group_sync.revision+1,
          observed_mesh_id=CASE WHEN
            guard.owner_mesh_group_sync.requested_group=EXCLUDED.requested_group AND
            guard.owner_mesh_group_sync.target_mesh_id IS NOT DISTINCT FROM EXCLUDED.target_mesh_id AND
            guard.owner_mesh_group_sync.status='OK'
          THEN guard.owner_mesh_group_sync.observed_mesh_id ELSE NULL END,
          confirmed_at=CASE WHEN
            guard.owner_mesh_group_sync.requested_group=EXCLUDED.requested_group AND
            guard.owner_mesh_group_sync.target_mesh_id IS NOT DISTINCT FROM EXCLUDED.target_mesh_id AND
            guard.owner_mesh_group_sync.status='OK'
          THEN guard.owner_mesh_group_sync.confirmed_at ELSE NULL END,
          last_error=NULL,
          updated_at=now()
    """),{"iid":iid,"g":group,"target":target})

def request_manual_retry(db, iid: UUID) -> bool:
    """The authenticated/CSRF-protected OWNER handler calls this explicitly."""
    row=db.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).first()
    if row is None:
        return False
    ensure_schema(db)
    result=db.execute(text("""
        UPDATE guard.owner_mesh_group_sync
        SET status='WAITING',attempts=0,revision=revision+1,
            last_error=NULL,updated_at=now()
        WHERE installation_id=:iid AND status='RETRY'
    """),{"iid":iid})
    return result.rowcount == 1

def get_status(db, iid: UUID) -> tuple[str, str, int]:
    """Read status without writing. Group is the actual/last confirmed
    group until OWNER Save creates a new desired sync revision."""
    row=db.execute(text("""
        SELECT s.requested_group,s.status,s.attempts,s.observed_mesh_id,
               s.target_mesh_id
        FROM guard.owner_mesh_group_sync s
        WHERE s.installation_id=:iid
    """),{"iid":iid}).mappings().first()
    if not row:
        # Existing OWNER installations predate the new sync table.
        # Derive only the FIRST line from the SAVED edition, never from
        # an unsubmitted selection and never imply MeshCentral verification.
        try:
            saved_group, _ = _current_owner_target(db, iid)
            return {"NONE":"Brak","CLIENT":"Klient","SERVICE":"Serwis"}[saved_group], "Czeka", 0
        except (MeshSyncError, ValueError, KeyError):
            return "—", "Czeka", 0
    state=row["status"]
    if state not in ("WAITING","MOVING","OK","RETRY"):
        return "—","Czeka",0
    display={"NONE":"Brak","CLIENT":"Klient","SERVICE":"Serwis"}
    status={"WAITING":"Czeka","MOVING":"Przenoszenie…","OK":"OK","RETRY":"Ponów"}
    return display.get(str(row["requested_group"]),"—"),status[state],int(row["attempts"])

def _list_visible_nodes() -> list[dict]:
    command=mesh._base_command()
    if command.count("DeviceSharing")!=1:
        raise MeshSyncError("INVALID_MESH_LIST_COMMAND")
    command[command.index("DeviceSharing")]="ListDevices"
    raw=mesh._run(command+["--json"])
    data=json.loads(raw)
    if not isinstance(data,list):
        raise MeshSyncError("INVALID_MESH_JSON")
    return data

def _fetch_record(db, iid: UUID) -> SyncRecord | None:
    row=db.execute(text("""
        SELECT s.installation_id,s.revision,s.requested_group,s.status,
               s.attempts,s.target_mesh_id,n.mesh_node_id
        FROM guard.owner_mesh_group_sync s
        LEFT JOIN guard.workshop_mesh_nodes n ON n.installation_id=s.installation_id
        WHERE s.installation_id=:iid
    """),{"iid":iid}).mappings().first()
    return SyncRecord(**dict(row)) if row else None

def _record_attempt(db,iid:UUID,revision:int) -> SyncRecord | None:
    """Reserve one attempt atomically; returns None for stale/racing work."""
    db.execute(text("""
        SELECT installation_id FROM guard.pending_installations
        WHERE installation_id=:iid FOR UPDATE
    """),{"iid":iid}).one()
    row=_fetch_record(db,iid)
    if not row or row.revision != revision or row.status!="WAITING" or row.attempts>=3:
        return None
    # Fail closed if a subsequent OWNER edit changed the requested edition.
    desired,target=_current_owner_target(db,iid)
    if desired != row.requested_group or target!=row.target_mesh_id:
        raise MeshSyncError("OWNER_CHANGED_DURING_SYNC")
    db.execute(text("""
        UPDATE guard.owner_mesh_group_sync
        SET status='MOVING',attempts=attempts+1,attempted_at=now(),
            updated_at=now()
        WHERE installation_id=:iid AND revision=:rev
    """),{"iid":iid,"rev":revision})
    return _fetch_record(db,iid)

def _finish(db,iid:UUID,revision:int,attempts:int,
            observed:str|None,success:bool,error:str="")->None:
    # Never overwrite a newer OWNER request or count failure on a new revision.
    db.execute(text("""
        UPDATE guard.owner_mesh_group_sync
        SET status=:state,observed_mesh_id=:seen,
            confirmed_at=CASE WHEN :success THEN now() ELSE NULL END,
            last_error=:error, updated_at=now()
        WHERE installation_id=:iid AND revision=:rev AND status='MOVING'
    """),{
        "iid":iid,"rev":revision,"seen":observed,
        "state":"OK" if success else "RETRY" if attempts>=3 else "WAITING",
        "success":success,"error":error[:180] if error else None,
    })

def sync_once(engine,iid:UUID,revision:int)->str:
    """Exactly one bounded attempt, with read-back verification.

    Never call this in the OWNER Save SQL transaction. The worker/runner
    must be separately enabled only after production preflight and scoped pilot.
    """
    with engine.begin() as db:
        current=_record_attempt(db,iid,revision)
    if current is None:
        return "STALE_OR_ALREADY_PROCESSED"
    seen=None
    ok=False
    issue=""
    try:
        if not current.mesh_node_id:
            if current.requested_group == "NONE":
                # No Mesh association is not sufficient to claim Windows is
                # disabled; keep this pending until a verified native ack.
                raise MeshSyncError("STANDARD_AWAITING_VERIFIED_WINDOWS_DISABLE")
            raise MeshSyncError("MESH_NODE_ID_NOT_LINKED")
        mesh._auto_mesh_identifier(current.mesh_node_id,"node")
        records=_list_visible_nodes()
        visible,seen=observed_group_for_node(records,current.mesh_node_id)
        if not visible:
            raise MeshSyncError("MESH_NODE_NOT_VISIBLE")
        if current.requested_group == "NONE":
            # Deletion from Mesh is not proof that Windows agent is disabled.
            # A separate signed SCM ack is required before removing any node.
            raise MeshSyncError("STANDARD_AWAITING_VERIFIED_WINDOWS_DISABLE")
        elif seen != current.target_mesh_id:
            mesh.move_registered_node_to_group(current.mesh_node_id,current.target_mesh_id)
            visible,seen=observed_group_for_node(_list_visible_nodes(),current.mesh_node_id)
            if not visible:
                raise MeshSyncError("MESH_NODE_MISSING_AFTER_MOVE")
        ok=seen==current.target_mesh_id
        if not ok:
            raise MeshSyncError("MESH_GROUP_NOT_CONFIRMED")
    except Exception as exc:
        # No tokens, device identifiers, or CLI output persisted in DB.
        issue=type(exc).__name__
    with engine.begin() as db:
        db.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """),{"iid":iid}).one()
        # A mismatch is not a failure of the NEW revision.
        _finish(db,iid,revision,current.attempts,seen,ok,issue)
    return "OK" if ok else "RETRY" if current.attempts>=3 else "WAITING"


def run_pending_installation(engine, iid: UUID, max_attempts: int = 3) -> str:
    """Bounded retry runner started after an authenticated, committed OWNER Save.

    No change is attempted if the same edition already reports OK or RETRY.
    """
    with engine.connect() as db:
        row=_fetch_record(db,iid)
    if not row:
        return "NO_SYNC_REQUEST"
    last=row.status
    for _ in range(min(max_attempts,3)):
        if last != "WAITING":
            break
        last=sync_once(engine,iid,row.revision)
    return last

