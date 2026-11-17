#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from datetime import datetime,timezone
from uuid import UUID
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
from app.routers import master15_owner_mesh_sync_engine as sync

A=UUID("7c8470c9-6e81-48a4-be7c-f75ec2cb4c6d")
L=UUID("cce9ab4a-bf6a-4135-a6bc-f0486e65e0c3")
print("=== OWNER SYNC: SAFE STALE RECOVERY / BOTH DEVICES ===")
with engine.begin() as db:
    rows=db.execute(text("""
       SELECT p.installation_id,p.hostname,l.lifecycle,l.plan_code,l.rebind_pending,l.valid_until
       FROM guard.pending_installations p JOIN guard.license_links l
       ON l.installation_id=p.installation_id
       WHERE p.installation_id IN (:a,:l)
       FOR UPDATE OF p
    """),{"a":A,"l":L}).mappings().all()
    if len(rows)!=2:
        raise SystemExit("STOP: BOTH ACTIVE INSTALLATIONS REQUIRED")
    by={r["installation_id"]:r for r in rows}
    if any((by[i]["hostname"].upper()!=h or by[i]["lifecycle"]!="ACTIVE" or
            by[i]["rebind_pending"] or not by[i]["valid_until"] or
            by[i]["valid_until"]<=datetime.now(timezone.utc))
           for i,h in ((A,"ROG"),(L,"THINKPAD"))):
        raise SystemExit("STOP: CURRENT DEVICE IDENTITY/LICENCE CHANGED")
    if by[A]["plan_code"]!="multi_guard_pro" or by[L]["plan_code"]!="multi_guard":
        raise SystemExit("STOP: OWNER EDITION CHANGED")
    # Existing client records require an agent registration from the Windows
    # privileged broker; do NOT forge a Mesh node or assert successful sync.
    a_node=db.execute(text("""
       SELECT mesh_node_id FROM guard.workshop_mesh_nodes
       WHERE installation_id=:iid
    """),{"iid":A}).scalar_one_or_none()
    a_sync=db.execute(text("""
       SELECT requested_group,status FROM guard.owner_mesh_group_sync
       WHERE installation_id=:iid
    """),{"iid":A}).mappings().first()
    if a_node and not a_sync:
        # Safe to queue only if a verified, installation-bound node exists.
        sync.queue_after_owner_save(db,A)
        print("ASUS: QUEUED_EXISTING_REGISTERED_AGENT")
    elif not a_node:
        print("ASUS: NEEDS_SIGNED_WINDOWS_MESH_AGENT_REGISTRATION; no fabricated link")
    else:
        print("ASUS: EXISTING_SYNC",dict(a_sync))
    l_sync=db.execute(text("""
       SELECT status,requested_group,requested_at,updated_at
       FROM guard.owner_mesh_group_sync WHERE installation_id=:iid FOR UPDATE
    """),{"iid":L}).mappings().first()
    if l_sync and l_sync["status"]=="WAITING" and l_sync["requested_group"]=="NONE":
        proof=sync._verified_standard_shutdown(db,L)
        age=(datetime.now(timezone.utc)-(l_sync["requested_at"] or l_sync["updated_at"])).total_seconds()
        if not proof and age>120:
            db.execute(text("""
               UPDATE guard.owner_mesh_group_sync
               SET status='RETRY',last_error='WINDOWS_CONFIRMATION_TIMEOUT',
                   updated_at=now()
               WHERE installation_id=:iid AND status='WAITING'
                 AND requested_group='NONE'
            """),{"iid":L})
            print("LENOVO: STALE_WAITING_TO_RETRY; signed Windows confirmation still required")
        else:
            print("LENOVO: WAITING; PROOF",proof,"AGE_SECONDS",int(age))
    elif l_sync:
        print("LENOVO: EXISTING_SYNC",dict(l_sync))
    else:
        print("LENOVO: NO_SYNC_RECORD")
print("=== NO LICENSE CHANGES; NO MESH COMMAND; NO FALSE OK ===")
PY
