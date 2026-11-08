#!/usr/bin/env bash
# MASTER 1.5 — Read-only diagnosis of the ASUS Standard Mesh membership.
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as license
print("=== MASTER 1.5 / STANDARD DETACH PREFLIGHT READONLY ===")
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT p.installation_id,p.hostname,p.status AS pending_status,
             l.lifecycle,l.plan_code,l.rebind_pending,
             n.mesh_node_id,
             s.requested_group,s.status AS sync_status,s.attempts,
             s.observed_mesh_id,s.last_error,
             t.target_mode,t.state AS transition_state,t.expires_at > now() AS transition_live
      FROM guard.pending_installations p
      LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
      LEFT JOIN guard.workshop_mesh_nodes n ON n.installation_id=p.installation_id
      LEFT JOIN guard.owner_mesh_group_sync s ON s.installation_id=p.installation_id
      LEFT JOIN guard.workshop_profile_transitions t ON t.installation_id=p.installation_id
      WHERE upper(p.hostname)='ROG'
      ORDER BY p.last_seen_at DESC LIMIT 4
    """)).mappings().all()
    for i,r in enumerate(rows,1):
      print("ROG_ROW",i)
      for k in ("hostname","pending_status","lifecycle","plan_code","rebind_pending",
                "requested_group","sync_status","attempts","last_error",
                "target_mode","transition_state","transition_live"):
        print(" ",k,":",r[k])
      print(" MESH_NODE_BOUND:",bool(r["mesh_node_id"]))
      print(" MESH_GROUP_OBSERVED:", "PRESENT" if r["observed_mesh_id"] else "ABSENT")
      try:
        print(" OWNER_MODE:",license._owner_effective_entitlement_mode(db,r["installation_id"]))
      except Exception as exc:
        print(" OWNER_MODE_ERROR:",type(exc).__name__)
      counts=db.execute(text("""
        SELECT
        (SELECT count(*) FROM guard.workshop_remote_sessions
         WHERE installation_id=:iid AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')) AS workshop,
        (SELECT count(*) FROM guard.remote_sessions rs JOIN guard.installations gi
         ON gi.id=rs.installation_id WHERE gi.installation_external_id=:iidstr
         AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')) AS client
      """),{"iid":r["installation_id"],"iidstr":str(r["installation_id"])}).mappings().one()
      print(" ACTIVE_SESSIONS_CLIENT:",counts["client"],"WORKSHOP:",counts["workshop"])
    if not rows:print("NO_ASUS_ROG_ROW")
print("=== READONLY DONE ===")
PY
