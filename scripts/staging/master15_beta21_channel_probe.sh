#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_updates as updater
print("=== MASTER 1.5 / ASUS BETA21 CHANNEL / READ ONLY ===")
with engine.connect() as db:
    r=db.execute(text("""
       SELECT p.installation_id,p.hostname,p.status AS installation_status,
              l.release_channel AS owner_channel,l.plan_code,l.lifecycle
       FROM guard.pending_installations p
       LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
       WHERE upper(p.hostname)='ROG'
       ORDER BY p.last_seen_at DESC
    """)).mappings().all()
    if len(r)!=1:raise SystemExit("STOP: ROG_NOT_UNIQUE")
    iid=r[0]['installation_id']
    actual,_=updater._resolve_channel(db,str(iid))
    print("HOST",r[0]['hostname'],"INSTALLATION_STATUS",r[0]['installation_status'])
    print("OWNER_CHANNEL",r[0]['owner_channel'])
    print("OWNER_PLAN",r[0]['plan_code'],"LIFECYCLE",r[0]['lifecycle'])
    print("UPDATER_RESOLVED_CHANNEL",actual)
    rows=db.execute(text("""
       SELECT release_channel,is_current FROM guard.installations
       WHERE installation_external_id=:iid
    """),{"iid":iid}).mappings().all()
    print("GUARD_INSTALLATIONS",[(x['release_channel'],x['is_current']) for x in rows])
    x=db.execute(text("""
       SELECT channel,status,rollout_percent FROM guard.release_versions
       WHERE version='0.3.46-beta.21'
    """)).mappings().all()
    print("BETA21_RELEASE_ROWS",[(v['channel'],v['status'],v['rollout_percent']) for v in x])
print("=== READ ONLY COMPLETE ===")
PY
