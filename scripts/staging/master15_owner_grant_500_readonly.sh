#!/usr/bin/env bash
set -euo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from sqlalchemy import text
from app.database import engine
from pathlib import Path
from app.routers import multiguard_license as lic
from app.routers import multiguard_workshop_remote as workshop
print("=== MASTER 1.5 / OWNER GRANT 500 READONLY ===")
with engine.connect() as db:
 ids=db.execute(text("SELECT installation_id FROM guard.pending_installations WHERE upper(hostname)='ROG'")).scalars().all()
 if len(ids)!=1: raise SystemExit("STOP ASUS_NOT_UNIQUE")
 iid=ids[0]
 print("OWNER_MODE",lic._owner_effective_entitlement_mode(db,iid))
 print("RESERVATION_TABLE_COLUMNS",db.execute(text("""
   SELECT column_name FROM information_schema.columns
   WHERE table_schema='guard' AND table_name='workshop_profile_transitions'
   ORDER BY ordinal_position
 """)).scalars().all())
 print("BRIDGE_SOURCE_PRESENT",Path('/opt/multiservis/app/routers/master15_owner_profile_bridge.py').is_file())
 print("GRANT_CODEC_PRESENT",Path('/opt/multiservis/app/routers/multiguard_owner_profile_grant.py').is_file())
 print("SIGNING_KEY_AVAILABLE",callable(getattr(lic,'_signing_key',None)))
 print("SCHEMA_HELPER_PRESENT",callable(getattr(workshop,'_schema',None)))
 print("SESSIONS_HELPER_PRESENT",callable(getattr(workshop,'_service_transition_sessions',None)))
print("=== ROUTES AND RECENT SERVER ERRORS ===")
PY
journalctl -u multiservis-api.service --since '20 minutes ago' --no-pager -o cat 2>/dev/null | grep -E -A 14 -B 3 'owner-profile-grant|owner_profile_grant|Traceback|Exception|ERROR|Internal Server Error' | tail -150 | sed -E 's/([A-Za-z0-9+\/=]{72,})/[LONG_VALUE_REDACTED]/g'
echo '=== READ_ONLY_COMPLETE ==='
