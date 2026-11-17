#!/usr/bin/env bash
# Pure read-only diagnosis for the currently provisioned Lenovo installation.
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
iid = UUID("cce9ab4a-bf6a-4135-a6bc-f0486e65e0c3")
print("=== LENOVO STANDARD: OWNER / GRANT / WINDOWS PROOF ===")
with engine.connect() as db:
    row=db.execute(text("""
      SELECT p.hostname,p.status installation_status,p.last_seen_at,
             l.lifecycle,l.plan_code,l.rebind_pending,l.valid_until,
             l.accepted_at,
             l.credential_sha256 IS NOT NULL credential_present
      FROM guard.pending_installations p
      LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
      WHERE p.installation_id=:iid
    """),{"iid":iid}).mappings().one()
    assert row["hostname"].upper()=="THINKPAD", "STOP WRONG_INSTALLATION"
    for k in ("installation_status","last_seen_at","lifecycle","plan_code",
              "rebind_pending","valid_until","accepted_at","credential_present"):
        print(k.upper(),row[k])
    print("OWNER_EFFECTIVE_MODE",lic._owner_effective_entitlement_mode(db,iid))
    gate = (row["lifecycle"]=="ACTIVE" and row["plan_code"]=="multi_guard"
         and row["rebind_pending"] is False and row["accepted_at"] is not None
         and row["valid_until"] is not None and row["valid_until"]>datetime.now(timezone.utc)
         and row["credential_present"])
    print("GRANT_BASIC_ELIGIBILITY", "PASS" if gate else "BLOCKED")
    status=db.execute(text("""
      SELECT requested_group,status,attempts,last_error,requested_at,
             updated_at,revision,target_mesh_id IS NOT NULL target_defined,
             observed_mesh_id IS NOT NULL observed_defined
      FROM guard.owner_mesh_group_sync WHERE installation_id=:iid
    """),{"iid":iid}).mappings().first()
    print("MESH_SYNC",dict(status) if status else "MISSING")
    report=db.execute(text("""
      SELECT target_mode,state,created_at,expires_at,
             reservation_id IS NOT NULL reservation_exists
      FROM guard.workshop_profile_transitions WHERE installation_id=:iid
    """),{"iid":iid}).mappings().first()
    print("SIGNED_WINDOWS_RESERVATION",dict(report) if report else "NONE")
    try:
        from app.routers import master15_owner_mesh_sync_engine as sync
        print("VERIFIED_STANDARD_WINDOWS_PROOF",sync._verified_standard_shutdown(db,iid))
    except Exception as exc:
        print("WINDOWS_PROOF_CHECK_ERROR",type(exc).__name__)
print("=== SERVER REQUEST ROUTES (PAST 3 HOURS, SUMMARY ONLY) ===")
import subprocess,re,collections
commands=[["journalctl","-u","multiservis-api.service","--since","3 hours ago","--no-pager","-o","cat"]]
paths=("/v1/multi-guard/owner-profile-grant","/v1/multi-guard/owner-profile-report")
pattern=re.compile(r'(?:POST|GET)\s+(/v1/multi-guard/owner-profile-(?:grant|report))\b.*?\s(\d{3})(?:\s|$)')
for cmd in commands:
    res=subprocess.run(cmd,capture_output=True,text=True,timeout=20,check=False)
    if res.returncode:
        print("JOURNAL_UNAVAILABLE",res.returncode)
        continue
    counts=collections.Counter()
    matches=0
    for line in res.stdout.splitlines():
        m=pattern.search(line)
        if m:
            counts[(m.group(1),m.group(2))]+=1
            matches+=1
    print("REQUEST_LOG_ENTRIES",matches)
    for key,num in sorted(counts.items()):
        print("ROUTE_RESPONSE",key[0],key[1],"COUNT",num)
    if not matches:
        print("NO_MATCHING_HTTP_ACCESS_LINES: this does NOT prove no requests were sent")
print("=== END: READ ONLY — NO CHANGE ===")
PY
