#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
echo '=== OWNER ASUS DELETE 502 — READ ONLY ==='
echo '--- SERVICE ---'
systemctl is-active multiservis-api.service || true
echo '--- SOURCE + DATABASE ---'
/opt/multiservis/.venv/bin/python - <<'PY'
import inspect, traceback, re
from pathlib import Path
from sqlalchemy import text
from app.database import engine
from app.routers import multiguard_license as lic
target = "a29b7aba-fb1f-48cb-8f22-3eadc2aa4727"
print("PATH_ID",target)
print("SOURCE_ROUTES")
try:
    from app.main import app
    routes = [r for r in app.routes if "licenses-grid" in str(getattr(r,"path","")) and "delete" in str(getattr(r,"path",""))]
    for r in routes:
        ep=getattr(r,"endpoint",None)
        if ep is None: continue
        print("ROUTE",str(getattr(r,"path","")),"METHODS",",".join(sorted(getattr(r,"methods",[]) or [])))
        print("HANDLER",getattr(ep,"__name__","unknown"),"FILE",inspect.getsourcefile(ep),"LINE",getattr(getattr(ep,"__code__",None),"co_firstlineno","unknown"))
        try:
            src=inspect.getsource(ep)
            for line in src.splitlines():
                stripped=line.strip()
                if any(x in stripped.lower() for x in ["keygate", "delete", "deactiv", "revoke", "commit", "begin(", "timeout", "mesh", "archiv", "return ", "http", "service", "install"]):
                    # strip string literal values and secret-shaped arguments
                    print("ROUTE_LOGIC",re.sub(r"'[^']{60,}'", "'[REDACTED]'",stripped)[:190])
        except (OSError,TypeError):print("SOURCE_UNAVAILABLE")
    if not routes: print("NO_MATCHING_ROUTE_IN_APP")
except Exception as exc: print("ROUTE_INTROSPECTION_ERROR",type(exc).__name__)
with engine.connect() as db:
    print("DB_SERVER_TIME",db.execute(text("SELECT now()")).scalar())
    for table in ["pending_installations","license_links","owner_mesh_group_sync","keygate_provision_attempts"]:
        cols=set(db.execute(text("""
          SELECT column_name FROM information_schema.columns
          WHERE table_schema='guard' AND table_name=:tbl
        """),{"tbl":table}).scalars())
        if not cols:
            print("TABLE_NOT_FOUND",table);continue
        print("TABLE",table,"FIELDS",",".join(sorted(cols & {
            "id","installation_id","hostname","status","lifecycle","plan_code",
            "valid_until","updated_at","last_seen_at","keygate_license_id","rebind_pending",
            "requested_group","last_error","state","created_at","device_id"
        })))
        sel=[v for v in ["id","installation_id","hostname","status","lifecycle","plan_code",
                        "valid_until","updated_at","last_seen_at","rebind_pending","requested_group","last_error","state","created_at"] if v in cols]
        where=[]
        if "installation_id" in cols:where.append("CAST(installation_id AS text) IN (SELECT CAST(installation_id AS text) FROM guard.pending_installations WHERE UPPER(hostname) LIKE '%ROG%')")
        if "id" in cols:where.append("CAST(id AS text)=:target")
        if "hostname" in cols:where.append("UPPER(hostname) LIKE '%ROG%'")
        if not where:continue
        sql="SELECT "+",".join('"'+v+'"' for v in sel)+" FROM guard."+table+" WHERE "+" OR ".join("("+q+")" for q in where)+" LIMIT 12"
        try:
            rows=db.execute(text(sql),{"target":target}).mappings().all()
            print("RECORD_COUNT",table,len(rows))
            for row in rows: print("RECORD",table,{k:str(v) if v is not None else None for k,v in row.items()})
        except Exception as exc:print("TABLE_READ_ERROR",table,type(exc).__name__)
print("END_DATABASE_READ_ONLY")
PY
echo '--- RECENT API EXCEPTIONS (SANITIZED, NO PAYLOADS) ---'
journalctl -u multiservis-api.service --since '2026-11-17 11:50:00 UTC' --no-pager -o short-iso 2>/dev/null | grep -Ei 'Traceback|Error|Exception|licenses-grid|KeyGate|revoke|delete|502|timeout|worker|killed|Restarting' | tail -85 | sed -E 's/(https?:\/\/)[^ /]+/\1[HOST]/g;s/[a-f0-9]{8}-[a-f0-9-]{27,}/[UUID]/Ig;s/[A-Za-z0-9+\/=]{80,}/[VALUE_REDACTED]/g' || true
echo '=== END READ ONLY — DO NOT RETRY DELETE YET ==='
