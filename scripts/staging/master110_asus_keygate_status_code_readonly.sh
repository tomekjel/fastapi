#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from uuid import UUID
from sqlalchemy import text
from fastapi import HTTPException
from app.database import engine
from app.routers import multiguard_license as lic
import urllib.parse, os
print("=== OWNER 502 — PRECISE KEYGATE HTTP STATUS / READ ONLY ===")
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT l.id, l.keygate_license_id,l.lifecycle,p.hostname
      FROM guard.license_links l
      JOIN guard.pending_installations p ON p.installation_id=l.installation_id
      WHERE l.id IN (:old,:active)
    """), {"old": UUID("a29b7aba-fb1f-48cb-8f22-3eadc2aa4727"),
             "active": UUID("d521b000-5351-4026-aca0-d5e8ca373849")}).mappings().all()
assert len(rows)==2 and all(r["hostname"]=="ROG" for r in rows), "STOP_UNEXPECTED_DEVICE_SET"
for r in rows:
    label="OLD_REVOKED" if str(r["id"])=="a29b7aba-fb1f-48cb-8f22-3eadc2aa4727" else "CURRENT_ACTIVE"
    print("LICENSE",label,"LOCAL_LIFECYCLE",r["lifecycle"])
    try:
        response=lic._keygate_license(str(r["keygate_license_id"]))
        print("KEYGATE",label,"HTTP","200","REMOTE_STATUS",str(response.get("status","UNKNOWN")).upper())
    except HTTPException as exc:
        status=exc.status_code
        # Never display raw upstream body, URL, token or license identifiers.
        print("KEYGATE",label,"HTTP_STATUS",status,"CLASS",
              "AUTH_DENIED" if status in (401,403) else
              "NOT_FOUND" if status==404 else
              "UPSTREAM_ERROR" if status>=500 else "OTHER")
    except Exception as exc:
        print("KEYGATE",label,"UNEXPECTED_EXCEPTION",type(exc).__name__)
print("CONFIG")
try:
    url=lic._keygate_base_url()
    parsed=urllib.parse.urlsplit(url)
    print("BASE_HOST",parsed.hostname or "[NONE]","SCHEME",parsed.scheme)
except Exception as exc:
    print("BASE_URL_ERROR",type(exc).__name__)
print("TOKEN_PRESENT",bool(os.getenv("MULTIGUARD_KEYGATE_LICENSES_TOKEN")))
print("=== END READ ONLY NO MUTATIONS ===")
PY
