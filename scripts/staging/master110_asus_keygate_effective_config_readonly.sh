#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/multiservis
/opt/multiservis/.venv/bin/python - <<'PY'
from uuid import UUID
from sqlalchemy import text
from fastapi import HTTPException
from app.database import engine
from app.routers import multiguard_license as lic
print("=== MASTER110 KEYGATE 503 — REAL CONFIG SOURCE / READ ONLY ===")
name="MULTIGUARD_KEYGATE_LICENSES_TOKEN"
try:
    token=lic._setting(name,"")
    print("KEYGATE_TOKEN_IN_EFFECTIVE_CONFIG",bool(str(token).strip()))
    print("KEYGATE_CONFIG_SOURCE","ENV" if __import__('os').getenv(name) else "FILE_OR_MISSING")
except HTTPException as exc:
    print("CONFIG_HTTP_STATUS",exc.status_code)
except Exception as exc:
    print("CONFIG_ERROR_CLASS",type(exc).__name__)
with engine.connect() as db:
    rows=db.execute(text("""
        SELECT l.id,l.lifecycle,l.keygate_license_id,p.hostname
        FROM guard.license_links l JOIN guard.pending_installations p
        ON p.installation_id=l.installation_id
        WHERE l.id IN (:old,:active)
    """),{"old":UUID("a29b7aba-fb1f-48cb-8f22-3eadc2aa4727"),
           "active":UUID("d521b000-5351-4026-aca0-d5e8ca373849")}).mappings().all()
if len(rows)!=2 or any(r["hostname"]!="ROG" for r in rows):
    raise SystemExit("STOP: UNEXPECTED LICENSE SET")
for r in rows:
    label="OLD_REVOKED" if str(r["id"])=="a29b7aba-fb1f-48cb-8f22-3eadc2aa4727" else "CURRENT_ACTIVE"
    print("RECORD",label,r["lifecycle"])
    try:
        result=lic._keygate_license(str(r["keygate_license_id"]))
        print("KEYGATE",label,"OK","STATUS",str(result.get("status","UNKNOWN")).upper())
    except HTTPException as exc:
        detail=str(exc.detail)
        # Print *only* constant classifications; never raw upstream body,
        # endpoint, tokens, licence keys or credentials.
        print("KEYGATE",label,"HTTP",exc.status_code,"REASON",
            "MISSING_ADMIN_TOKEN" if "Brak konfiguracji MULTIGUARD_KEYGATE_LICENSES_TOKEN" in detail else
            "BAD_CONFIG_FILE" if "Błędny plik konfiguracji" in detail else
            "KEYGATE_REJECTED" if "KeyGate odrzucił operację" in detail else
            "REMOTE_HTTP_ERROR" if detail.startswith("KeyGate:") else
            "CONNECTIVITY_OR_OTHER" if "Brak połączenia z KeyGate" in detail else
            "OTHER")
    except Exception as exc:
        print("KEYGATE",label,"ERROR_TYPE",type(exc).__name__)
print("=== END READ ONLY — NO TOKEN DISPLAY NO DELETE ===")
PY
