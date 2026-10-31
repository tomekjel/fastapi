#!/usr/bin/env python3
"""OWNER read-only remote isolation preflight; NO licence or Mesh mutations.

Run in FastAPI's Python environment. Only aggregated counts and booleans
are printed. Never prints mesh IDs, device identities, secrets or customer data.
A PASS is a configuration gate, NOT an end-to-end Windows/Mesh validation.
"""
from __future__ import annotations
import json
import os
import re

MESH_ID = re.compile(r"^mesh/[A-Za-z0-9_.-]{0,64}/[A-Za-z0-9@$]{64}$")
TABLES = {
    "guard.pending_installations",
    "guard.license_links",
    "guard.workshop_grants",
    "guard.owner_entitlement_selections",
    "guard.workshop_standing_remote_authorizations",
    "guard.workshop_remote_sessions",
    "guard.remote_sessions",
    "guard.workshop_mesh_nodes",
}

def config_report(env):
    service=env.get("MESH_CENTRAL_SERVICE_DIAGNOSTICS_MESH_ID","").strip()
    customer=env.get("MESH_CENTRAL_CUSTOMER_MESH_ID","").strip()
    legacy=env.get("MESH_CENTRAL_SINGLE_PROMPT_MESH_ID","").strip()
    service_ok=bool(MESH_ID.fullmatch(service))
    customer_ok=bool(MESH_ID.fullmatch(customer))
    collision=service_ok and service in {customer,legacy}
    return {
        "service_mesh_group_configured": service_ok,
        "customer_mesh_group_configured": customer_ok,
        "service_customer_groups_separate": bool(service_ok and customer_ok and not collision and service != customer),
        "legacy_customer_group_collision": bool(service_ok and legacy and service == legacy),
    }

def db_report(engine):
    from sqlalchemy import text
    with engine.connect() as conn:
        with conn.begin():
            conn.execute(text("SET TRANSACTION READ ONLY"))
            rows=conn.execute(text("""
                SELECT table_schema || '.' || table_name AS relation
                FROM information_schema.tables
                WHERE table_schema='guard'
            """)).scalars().all()
            present=set(rows)
            missing=sorted(TABLES-present)
            out={"missing_guard_tables":missing}
            if "guard.remote_sessions" in present:
                out["open_paid_remote_sessions"]=conn.execute(text("""
                    SELECT count(*) FROM guard.remote_sessions
                    WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
                       OR mesh_public_id IS NOT NULL
                """)).scalar_one()
            if "guard.workshop_remote_sessions" in present:
                out["open_service_remote_sessions"]=conn.execute(text("""
                    SELECT count(*) FROM guard.workshop_remote_sessions
                    WHERE status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE')
                       OR mesh_public_id IS NOT NULL
                """)).scalar_one()
            if {"guard.owner_entitlement_selections","guard.workshop_grants"}.issubset(present):
                out["service_selected_without_enabled_grant"]=conn.execute(text("""
                    SELECT count(*) FROM guard.owner_entitlement_selections s
                    LEFT JOIN guard.workshop_grants g ON g.installation_id=s.installation_id
                    WHERE s.selected_mode='SERVICE'
                      AND (g.installation_id IS NULL OR g.enabled IS NOT TRUE)
                """)).scalar_one()
            return out

def main():
    from app.database import engine
    cfg=config_report(os.environ)
    db=db_report(engine)
    result={
        "check":"OWNER_REMOTE_MODE_READ_ONLY",
        "mode":"NO_MUTATION",
        "config":cfg,
        "database":db,
        "ready_for_controlled_lab_test":bool(
            all(cfg[k] for k in (
                "service_mesh_group_configured",
                "customer_mesh_group_configured",
                "service_customer_groups_separate",
            ))
            and not db["missing_guard_tables"]
            and db.get("open_paid_remote_sessions",1)==0
            and db.get("open_service_remote_sessions",1)==0
            and db.get("service_selected_without_enabled_grant",1)==0
        ),
        "production_switch_authorized":False,
    }
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    return 0 if result["ready_for_controlled_lab_test"] else 2

if __name__=="__main__":
    raise SystemExit(main())
