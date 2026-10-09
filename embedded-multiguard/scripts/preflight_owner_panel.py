#!/usr/bin/env python3
"""READ-ONLY contract preflight for the Multi-Servis V12 owner web panel.

Prints schema/column and disk availability only, never any customer record,
phone, path, password, storage key or licensed device secret.
DOES NOT create tables, migrate, restart FastAPI or deploy any release.
Execute first on an isolated snapshot/copy of the real backend.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from sqlalchemy import text

# Checked against service panel and runtime SQL. Existing Android schema
# remains untouched; new guard.owner_* tables are created only during a
# separately authorized deployment and are not prerequisites here.
NEEDED = {
    "core.devices": {"id","manufacturer","model","serial_number","hostname","device_type"},
    "service.service_orders": {
        "id","device_id","reception_number","status","received_at",
        "ready_at","completed_at","intake_description","fault_description",
        "technician_notes","customer_notes","accessories_received",
    },
    "service.v_service_order_summary": {
        "id","reception_number","status","received_at","ready_at","completed_at",
        "manufacturer","model","serial_number","device_type","display_name","phone_e164",
    },
    "service.owner_finances": {"service_order_id","service_amount","material_cost","donor_material_value"},
    "service.service_order_media": {"id","service_order_id","storage_object_id",
                                   "media_kind","caption","created_at","sort_order","deleted_at"},
    "core.storage_objects": {"id","object_key","original_filename",
                             "mime_type","size_bytes","deleted_at"},
    "service.service_order_status_history": {
        "service_order_id","old_status","new_status","changed_at"
    },
}
GUARD_REQUIREMENTS = {
    "guard.installations": {"id","installation_external_id","service_device_id",
                            "lifecycle","last_seen_at","plan_code"},
    "guard.license_links": {"id","service_device_id","installation_id","reception_id",
                            "reception_number"},
    "guard.events": {"event_id","installation_id","occurred_at","payload"},
}


def contract_check(engine, media_root: str | Path) -> dict:
    """Read-only PostgreSQL introspection; safe to execute against a copy."""
    from sqlalchemy import text
    wanted = {**NEEDED,**GUARD_REQUIREMENTS}
    with engine.connect() as db:
        with db.begin():
            db.execute(text("SET TRANSACTION READ ONLY"))
            rows=db.execute(text("""
                SELECT table_schema,table_name,column_name
                FROM information_schema.columns
                WHERE table_schema IN ('core','service','guard')
            """)).mappings().all()
    actual={}
    for r in rows:
        actual.setdefault(f'{r["table_schema"]}.{r["table_name"]}',set()).add(r["column_name"])

    errors={}
    warnings={}
    for relation, expected in NEEDED.items():
        if relation not in actual:
            errors[relation]=["RELATION_NOT_FOUND"]
        else:
            missing=sorted(expected-actual[relation])
            if missing:
                errors[relation]=missing
    for relation,expected in GUARD_REQUIREMENTS.items():
        missing=sorted(expected-actual.get(relation,set()))
        if missing:
            # Existing GUARD may be absent on a fresh copy; its planned
            # guarded migrator runs only during a controlled deployment.
            warnings[relation]=missing if relation in actual else ["WILL_REQUIRE_SCHEMA_INITIALIZATION"]

    root=Path(media_root)
    disk={
        "root_exists":root.is_dir(),
        "readable":root.is_dir() and os.access(root,os.R_OK|os.X_OK),
    }
    if not disk["readable"]:
        errors["media_root"]=["MISSING_OR_UNREADABLE"]
    return {
        "result":"PASS" if not errors else "BLOCK_DEPLOYMENT",
        "required_schema_issues":errors,
        "guard_schema_migration_notes":warnings,
        "media_store":disk,
        "production_data_accessed":False,
        "database_mutated":False,
    }


def main():
    from app.database import engine
    from app.config import settings
    report=contract_check(engine,settings.media_root)
    print(json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True))
    raise SystemExit(0 if report["result"]=="PASS" else 2)


if __name__=="__main__":
    main()
