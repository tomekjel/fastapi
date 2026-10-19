"""Read-only compatibility check for warranty returns on the REAL FastAPI DB.

Runs no DDL, no data changes, no PII, and prints only presence/type metadata.
Safe to paste output back for planning the precise PostgreSQL migration.
"""
from __future__ import annotations

import json
from sqlalchemy import text
from app.database import engine

TABLES = (
    "service.service_orders",
    "service.owner_finances",
    "service.service_order_status_history",
    "service.service_order_visits",
)
COLUMNS = {
    "service_orders": (
        "id", "reception_number", "status", "received_at", "ready_at",
        "completed_at", "released_at", "client_notified_at", "updated_by",
        "current_visit_received_at", "is_warranty_repair",
    ),
    "owner_finances": (
        "service_order_id", "service_amount", "material_cost",
        "donor_material_value",
    ),
    "service_order_visits": (
        "service_order_id", "visit_number", "is_current",
        "received_at", "completed_at", "status", "service_amount",
    ),
}

with engine.connect() as db:
    results = {}
    for name in TABLES:
        results[name] = bool(db.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"),
            {"name": name},
        ).scalar_one())
    columns = db.execute(text("""
        SELECT table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'service'
          AND table_name IN (
            'service_orders','owner_finances','service_order_visits'
          )
        ORDER BY table_name,ordinal_position
    """)).mappings().all()
    columns_by_table: dict[str, dict[str,str]] = {}
    for row in columns:
        columns_by_table.setdefault(row["table_name"], {})[
            row["column_name"]
        ] = row["data_type"]
    results["columns"] = {
        table: {
            name: columns_by_table.get(table, {}).get(name, "MISSING")
            for name in required
        }
        for table,required in COLUMNS.items()
    }
    results["function_exists"] = bool(db.execute(text("""
        SELECT to_regprocedure(
            'service.reopen_warranty_return(uuid,uuid)'
        ) IS NOT NULL
    """)).scalar_one())
    results["report_exists"] = bool(db.execute(text("""
        SELECT to_regclass(
            'service.v_owner_completed_visit_profit'
        ) IS NOT NULL
    """)).scalar_one())
    results["database_dialect"] = db.dialect.name

print(json.dumps(results, ensure_ascii=False, indent=2))
