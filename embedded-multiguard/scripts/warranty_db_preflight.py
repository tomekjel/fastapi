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



# Compatibility inventory: no customer names, phone numbers or order IDs.
with engine.connect() as db:
    results["status_enum_labels"] = list(db.execute(text("""
        SELECT e.enumlabel
        FROM pg_type t
        JOIN pg_namespace ns ON ns.oid=t.typnamespace
        JOIN pg_enum e ON e.enumtypid=t.oid
        WHERE ns.nspname='service' AND t.typname='reception_status'
        ORDER BY e.enumsortorder
    """)).scalars())
    results["order_triggers"] = [
        {"name":row["tgname"],"function":row["proname"]}
        for row in db.execute(text("""
            SELECT t.tgname,p.proname
            FROM pg_trigger t
            JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid='service.service_orders'::regclass
              AND NOT t.tgisinternal
            ORDER BY t.tgname
        """)).mappings()
    ]
    results["finance_triggers"] = [
        {"name":row["tgname"],"function":row["proname"]}
        for row in db.execute(text("""
            SELECT t.tgname,p.proname
            FROM pg_trigger t
            JOIN pg_proc p ON p.oid=t.tgfoid
            WHERE t.tgrelid='service.owner_finances'::regclass
              AND NOT t.tgisinternal
            ORDER BY t.tgname
        """)).mappings()
    ]
    results["legacy_report_views"] = {
        name:bool(db.execute(text("SELECT to_regclass(:name) IS NOT NULL"),
            {"name":"service."+name}).scalar_one())
        for name in (
            "v_owner_monthly_report","v_owner_quarterly_report",
            "v_owner_yearly_report","v_service_order_summary"
        )
    }
    results["view_column_types"] = [
        {"view":row["table_name"],"column":row["column_name"],
         "type":row["data_type"]}
        for row in db.execute(text("""
            SELECT table_name,column_name,data_type
            FROM information_schema.columns
            WHERE table_schema='service'
              AND table_name IN (
                'v_owner_monthly_report',
                'v_owner_quarterly_report',
                'v_owner_yearly_report','v_service_order_summary'
              )
            ORDER BY table_name,ordinal_position
        """)).mappings()
    ]
    if results["service.service_orders"] and results["service.owner_finances"]:
        results["counts_and_totals_no_personal_data"] = dict(db.execute(text("""
            SELECT COUNT(*) AS all_orders,
                   COUNT(*) FILTER (WHERE so.status='COMPLETED') AS issued,
                   COUNT(*) FILTER (WHERE so.status='IN_SERVICE') AS in_service,
                   COUNT(*) FILTER (WHERE so.status='READY_FOR_PICKUP') AS ready,
                   COUNT(*) FILTER (WHERE so.status='COMPLETED'
                                    AND so.completed_at IS NULL) AS issued_missing_date,
                   COUNT(*) FILTER (WHERE so.is_warranty_repair) AS existing_warranty_flags,
                   COUNT(*) FILTER (WHERE so.is_warranty_repair
                                    AND so.status='COMPLETED') AS issued_warranty_flags,
                   COUNT(*) FILTER (WHERE so.status='COMPLETED'
                                    AND f.service_order_id IS NULL) AS issued_without_finances,
                   COALESCE(SUM(f.service_amount) FILTER (
                       WHERE so.status='COMPLETED'),0) AS settled_revenue,
                   COALESCE(SUM(f.material_cost) FILTER (
                       WHERE so.status='COMPLETED'),0) AS settled_material_cost
            FROM service.service_orders so
            LEFT JOIN service.owner_finances f
              ON f.service_order_id=so.id
        """)).mappings().one())
        for key,value in results["counts_and_totals_no_personal_data"].items():
            if value is not None and not isinstance(value,(str,int,float,bool)):
                results["counts_and_totals_no_personal_data"][key]=str(value)
    results["server_version_major"] = int(db.execute(
        text("SHOW server_version_num")
    ).scalar_one()) // 10000

print(json.dumps(results, ensure_ascii=False, indent=2))
