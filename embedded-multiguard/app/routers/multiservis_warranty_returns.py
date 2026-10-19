"""Multi-Servis: repeat warranty intake WITHOUT generating a new reception number.

Activation gate:
  1. Back up and inspect real production DB; apply/test reviewed DB migration.
  2. Confirm finance reports use the immutable completed-visit ledger.
  3. Wire this router into app.main after existing authentication middleware.
  4. Test with synthetic data before publishing Android.
Never load this router in production with an absent/incompatible DB migration.
"""
from __future__ import annotations

import uuid
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.database import engine
from app.security import CurrentUser, require_owner, require_staff

router = APIRouter(tags=["multiservis-warranty-returns"])


def _schema_ready(conn) -> None:
    tables = conn.execute(
        text(
            """
            SELECT
              to_regclass('service.service_orders') IS NOT NULL AS orders_ok,
              to_regclass('service.service_order_visits') IS NOT NULL AS visits_ok,
              to_regclass('service.v_owner_completed_visit_profit') IS NOT NULL AS report_ok,
              to_regprocedure('service.reopen_warranty_return(uuid,uuid)') IS NOT NULL AS fn_ok
            """
        )
    ).mappings().one()
    if not all(tables.values()):
        raise HTTPException(
            status_code=503,
            detail="Migracja napraw gwarancyjnych nie została jeszcze wdrożona.",
        )


def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="Nieprawidłowe ID zlecenia.") from exc


@router.post("/receptions/{reception_id}/warranty-return")
def reopen_warranty_return(
    reception_id: str,
    user: CurrentUser = Depends(require_staff),
):
    """Atomic, idempotency-safe via DB status check: only issued orders reopen.

    Old completed periods, amounts, and release dates remain immutable.
    One original UUID, reception number and printed QR for every return.
    """
    order_id = _uuid(reception_id)
    try:
        with engine.begin() as conn:
            _schema_ready(conn)
            row = conn.execute(
                text(
                    """
                    SELECT id, reception_number, status
                    FROM service.service_orders WHERE id=:id FOR UPDATE
                    """
                ),
                {"id": order_id},
            ).mappings().first()
            if row is None:
                raise HTTPException(404, "Zlecenie nie istnieje.")
            if row["status"] != "COMPLETED":
                raise HTTPException(
                    409, "Naprawę gwarancyjną można otworzyć tylko dla wydanego zlecenia."
                )

            # Authorization is enforced by require_staff, never by URL or
            # an order number. The database function performs the transactional
            # snapshot + zeroing; a plain PATCH status would lose past revenue.
            conn.execute(
                text("SELECT service.reopen_warranty_return(:id, NULL::uuid)"),
                {"id": order_id},
            )
            result = conn.execute(
                text(
                    """
                    SELECT id, reception_number, status, received_at,
                           current_visit_received_at, is_warranty_repair
                    FROM service.service_orders WHERE id=:id
                    """
                ),
                {"id": order_id},
            ).mappings().one()
            return {
                "id": str(result["id"]),
                "reception_number": result["reception_number"],
                "status": str(result["status"]),
                "received_at": result["received_at"].isoformat(),
                "current_visit_received_at": (
                    result["current_visit_received_at"].isoformat()
                    if result["current_visit_received_at"] else None
                ),
                "is_warranty_repair": bool(result["is_warranty_repair"]),
            }
    except HTTPException:
        raise
    except DBAPIError as exc:
        # No leaked SQL/PII in end-user responses. All writes are rolled back.
        raise HTTPException(
            status_code=503,
            detail="Nie udało się bezpiecznie przyjąć naprawy gwarancyjnej.",
        ) from exc


@router.get("/mobile/warranty/active-receptions")
def active_warranty_receptions(
    user: CurrentUser = Depends(require_staff),
):
    """Small overlay for unchanged legacy GET /receptions list payload."""
    with engine.connect() as conn:
        _schema_ready(conn)
        rows = conn.execute(
            text(
                """
                SELECT id, current_visit_received_at
                FROM service.service_orders
                WHERE is_warranty_repair IS TRUE
                  AND status IN ('IN_SERVICE','READY_FOR_PICKUP')
                ORDER BY current_visit_received_at DESC NULLS LAST
                LIMIT 5000
                """
            )
        ).mappings()
        return [
            {
                "id": str(r["id"]),
                "is_warranty_repair": True,
                "current_visit_received_at": (
                    r["current_visit_received_at"].isoformat()
                    if r["current_visit_received_at"] else None
                ),
            }
            for r in rows
        ]


@router.get("/mobile/finances/visit-report")
def completed_visit_finances(
    group_by: str = Query(default="month", alias="groupBy"),
    date_from: date | None = Query(default=None, alias="dateFrom"),
    date_to: date | None = Query(default=None, alias="dateTo"),
    user: CurrentUser = Depends(require_owner),
):
    """Report every paid/released visit once, grouped by its release date.

    Never aggregate service.owner_finances by service_order_id for completed
    historical periods: that table tracks the editable CURRENT visit only.
    """
    if group_by not in {"month", "quarter", "year"}:
        raise HTTPException(400, "Nieprawidłowe grupowanie raportu.")
    if date_from and date_to and date_from > date_to:
        raise HTTPException(400, "Data OD jest późniejsza niż data DO.")

    # SQL interval granularity cannot be bound as an identifier. Whitelist
    # first, then bind the validated literal as a date_trunc argument.
    with engine.connect() as conn:
        _schema_ready(conn)
        rows = conn.execute(
            text(
                """
                SELECT
                  date_trunc(:grp, completed_at AT TIME ZONE 'Europe/Warsaw')::date
                    AS period,
                  COUNT(*)::integer AS orders,
                  COALESCE(SUM(service_amount),0) AS service_amount,
                  COALESCE(SUM(material_cost),0) AS material_cost,
                  COALESCE(SUM(donor_material_value),0) AS donor_material_value,
                  COALESCE(SUM(actual_profit),0) AS actual_profit,
                  COALESCE(SUM(economic_profit),0) AS economic_profit
                FROM service.v_owner_completed_visit_profit
                WHERE (CAST(:since AS date) IS NULL OR
                    (completed_at AT TIME ZONE 'Europe/Warsaw')::date >= CAST(:since AS date))
                  AND (CAST(:until AS date) IS NULL OR
                    (completed_at AT TIME ZONE 'Europe/Warsaw')::date <= CAST(:until AS date))
                GROUP BY 1 ORDER BY 1 DESC
                """
            ),
            {"grp": group_by, "since": date_from, "until": date_to},
        ).mappings().all()
        return [
            {
                "period": r["period"].isoformat(),
                "orders": r["orders"],
                "service_amount": float(r["service_amount"]),
                "material_cost": float(r["material_cost"]),
                "donor_material_value": float(r["donor_material_value"]),
                "actual_profit": float(r["actual_profit"]),
                "economic_profit": float(r["economic_profit"]),
            }
            for r in rows
        ]
