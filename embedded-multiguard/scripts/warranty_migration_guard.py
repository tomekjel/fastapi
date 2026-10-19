#!/usr/bin/env python3
"""Guarded migration verifier for the observed Multi-Servis PostgreSQL 18 schema.

DEFAULT: execute the entire SQL migration in an isolated DB transaction, test
an issued-order warranty cycle under a savepoint, then ALWAYS ROLLBACK.
APPLY:  make and verify a full pg_dump archive BEFORE running the same tests;
        COMMIT only if all integrity checks pass.
Both modes avoid logging customer/order identifiers or DB credentials.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

from sqlalchemy import text
from app.database import engine

# Immutable commit SHA of the reviewed migration; update only after review.
MIGRATION_SHA = "06efbbe7e30b69e710a1186715b4e8da39b25a5a"
MIGRATION_URL = (
    "https://raw.githubusercontent.com/tomekjel/db-postgresql/"
    + MIGRATION_SHA + "/migrations/2026-10-19-warranty-returns.sql"
)


def fetch_migration() -> str:
    request = Request(MIGRATION_URL, headers={"User-Agent": "Multi-Servis-warranty-review"})
    with urlopen(request, timeout=25) as response:
        source = response.read(125_000).decode("utf-8")
    if len(source) < 5_000 or len(source) > 100_000:
        raise RuntimeError("Unexpected migration size; fail closed.")
    required = (
        "CREATE TABLE IF NOT EXISTS service.service_order_visits",
        "CREATE OR REPLACE FUNCTION service.reopen_warranty_return",
        "CREATE OR REPLACE VIEW service.v_owner_completed_visit_profit",
        "COMPLETED_ORDER_REQUIRES_WARRANTY_RETURN",
    )
    for entry in required:
        if entry not in source:
            raise RuntimeError("Migration contract changed; fail closed.")
    if not re.search(r"(?m)^BEGIN;\s*$", source) or not re.search(
        r"(?m)^COMMIT;\s*$", source
    ):
        raise RuntimeError("Migration transaction boundaries missing.")
    # The runner owns BEGIN/COMMIT; never execute the migration's COMMIT.
    source = re.sub(r"(?m)^BEGIN;\s*$", "", source, count=1)
    source = re.sub(r"(?m)^COMMIT;\s*$", "", source, count=1)
    if source.count("$$") % 2:
        raise RuntimeError("Unbalanced SQL function delimiters.")
    return source


def totals(cur):
    cur.execute("""
        SELECT COUNT(*)::integer,
               COUNT(*) FILTER (WHERE s.status='COMPLETED')::integer,
               COUNT(*) FILTER (WHERE s.status='COMPLETED'
                                   AND s.completed_at IS NULL)::integer,
               COUNT(*) FILTER (WHERE s.is_warranty_repair)::integer,
               COALESCE(SUM(f.service_amount) FILTER
                   (WHERE s.status='COMPLETED'),0),
               COALESCE(SUM(f.material_cost) FILTER
                   (WHERE s.status='COMPLETED'),0)
        FROM service.service_orders s
        LEFT JOIN service.owner_finances f ON f.service_order_id=s.id
    """)
    return cur.fetchone()


def completed_visit_totals(cur):
    cur.execute("""
        SELECT COUNT(*)::integer,
               COALESCE(SUM(service_amount),0),
               COALESCE(SUM(material_cost),0)
        FROM service.v_owner_completed_visit_profit
    """)
    return cur.fetchone()


def check_base_schema(cur):
    cur.execute("""
        SELECT current_setting('server_version_num')::integer,
               to_regclass('service.service_orders') IS NOT NULL,
               to_regclass('service.owner_finances') IS NOT NULL,
               to_regclass('service.service_order_visits') IS NULL,
               to_regclass('service.v_owner_completed_visit_profit') IS NULL
    """)
    version, orders, finances, no_visits, no_view = cur.fetchone()
    if version // 10000 != 18 or not all((orders, finances, no_visits, no_view)):
        raise RuntimeError("Unrecognized or already-migrated PostgreSQL schema.")
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema='service' AND table_name='service_orders'
    """)
    columns = {row[0] for row in cur.fetchall()}
    if not {"id","reception_number","received_at","completed_at",
            "is_warranty_repair"}.issubset(columns):
        raise RuntimeError("Missing known production service_order columns.")
    cur.execute("""
        SELECT enumlabel FROM pg_enum
        WHERE enumtypid='service.reception_status'::regtype
        ORDER BY enumsortorder
    """)
    if [x[0] for x in cur.fetchall()] != [
        "IN_SERVICE","READY_FOR_PICKUP","COMPLETED","CANCELLED"
    ]:
        raise RuntimeError("Unexpected status enum; refuse to migrate.")


def verify_migrated(cur, baseline):
    previous_count, previous_issued, missing_issued, warranty_count, revenue, cost = baseline
    if missing_issued or warranty_count:
        raise RuntimeError("Prior warranty/missing release date needs individual review.")
    cur.execute("SELECT COUNT(*)::integer FROM service.service_order_visits")
    if cur.fetchone()[0] != previous_count:
        raise RuntimeError("Historical order count was not preserved.")
    cur.execute("""
        SELECT COUNT(*)::integer FROM service.service_order_visits
        WHERE visit_number<>1 OR NOT is_current OR is_warranty_return
    """)
    if cur.fetchone()[0] != 0:
        raise RuntimeError("Unexpected historical visit states.")
    visits, visit_revenue, visit_cost = completed_visit_totals(cur)
    if (visits, Decimal(visit_revenue), Decimal(visit_cost)) != (
        previous_issued, Decimal(revenue), Decimal(cost)
    ):
        raise RuntimeError("Historic completed-period revenue/cost mismatch.")
    cur.execute("""
        SELECT COUNT(*)::integer FROM service.service_orders
        WHERE current_visit_received_at IS NOT NULL
    """)
    if cur.fetchone()[0] != 0:
        raise RuntimeError("Old received/updated timestamps were modified.")
    print(
        "PASS: baseline rows={}, issued={}, historic revenue={}, material cost={}".format(
            previous_count, previous_issued, revenue, cost
        ),
        flush=True,
    )


def simulate_one_warranty(cur, baseline):
    """SAVEPOINT only. Never keep data changes made on a real order."""
    if baseline[1] < 1:
        raise RuntimeError("No issued order available for rollback test.")
    cur.execute("SAVEPOINT warranty_sim")
    try:
        cur.execute("""
            SELECT s.id,s.reception_number,s.received_at,s.completed_at,
                   f.service_amount,f.material_cost
            FROM service.service_orders s
            JOIN service.owner_finances f ON f.service_order_id=s.id
            WHERE s.status='COMPLETED'
            ORDER BY s.completed_at ASC LIMIT 1 FOR UPDATE OF s,f
        """)
        selected = cur.fetchone()
        if selected is None:
            raise RuntimeError("Missing settled finance row for released order.")
        order_id, number, received_at, completed_at, amount, cost = selected
        # Old shortcut must be denied; only the function may reopen an issue.
        cur.execute("SAVEPOINT reject_shortcut")
        try:
            cur.execute("""
                UPDATE service.service_orders SET status='IN_SERVICE'
                WHERE id=%s
            """, (order_id,))
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT reject_shortcut")
        else:
            raise RuntimeError("Unsafe generic reopen unexpectedly allowed.")
        cur.execute(
            "SELECT service.reopen_warranty_return(%s,NULL::uuid)", (order_id,)
        )
        cur.execute("""
            SELECT reception_number,received_at,status,is_warranty_repair,
                   completed_at,ready_at,current_visit_received_at
            FROM service.service_orders WHERE id=%s
        """, (order_id,))
        new = cur.fetchone()
        if (new[0] != number or new[1] != received_at or
            str(new[2]) != "IN_SERVICE" or not new[3] or
            new[4] is not None or new[5] is not None or new[6] is None):
            raise RuntimeError("Warranty reopen changed the original QR/number.")
        cur.execute("""
            SELECT visit_number,is_current,is_warranty_return,completed_at,
                   service_amount,material_cost
            FROM service.service_order_visits
            WHERE service_order_id=%s ORDER BY visit_number
        """, (order_id,))
        rows = cur.fetchall()
        if len(rows) != 2 or rows[0][1] or not rows[1][1] or not rows[1][2]:
            raise RuntimeError("Visit history was not separated correctly.")
        if (rows[0][3] != completed_at or
            Decimal(rows[0][4]) != Decimal(amount) or
            Decimal(rows[0][5]) != Decimal(cost) or
            Decimal(rows[1][4]) != 0):
            raise RuntimeError("Historical issue finances were overwritten.")
        if completed_visit_totals(cur)[0] != baseline[1]:
            raise RuntimeError("Old revenue vanished during return.")
        # Simulate a subsequent PAID repair and second release.
        cur.execute("""
            UPDATE service.owner_finances SET service_amount=350
            WHERE service_order_id=%s
        """, (order_id,))
        cur.execute("""
            UPDATE service.service_orders SET status='READY_FOR_PICKUP'
            WHERE id=%s
        """, (order_id,))
        cur.execute("""
            UPDATE service.service_orders SET status='COMPLETED'
            WHERE id=%s
        """, (order_id,))
        visits, revenue, material = completed_visit_totals(cur)
        if (visits != baseline[1] + 1 or
            Decimal(revenue) != Decimal(baseline[4]) + Decimal(350) or
            Decimal(material) != Decimal(baseline[5])):
            raise RuntimeError("Reissued paid warranty double-counted finances.")
        print("PASS: reversible warranty scenario (same QR; original + 350 PLN release)",flush=True)
    finally:
        cur.execute("ROLLBACK TO SAVEPOINT warranty_sim")
        cur.execute("RELEASE SAVEPOINT warranty_sim")


def full_backup():
    pg_dump = shutil.which("pg_dump")
    pg_restore = shutil.which("pg_restore")
    if not pg_dump or not pg_restore:
        raise RuntimeError("No pg_dump/pg_restore; database NOT modified.")
    url = engine.url
    if not url.database or not url.username:
        raise RuntimeError("Unknown PostgreSQL DSN for pg_dump.")
    env = os.environ.copy()
    if url.host: env["PGHOST"] = url.host
    if url.port: env["PGPORT"] = str(url.port)
    if url.username: env["PGUSER"] = url.username
    if url.password: env["PGPASSWORD"] = url.password
    for key in ("sslmode","sslrootcert","sslcert","sslkey"):
        if key in url.query:
            env["PG"+key.upper()] = str(url.query[key])
    # pg_dump must be at least as new as PostgreSQL server (PG18).
    version = subprocess.run(
        [pg_dump,"--version"],capture_output=True,text=True,timeout=10,check=True
    ).stdout
    major = re.search(r"(\d+)\.\d+",version)
    if not major or int(major.group(1)) < 18:
        raise RuntimeError("pg_dump older than PostgreSQL 18; NOT modifying DB.")
    parent = Path("/opt/multiservis/backups")
    parent.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(parent).free < 250 * 1024 * 1024:
        raise RuntimeError("Insufficient free backup space (<250 MiB).")
    directory = Path(tempfile.mkdtemp(prefix="warranty-pg18-",dir=parent))
    directory.chmod(0o700)
    archive = directory / "multiservis-full-before-warranty.dump"
    try:
        subprocess.run(
            [pg_dump, "-Fc", "--no-owner", "--no-acl", "-f",str(archive),
             "-d",url.database],env=env,check=True,timeout=300,
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
        )
        if archive.stat().st_size < 2_048:
            raise RuntimeError("DB backup archive unusually small.")
        subprocess.run(
            [pg_restore,"--list",str(archive)],check=True,timeout=30,
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
        )
        archive.chmod(0o600)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (directory/"SHA256.txt").write_text(digest+"  "+archive.name+"\n")
        (directory/"SHA256.txt").chmod(0o600)
    except Exception:
        archive.unlink(missing_ok=True)
        raise
    print("PASS: verified full database dump:", archive, flush=True)
    print("Backup SHA256:",digest,flush=True)
    return archive


def run(mode: str):
    sql = fetch_migration()
    digest = hashlib.sha256(sql.encode()).hexdigest()
    print("Immutable SQL SHA256:", digest, flush=True)
    if mode == "apply":
        full_backup()
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        # Original DDL changes + every test run under ONE transaction.
        cur.execute("BEGIN")
        cur.execute("SET LOCAL lock_timeout='5000ms'")
        cur.execute("SET LOCAL statement_timeout='90000ms'")
        check_base_schema(cur)
        baseline = totals(cur)
        if baseline[0] < 1 or baseline[1] < 1:
            raise RuntimeError("No verified real service data in target DB.")
        cur.execute(sql)
        verify_migrated(cur,baseline)
        simulate_one_warranty(cur,baseline)
        verify_migrated(cur,baseline)
        # No user data was ever permanently changed by synthetic test.
        if mode == "apply":
            raw.commit()
            print("APPLIED: warranty migration COMMITTED after backup and checks.")
        else:
            raw.rollback()
            with engine.connect() as conn:
                gone = conn.execute(text(
                    "SELECT to_regclass('service.service_order_visits') IS NULL"
                )).scalar_one()
            if not gone:
                raise RuntimeError("ROLLBACK did not remove temporary schema!")
            print("DRY-RUN PASS: rolled back ALL schema and test changes.")
    except Exception:
        raw.rollback()
        print("BLOCKED: all uncommitted changes rolled back.",file=sys.stderr)
        raise
    finally:
        raw.close()


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--apply",action="store_true",help="full pg_dump, tests, then commit")
    args=parser.parse_args()
    run("apply" if args.apply else "dry-run")
