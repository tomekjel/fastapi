#!/usr/bin/env python3
"""Read-only dependency inventory for a MultiGuard test installation.

Run inside FastAPI LXC, from /opt/multiservis with its virtualenv.
Never prints credential/key data and never modifies records.
Usage: python inspect_test_installation.py <installation-uuid> [<installation-uuid> ...]
"""
import argparse
import uuid

from sqlalchemy import text
from app.database import engine

TABLES = (
    ("guard.pending_installations", "installation_id"),
    ("guard.workshop_grants", "installation_id"),
    ("guard.license_links", "installation_id"),
    ("guard.direct_keygate_attempts", "installation_id"),
    ("guard.direct_keygate_attempts_archive", "installation_id"),
    ("guard.owner_installation_labels", "installation_external_id"),
    ("guard.installations", "installation_external_id"),
)

def inspect(installation_id):
    print(f"INSTALLATION {installation_id}")
    with engine.connect() as con:
        con.execute(text("SET TRANSACTION READ ONLY"))
        for table, column in TABLES:
            schema, name = table.split(".")
            exists = con.execute(text("""
                SELECT EXISTS(
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema=:schema AND table_name=:name
                    AND column_name=:column
                )
            """), {"schema": schema, "name": name, "column": column}).scalar()
            if not exists:
                print(f"  {table}: NOT PRESENT")
                continue
            count = con.execute(text(f"SELECT count(*) FROM {table} WHERE {column}=:iid"),
                                {"iid": installation_id}).scalar()
            print(f"  {table}: {count} record(s)")
        # Discover all foreign key dependencies of guard.installations and
        # guard.pending_installations before planning deletions.
        dependencies = con.execute(text("""
          SELECT c.conrelid::regclass::text AS child,
                 c.confrelid::regclass::text AS parent,
                 pg_get_constraintdef(c.oid) AS constraint_def
          FROM pg_constraint c
          WHERE c.contype='f'
            AND c.confrelid IN
                ('guard.installations'::regclass,
                 'guard.pending_installations'::regclass)
          ORDER BY 1,2
        """)).all()
        print("  FOREIGN KEY DEPENDENCIES:")
        for child, parent, definition in dependencies:
            print(f"    {child} -> {parent}: {definition}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("installation_ids", nargs="+", type=uuid.UUID)
    args = parser.parse_args()
    for iid in args.installation_ids:
        inspect(iid)
