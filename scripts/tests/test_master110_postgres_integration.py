"""Integration tests against an EPHEMERAL GitHub Actions PostgreSQL instance.

Exercises the *actual SQL extracted from the current backend schema*.
No calls to production DB, KeyGate, or MeshCentral.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import threading
import unittest
import uuid

import psycopg
from psycopg import errors

SRC=Path("embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")
SQL=SRC.split('_SCHEMA_SQL = """',1)[1].split('"""',1)[0]
DB=os.environ.get("MASTER110_TEST_POSTGRES")
if not DB or "localhost" not in DB and "127.0.0.1" not in DB:
    raise RuntimeError("Test requires explicitly local, temporary PostgreSQL only")
TABLE=re.search(r"CREATE TABLE IF NOT EXISTS guard.keygate_provision_attempts \((.*?)\);",SQL,re.S)
INDEX=re.search(r"CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_keygate_provision_unresolved(.*?);",SQL,re.S)
REVIEW=re.search(r"CREATE TABLE IF NOT EXISTS guard.keygate_provision_reviews \((.*?)\);",SQL,re.S)
assert TABLE and INDEX and REVIEW, "current backend SQL journal must be present"

def connect():
    return psycopg.connect(DB,connect_timeout=5)

class PostgresJournal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with connect() as c:
            c.execute("CREATE SCHEMA IF NOT EXISTS guard")
            c.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            c.execute("CREATE TABLE IF NOT EXISTS guard.keygate_provision_attempts ("+TABLE.group(1)+")")
            c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_keygate_provision_unresolved"+INDEX.group(1))
            c.execute("CREATE TABLE IF NOT EXISTS guard.keygate_provision_reviews ("+REVIEW.group(1)+")")
    def setUp(self):
        with connect() as c:
            c.execute("TRUNCATE guard.keygate_provision_reviews,guard.keygate_provision_attempts")
        self.license="LIC-TEST-"+uuid.uuid4().hex[:12]
    def insert(self,license_id,device="device-A"):
        with connect() as c:
            return c.execute(
                """INSERT INTO guard.keygate_provision_attempts
                (id,keygate_license_id,installation_id,device_id,state)
                VALUES (%s,%s,%s,%s,'INTENT') RETURNING id""",
                (uuid.uuid4(),license_id,uuid.uuid4(),device)
            ).fetchone()[0]
    def test_unresolved_intent_uniqueness(self):
        self.insert(self.license)
        with self.assertRaises(errors.UniqueViolation):
            self.insert(self.license,"device-B")
    def test_manual_review_does_not_remove_block(self):
        attempt=self.insert(self.license)
        with connect() as c:
            c.execute("""INSERT INTO guard.keygate_provision_reviews
                (attempt_id,finding,note,observed_attempt_state)
                VALUES (%s,'UNKNOWN','OWNER checked remote licensing system','INTENT')""",(attempt,))
        with self.assertRaises(errors.UniqueViolation):
            self.insert(self.license,"device-B")
    def test_commit_releases_journal_unique_constraint(self):
        attempt=self.insert(self.license)
        with connect() as c:
            c.execute("UPDATE guard.keygate_provision_attempts SET state='COMMITTED' WHERE id=%s",(attempt,))
        self.insert(self.license,"device-B")
    def test_review_state_preserves_block(self):
        attempt=self.insert(self.license)
        with connect() as c:
            c.execute("UPDATE guard.keygate_provision_attempts SET state='NEEDS_REVIEW' WHERE id=%s",(attempt,))
        with self.assertRaises(errors.UniqueViolation):
            self.insert(self.license,"device-B")
    def test_rollback_cannot_lose_previous_review(self):
        attempt=self.insert(self.license)
        with self.assertRaises(RuntimeError):
            with connect() as c:
                c.execute("""INSERT INTO guard.keygate_provision_reviews
                    (attempt_id,finding,note,observed_attempt_state)
                    VALUES (%s,'ESCALATED','OWNER reconciliation must continue','INTENT')""",(attempt,))
                raise RuntimeError("rolled back")
        with connect() as c:
            rows=c.execute("SELECT count(*) FROM guard.keygate_provision_reviews").fetchone()[0]
            state=c.execute("SELECT state FROM guard.keygate_provision_attempts WHERE id=%s",(attempt,)).fetchone()[0]
        self.assertEqual(rows,0)
        self.assertEqual(state,"INTENT")
    def test_concurrent_atomic_intents_return_one_conflict_without_sql_exception(self):
        # Exercise the ON CONFLICT clause used by production before calling
        # KeyGate. Both competitors start at the same instant.
        barrier=threading.Barrier(2)
        def contender(device):
            barrier.wait(timeout=5)
            with connect() as c:
                row=c.execute("""
                    INSERT INTO guard.keygate_provision_attempts
                        (id,keygate_license_id,installation_id,device_id,state)
                    VALUES (%s,%s,%s,%s,'INTENT')
                    ON CONFLICT (keygate_license_id)
                        WHERE state IN ('INTENT','NEEDS_REVIEW')
                    DO NOTHING RETURNING id
                """,(uuid.uuid4(),self.license,uuid.uuid4(),device)).fetchone()
                return "INSERTED" if row else "RECOVERY_RECONCILIATION_REQUIRED"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(contender,["device-A","device-B"]))
        self.assertCountEqual(results,["INSERTED","RECOVERY_RECONCILIATION_REQUIRED"])
        with connect() as c:
            count=c.execute(
                "SELECT count(*) FROM guard.keygate_provision_attempts WHERE keygate_license_id=%s",
                (self.license,)
            ).fetchone()[0]
        self.assertEqual(count,1)

    def test_concurrent_competitors_only_one_intent(self):
        barrier=threading.Barrier(2)
        def contender(device):
            barrier.wait(timeout=5)
            try:
                self.insert(self.license,device)
                return "INSERTED"
            except errors.UniqueViolation:
                return "CONFLICT"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(contender,["device-A","device-B"]))
        self.assertCountEqual(results,["INSERTED","CONFLICT"])

if __name__=="__main__":unittest.main()
